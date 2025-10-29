#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>

#include "telemetry/telemetry.h"
#include "http_server.h"
#include "store.h"

#define BACKLOG 16
#define RECV_BUFFER 2048

static volatile sig_atomic_t stop_flag;

static void handle_signal(int signo)
{
	(void)signo;
	stop_flag = 1;
}

static int read_exact(int fd, unsigned char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = recv(fd, buf, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static void handle_client(int fd, struct telemetry_store *store)
{
    unsigned char len_buf[4];
    unsigned char payload[RECV_BUFFER];
    struct telemetry_packet pkt;
    size_t frame_len;
    fprintf(stdout, "central: client connected fd=%d\n", fd);
    fflush(stdout);

	while (!stop_flag) {
		if (read_exact(fd, len_buf, sizeof(len_buf))) {
			break;
		}

		frame_len = (size_t)len_buf[0] |
			    ((size_t)len_buf[1] << 8) |
			    ((size_t)len_buf[2] << 16) |
			    ((size_t)len_buf[3] << 24);

        if (frame_len == 0 || frame_len > sizeof(payload)) {
            fprintf(stderr,
                    "central: invalid frame length %zu\n",
                    frame_len);
            fflush(stderr);
            break;
        }

		if (read_exact(fd, payload, frame_len)) {
			break;
		}

		telemetry_packet_init(&pkt);
        if (telemetry_packet_decode(&pkt, payload, frame_len)) {
            fprintf(stderr,
                    "central: failed to decode telemetry frame (len=%zu)\n",
                    frame_len);
            fflush(stderr);
            break;
        }

        telemetry_store_record(store, &pkt);
        fprintf(stdout, "central: stored event (agent_id='%s')\n", pkt.agent_id);
        fflush(stdout);
    }
}

struct client_thread_args {
    int fd;
    struct telemetry_store *store;
};

static void *client_thread_main(void *arg)
{
    struct client_thread_args *args = (struct client_thread_args *)arg;
    int fd = -1;
    if (!args)
        return NULL;
    fd = args->fd;
    handle_client(fd, args->store);
    if (fd >= 0)
        close(fd);
    free(args);
    return NULL;
}

int main(int argc, char **argv)
{
	int telemetry_port = 50051;
	int http_port = 8080;
	int server_fd = -1;
	struct sockaddr_in addr = {0};
	int optval = 1;
	struct telemetry_store *store = NULL;
	pthread_t http_thread;
	bool http_started = false;
	int argi = 1;

	if (argc > 3) {
		fprintf(stderr, "Usage: %s [telemetry_port] [http_port]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (argc >= 2) {
		char *endptr = NULL;
		long parsed = strtol(argv[argi++], &endptr, 10);

		if (!argv[1][0] || !endptr || *endptr != '\0' ||
		    parsed <= 0 || parsed > 65535) {
			fprintf(stderr,
				"central: invalid telemetry port '%s'\n",
				argv[1]);
			return EXIT_FAILURE;
		}
		telemetry_port = (int)parsed;
	}

	if (argc == 3) {
		char *endptr = NULL;
		long parsed = strtol(argv[argi], &endptr, 10);

		if (!argv[argi][0] || !endptr || *endptr != '\0' ||
		    parsed <= 0 || parsed > 65535) {
			fprintf(stderr,
				"central: invalid http port '%s'\n",
				argv[argi]);
			return EXIT_FAILURE;
		}
		http_port = (int)parsed;
	}

	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		perror("signal");
		return EXIT_FAILURE;
	}

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    if (telemetry_store_init(&store) != 0) {
        fprintf(stderr, "central: failed to init telemetry store\n");
        return EXIT_FAILURE;
    }

	struct http_server_config http_cfg = {
		.host = NULL,
		.port = (uint16_t)http_port,
		.static_dir = "central/ui/static",
		.store = store,
		.stop_flag = &stop_flag,
	};

	if (http_server_start(&http_cfg, &http_thread) == 0)
		http_started = true;
	else
		fprintf(stderr,
			"central: warning: failed to start HTTP server\n");

	server_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (server_fd < 0) {
		perror("socket");
		goto out;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
		       &optval, sizeof(optval)) != 0) {
		perror("setsockopt");
		goto out;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)telemetry_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		goto out;
	}

	if (listen(server_fd, BACKLOG) != 0) {
		perror("listen");
		goto out;
	}

	printf("central: telemetry listening on 0.0.0.0:%d\n", telemetry_port);

	while (!stop_flag) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd;
		struct client_thread_args *args;
		pthread_t th;

		client_fd = accept4(server_fd, (struct sockaddr *)&client_addr,
				    &client_len, SOCK_CLOEXEC);
		if (client_fd < 0) {
			if (errno == EINTR && stop_flag)
				break;
			perror("accept");
			continue;
		}

		args = calloc(1, sizeof(*args));
		if (!args) {
			perror("calloc");
			close(client_fd);
			continue;
		}
		args->fd = client_fd;
		args->store = store;

		if (pthread_create(&th, NULL, client_thread_main, args) != 0) {
			perror("pthread_create");
			close(client_fd);
			free(args);
			continue;
		}
		/* Detach so resources are reclaimed when thread exits */
		pthread_detach(th);
	}

out:
	stop_flag = 1;
	if (server_fd >= 0)
		close(server_fd);
	if (http_started)
		pthread_join(http_thread, NULL);
	telemetry_store_destroy(store);
	printf("central: stopped\n");
	return 0;
}
