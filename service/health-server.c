#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define BACKLOG 16

static volatile sig_atomic_t stop_server;

static void handle_signal(int signo)
{
	(void)signo;
	stop_server = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [port]\n", prog);
}

static int install_signal_handlers(void)
{
	struct sigaction sa = {
		.sa_handler = handle_signal,
	};

	if (sigemptyset(&sa.sa_mask) != 0)
		return -1;

	sa.sa_flags = 0; /* ensure accept() is interrupted */

	if (sigaction(SIGINT, &sa, NULL) != 0)
		return -1;
	if (sigaction(SIGTERM, &sa, NULL) != 0)
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	int port = DEFAULT_PORT;
	int server_fd = -1;
	int optval = 1;
	struct sockaddr_in addr = {0};

	if (argc > 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 2) {
		char *endptr = NULL;
		long parsed = strtol(argv[1], &endptr, 10);

		if (!argv[1][0] || !endptr || *endptr != '\0' ||
		    parsed <= 0 || parsed > 65535) {
			fprintf(stderr, "Invalid port: %s\n", argv[1]);
			return EXIT_FAILURE;
		}

		port = (int)parsed;
	}

	if (install_signal_handlers() != 0) {
		perror("sigaction");
		return EXIT_FAILURE;
	}

	server_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (server_fd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
		       &optval, sizeof(optval)) != 0) {
		perror("setsockopt");
		close(server_fd);
		return EXIT_FAILURE;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind");
		close(server_fd);
		return EXIT_FAILURE;
	}

	if (listen(server_fd, BACKLOG) != 0) {
		perror("listen");
		close(server_fd);
		return EXIT_FAILURE;
	}

	printf("health-server: listening on 0.0.0.0:%d\n", port);

	while (!stop_server) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd;
		char buf[1024];

		client_fd = accept4(server_fd, (struct sockaddr *)&client_addr,
				    &client_len, SOCK_CLOEXEC);
		if (client_fd < 0) {
			if (errno == EINTR) {
				if (stop_server)
					break;
				continue;
			}
			perror("accept");
			continue;
		}

		char addr_str[INET_ADDRSTRLEN] = "unknown";
		if (inet_ntop(AF_INET, &client_addr.sin_addr,
			      addr_str, sizeof(addr_str)) == NULL)
			strncpy(addr_str, "invalid", sizeof(addr_str) - 1);

		printf("health-server: accepted connection from %s:%u\n",
		       addr_str, ntohs(client_addr.sin_port));

		(void)recv(client_fd, buf, sizeof(buf), 0);

		const char response[] =
			"HTTP/1.1 200 OK\r\n"
			"Connection: close\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 2\r\n"
			"\r\n"
			"OK";

		(void)send(client_fd, response, sizeof(response) - 1, 0);
		close(client_fd);
	}

	close(server_fd);
	printf("health-server: stopped\n");
	return EXIT_SUCCESS;
}
