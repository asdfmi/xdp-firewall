#define _GNU_SOURCE

#include "http_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "store.h"

struct http_server_context {
	char host[64];
	uint16_t port;
	char static_dir[PATH_MAX];
	struct telemetry_store *store;
	volatile sig_atomic_t *stop_flag;
};

static const char *content_type_for_path(const char *path)
{
	const char *ext = strrchr(path, '.');

	if (!ext)
		return "text/plain";
	if (strcmp(ext, ".html") == 0)
		return "text/html; charset=utf-8";
	if (strcmp(ext, ".js") == 0)
		return "application/javascript; charset=utf-8";
	if (strcmp(ext, ".css") == 0)
		return "text/css; charset=utf-8";
	if (strcmp(ext, ".json") == 0)
		return "application/json; charset=utf-8";
	return "text/plain; charset=utf-8";
}

static ssize_t recv_line(int fd, char *buf, size_t buf_sz)
{
	size_t i = 0;

	while (i + 1 < buf_sz) {
		char c;
		ssize_t n = recv(fd, &c, 1, 0);

		if (n <= 0)
			return -1;
		if (c == '\r')
			continue;
		if (c == '\n') {
			buf[i] = '\0';
			return (ssize_t)i;
		}
		buf[i++] = c;
	}

	return -1;
}

static void send_response_header(int fd, const char *status,
				 const char *content_type)
{
	dprintf(fd,
		"HTTP/1.0 %s\r\n"
		"Content-Type: %s\r\n"
		"Cache-Control: no-store\r\n"
		"\r\n",
		status, content_type);
}

static void send_not_found(int fd)
{
	send_response_header(fd, "404 Not Found", "text/plain; charset=utf-8");
	dprintf(fd, "not found\n");
}

static void send_server_error(int fd)
{
	send_response_header(fd, "500 Internal Server Error",
			     "text/plain; charset=utf-8");
	dprintf(fd, "internal error\n");
}

static void send_metrics_json(int fd, struct telemetry_store *store)
{
	struct telemetry_snapshot snapshot;
	size_t i, j;

	telemetry_store_snapshot(store, &snapshot);

	send_response_header(fd, "200 OK", "application/json; charset=utf-8");

	dprintf(fd, "{ \"total_events\": %llu, \"nodes\": [",
		(unsigned long long)snapshot.total_events);

	for (i = 0; i < snapshot.node_count; i++) {
		const struct telemetry_node_snapshot *node = &snapshot.nodes[i];

		dprintf(fd, "%s{\"agent_id\": \"%s\", \"total_events\": %llu, \"label_counts\": [",
			i ? ", " : "",
			node->agent_id[0] ? node->agent_id : "unknown",
			(unsigned long long)node->total_events);

		for (j = 0; j < node->label_count; j++) {
			dprintf(fd,
				"%s{\"label_id\": %u, \"count\": %llu}",
				j ? ", " : "",
				node->labels[j].label_id,
				(unsigned long long)node->labels[j].count);
		}

		dprintf(fd, "], \"recent_events\": [");

		for (j = 0; j < node->event_count; j++) {
			const struct telemetry_packet *pkt =
				&node->events[j].packet;
			const char *src_ip = pkt->src_ip[0] ? pkt->src_ip : "-";
			const char *dst_ip = pkt->dst_ip[0] ? pkt->dst_ip : "-";

			dprintf(fd,
				"%s{"
				"\"timestamp_ns\": %llu,"
				"\"ifindex\": %u,"
				"\"queue_id\": %u,"
				"\"action\": %u,"
				"\"label_id\": %u,"
				"\"data_len\": %u,"
				"\"src_ip\": \"%s\","
				"\"dst_ip\": \"%s\","
				"\"src_port\": %u,"
				"\"dst_port\": %u"
				"}",
				j ? ", " : "",
				(unsigned long long)pkt->timestamp_ns,
				pkt->ifindex,
				pkt->queue_id,
				pkt->action,
				pkt->label_id,
				pkt->data_len,
				src_ip,
				dst_ip,
				pkt->src_port,
				pkt->dst_port);
		}

		dprintf(fd, "] }");
	}

	dprintf(fd, "] }\n");
}

static void send_static_file(int fd, const char *static_dir,
			     const char *path)
{
	char resolved_path[PATH_MAX];
	const char *content_type;
	int file_fd;
	ssize_t n;
	char buf[4096];

	if (strcmp(path, "/") == 0)
		path = "/index.html";

	if (snprintf(resolved_path, sizeof(resolved_path), "%s%s",
		     static_dir, path) >= (int)sizeof(resolved_path)) {
		send_server_error(fd);
		return;
	}

	file_fd = open(resolved_path, O_RDONLY);
	if (file_fd < 0) {
		send_not_found(fd);
		return;
	}

	content_type = content_type_for_path(path);
	send_response_header(fd, "200 OK", content_type);

	while ((n = read(file_fd, buf, sizeof(buf))) > 0)
		(void)send(fd, buf, (size_t)n, 0);

	close(file_fd);
}

static void handle_http_client(int fd, struct telemetry_store *store,
			       const char *static_dir)
{
	char line[1024];
	char method[16];
	char path[512];

	if (recv_line(fd, line, sizeof(line)) < 0)
		return;

	if (sscanf(line, "%15s %511s", method, path) != 2)
		return;

	/* Consume rest of headers */
	while (recv_line(fd, line, sizeof(line)) > 0) {
		if (line[0] == '\0')
			break;
	}

	if (strcmp(method, "GET") != 0) {
		send_response_header(fd, "405 Method Not Allowed",
				     "text/plain; charset=utf-8");
		dprintf(fd, "method not allowed\n");
		return;
	}

	if (strcmp(path, "/metrics.json") == 0) {
		send_metrics_json(fd, store);
		return;
	}

	send_static_file(fd, static_dir, path);
}

static void *http_server_thread(void *arg)
{
	struct http_server_context *ctx = arg;
	int srv_fd = -1;
	struct sockaddr_in addr = {0};
	int optval = 1;

	srv_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (srv_fd < 0)
		goto out;

	if (setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
		       sizeof(optval)) != 0)
		goto out;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(ctx->port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		goto out;

	if (listen(srv_fd, 16) != 0)
		goto out;

	printf("central: HTTP UI listening on 0.0.0.0:%u (static dir %s)\n",
	       ctx->port, ctx->static_dir);

	while (!*ctx->stop_flag) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd;

		client_fd = accept4(srv_fd, (struct sockaddr *)&client_addr,
				    &client_len, SOCK_CLOEXEC);
		if (client_fd < 0) {
			if (errno == EINTR && *ctx->stop_flag)
				break;
			continue;
		}

		handle_http_client(client_fd, ctx->store, ctx->static_dir);
		close(client_fd);
	}

out:
	if (srv_fd >= 0)
		close(srv_fd);
	free(ctx);
	return NULL;
}

int http_server_start(const struct http_server_config *config,
		      pthread_t *thread_out)
{
	struct http_server_context *ctx;
	pthread_t thread;
	int ret;

	if (!config || !config->store || !thread_out)
		return -1;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	if (config->host)
		strncpy(ctx->host, config->host, sizeof(ctx->host) - 1);
	ctx->port = config->port;
	if (config->static_dir)
		strncpy(ctx->static_dir, config->static_dir,
			sizeof(ctx->static_dir) - 1);
	ctx->store = config->store;
	ctx->stop_flag = config->stop_flag;

	ret = pthread_create(&thread, NULL, http_server_thread, ctx);
	if (ret != 0) {
		free(ctx);
		return -1;
	}

	*thread_out = thread;
	return 0;
}
#include <limits.h>
