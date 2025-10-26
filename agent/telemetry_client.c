#define _GNU_SOURCE

#include "telemetry_client.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TELEMETRY_MAX_MESSAGE 1024

struct telemetry_client {
	int fd;
};

static int send_all(int fd, const unsigned char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = send(fd, buf, len, 0);

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

int telemetry_client_create(struct telemetry_client **clientp,
			    const char *host, uint16_t port)
{
	struct telemetry_client *client;
	char port_str[16];
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	int ret;

	if (!clientp || !host)
		return -1;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port_str, &hints, &res);
	if (ret != 0) {
		fprintf(stderr, "telemetry: getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	client = calloc(1, sizeof(*client));
	if (!client) {
		freeaddrinfo(res);
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		client->fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
				    ai->ai_protocol);
		if (client->fd < 0)
			continue;

		if (connect(client->fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;

		close(client->fd);
		client->fd = -1;
	}

	freeaddrinfo(res);

	if (client->fd < 0) {
		free(client);
		fprintf(stderr,
			"telemetry: failed to connect to %s:%u: %s\n",
			host, (unsigned int)port, strerror(errno));
		return -1;
	}

	*clientp = client;
	return 0;
}

void telemetry_client_destroy(struct telemetry_client *client)
{
	if (!client)
		return;

	if (client->fd >= 0)
		close(client->fd);
	free(client);
}

int telemetry_client_send(struct telemetry_client *client,
			  const struct telemetry_packet *packet)
{
	unsigned char buf[TELEMETRY_MAX_MESSAGE];
	size_t encoded_len;
	unsigned char header[4];

	if (!client || client->fd < 0 || !packet)
		return -1;

	if (telemetry_packet_encode(packet, buf, sizeof(buf), &encoded_len))
		return -1;

	if (encoded_len > 0xffffffffu)
		return -1;

	header[0] = (unsigned char)(encoded_len & 0xffu);
	header[1] = (unsigned char)((encoded_len >> 8) & 0xffu);
	header[2] = (unsigned char)((encoded_len >> 16) & 0xffu);
	header[3] = (unsigned char)((encoded_len >> 24) & 0xffu);

	if (send_all(client->fd, header, sizeof(header)))
		return -1;
	if (send_all(client->fd, buf, encoded_len))
		return -1;

	return 0;
}
