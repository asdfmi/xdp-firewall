#pragma once

#include <signal.h>
#include <stdint.h>
#include <pthread.h>

struct telemetry_store;

struct http_server_config {
	const char *host;
	uint16_t port;
	const char *static_dir;
	struct telemetry_store *store;
	volatile sig_atomic_t *stop_flag;
};

int http_server_start(const struct http_server_config *config,
		      pthread_t *thread_out);
