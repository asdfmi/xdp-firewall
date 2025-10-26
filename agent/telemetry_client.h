#pragma once

#include <stdint.h>

#include "telemetry/telemetry.h"

struct telemetry_client;

int telemetry_client_create(struct telemetry_client **clientp,
			    const char *host, uint16_t port);
void telemetry_client_destroy(struct telemetry_client *client);
int telemetry_client_send(struct telemetry_client *client,
			  const struct telemetry_packet *packet);
