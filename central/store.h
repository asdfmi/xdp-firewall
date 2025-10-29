#pragma once

#include <stddef.h>
#include <stdint.h>

#include "telemetry/telemetry.h"

#define TELEMETRY_STORE_MAX_EVENTS 256
#define TELEMETRY_STORE_MAX_LABELS 128
#define TELEMETRY_STORE_MAX_NODES 32

struct telemetry_event {
	struct telemetry_packet packet;
};

struct telemetry_label_count {
	uint32_t label_id;
	uint64_t count;
};

struct telemetry_node_snapshot {
	char agent_id[TELEMETRY_MAX_AGENT_ID];
	uint64_t total_events;

	struct telemetry_label_count labels[TELEMETRY_STORE_MAX_LABELS];
	size_t label_count;

	struct telemetry_event events[TELEMETRY_STORE_MAX_EVENTS];
	size_t event_count;
};

struct telemetry_snapshot {
	uint64_t total_events;
	struct telemetry_node_snapshot nodes[TELEMETRY_STORE_MAX_NODES];
	size_t node_count;
};

struct telemetry_store;

int telemetry_store_init(struct telemetry_store **storep);
void telemetry_store_destroy(struct telemetry_store *store);
void telemetry_store_record(struct telemetry_store *store,
			    const struct telemetry_packet *packet);
void telemetry_store_snapshot(struct telemetry_store *store,
			      struct telemetry_snapshot *snapshot);
