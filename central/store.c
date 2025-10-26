#define _GNU_SOURCE

#include "store.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct telemetry_node_stats {
	char agent_id[TELEMETRY_MAX_AGENT_ID];
	struct telemetry_event events[TELEMETRY_STORE_MAX_EVENTS];
	size_t event_head;
	size_t event_count;
	struct telemetry_label_count labels[TELEMETRY_STORE_MAX_LABELS];
	size_t label_count;
	uint64_t total_events;
};

struct telemetry_store {
	pthread_mutex_t lock;
	struct telemetry_node_stats nodes[TELEMETRY_STORE_MAX_NODES];
	size_t node_count;
	uint64_t total_events;
};

static struct telemetry_node_stats *find_or_create_node(
	struct telemetry_store *store, const char *agent_id)
{
	size_t i;

	for (i = 0; i < store->node_count; i++) {
		if (strncmp(store->nodes[i].agent_id, agent_id,
			    sizeof(store->nodes[i].agent_id)) == 0)
			return &store->nodes[i];
	}

	if (store->node_count >= TELEMETRY_STORE_MAX_NODES)
		return NULL;

    struct telemetry_node_stats *node = &store->nodes[store->node_count++];
    memset(node, 0, sizeof(*node));
    if (agent_id && agent_id[0]) {
        snprintf(node->agent_id, sizeof(node->agent_id), "%s", agent_id);
    }
	return node;
}

static void update_label_counts(struct telemetry_node_stats *node,
				       uint32_t label_id)
{
	size_t i;

	for (i = 0; i < node->label_count; i++) {
		if (node->labels[i].label_id == label_id) {
			node->labels[i].count++;
			return;
		}
	}

	if (node->label_count >= TELEMETRY_STORE_MAX_LABELS)
		return;

	node->labels[node->label_count].label_id = label_id;
	node->labels[node->label_count].count = 1;
	node->label_count++;
}

int telemetry_store_init(struct telemetry_store **storep)
{
	struct telemetry_store *store;

	if (!storep)
		return -1;

	store = calloc(1, sizeof(*store));
	if (!store)
		return -1;

	if (pthread_mutex_init(&store->lock, NULL) != 0) {
		free(store);
		return -1;
	}

	*storep = store;
	return 0;
}

void telemetry_store_destroy(struct telemetry_store *store)
{
	if (!store)
		return;

	pthread_mutex_destroy(&store->lock);
	free(store);
}

void telemetry_store_record(struct telemetry_store *store,
			    const struct telemetry_packet *packet)
{
	struct telemetry_node_stats *node;
	struct telemetry_event *event;

	if (!store || !packet)
		return;

	pthread_mutex_lock(&store->lock);

	node = find_or_create_node(store, packet->agent_id);
	if (!node) {
		pthread_mutex_unlock(&store->lock);
		return;
	}

	event = &node->events[node->event_head];
	event->packet = *packet;

	node->event_head = (node->event_head + 1) % TELEMETRY_STORE_MAX_EVENTS;
	if (node->event_count < TELEMETRY_STORE_MAX_EVENTS)
		node->event_count++;

	node->total_events++;
	store->total_events++;
	update_label_counts(node, packet->label_id);

	pthread_mutex_unlock(&store->lock);
}

void telemetry_store_snapshot(struct telemetry_store *store,
			       struct telemetry_snapshot *snapshot)
{
	size_t i, j;

	if (!store || !snapshot)
		return;

	pthread_mutex_lock(&store->lock);

	snapshot->total_events = store->total_events;
	snapshot->node_count = store->node_count;

	for (i = 0; i < store->node_count; i++) {
		const struct telemetry_node_stats *node = &store->nodes[i];
		struct telemetry_node_snapshot *out = &snapshot->nodes[i];

		memset(out, 0, sizeof(*out));
		strncpy(out->agent_id, node->agent_id, sizeof(out->agent_id) - 1);
		out->agent_id[sizeof(out->agent_id) - 1] = '\0';
		out->total_events = node->total_events;

		out->label_count = node->label_count;
		for (j = 0; j < node->label_count; j++)
			out->labels[j] = node->labels[j];

		out->event_count = node->event_count;
		for (j = 0; j < node->event_count; j++) {
			size_t idx = (node->event_head + TELEMETRY_STORE_MAX_EVENTS -
				      node->event_count + j) % TELEMETRY_STORE_MAX_EVENTS;
			out->events[j] = node->events[idx];
		}
	}

	pthread_mutex_unlock(&store->lock);
}
