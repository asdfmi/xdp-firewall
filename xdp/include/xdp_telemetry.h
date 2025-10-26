#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifndef __VMLINUX_H__
#include <linux/if_link.h>
#include <linux/types.h>
#endif

#define XDP_TELEMETRY_DEFAULT_OBJECT "build/xdp.bpf.o"
#define XDP_TELEMETRY_PIN_ROOT_DEFAULT "/sys/fs/bpf/xdp-telemetry"

#include "label_meta.h"
#include "rule.h"

struct xdp_telemetry_device;
struct xdp_telemetry_rule_session;
struct xdp_telemetry_event_session;

enum xdp_telemetry_attach_mode {
	XDP_TELEMETRY_ATTACH_MODE_SKB = 0,
	XDP_TELEMETRY_ATTACH_MODE_NATIVE = 1,
};

struct xdp_telemetry_attach_opts {
	const char *ifname;
	const char *prog_path;
	enum xdp_telemetry_attach_mode mode;
	bool pin_maps;
	bool pin_maps_set;
	const char *pin_path;
};

struct xdp_telemetry_rule {
	struct lpm_v4_key key;
	__u32 action;
	__u32 label_id;
	bool replace;
};

struct xdp_telemetry_rule_list {
	struct xdp_telemetry_rule *rules;
	size_t count;
};

struct xdp_telemetry_event_filter {
	const __u32 *label_ids;
	size_t label_id_count;
};

struct xdp_telemetry_packet {
	struct xdp_label_meta meta;
	const void *data;
	size_t data_len;
	__u64 timestamp_ns;
	__u32 ifindex;
	__u32 queue_id;
	bool forward_to_kernel;
};

typedef void (*xdp_telemetry_event_cb)(struct xdp_telemetry_packet *packet,
				      void *user_data);

int xdp_telemetry_device_open(struct xdp_telemetry_device **device,
			     const struct xdp_telemetry_attach_opts *attach_opts);
void xdp_telemetry_device_close(struct xdp_telemetry_device *device);

int xdp_telemetry_device_attach(const struct xdp_telemetry_device *device);
int xdp_telemetry_device_detach(const struct xdp_telemetry_device *device);

int xdp_telemetry_rule_session_open(const struct xdp_telemetry_device *device,
				   struct xdp_telemetry_rule_session **session);
void xdp_telemetry_rule_session_close(struct xdp_telemetry_rule_session *session);

int xdp_telemetry_rule_upsert(struct xdp_telemetry_rule_session *session,
			     const struct xdp_telemetry_rule *rule);
int xdp_telemetry_rule_bulk_upsert(struct xdp_telemetry_rule_session *session,
				  const struct xdp_telemetry_rule *rules,
				  size_t rule_count);
int xdp_telemetry_rule_remove(struct xdp_telemetry_rule_session *session,
			     const struct lpm_v4_key *key);
int xdp_telemetry_rule_list(struct xdp_telemetry_rule_session *session,
			   struct xdp_telemetry_rule_list *out);
void xdp_telemetry_rule_list_free(struct xdp_telemetry_rule_list *list);

int xdp_telemetry_event_session_open(const struct xdp_telemetry_device *device,
				    struct xdp_telemetry_event_session **session);
void xdp_telemetry_event_session_close(struct xdp_telemetry_event_session *session);

int xdp_telemetry_events_subscribe(struct xdp_telemetry_event_session *session,
				  const struct xdp_telemetry_event_filter *filter,
				  xdp_telemetry_event_cb callback,
				  void *user_data);
int xdp_telemetry_events_poll(struct xdp_telemetry_event_session *session,
			     int timeout_ms);
int xdp_telemetry_events_unsubscribe(struct xdp_telemetry_event_session *session);

int xdp_telemetry_stats_get(struct xdp_telemetry_rule_session *session,
			   __u32 label_id, __u64 *hit_count);
