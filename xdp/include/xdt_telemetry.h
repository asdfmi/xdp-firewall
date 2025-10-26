#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifndef __VMLINUX_H__
#include <linux/if_link.h>
#include <linux/types.h>
#endif

#define XDT_TELEMETRY_DEFAULT_OBJECT "build/xdp.bpf.o"
#define XDT_TELEMETRY_PIN_ROOT_DEFAULT "/sys/fs/bpf/xdt-telemetry"

#include "label_meta.h"
#include "rule.h"

struct xdt_telemetry_device;
struct xdt_telemetry_rule_session;
struct xdt_telemetry_event_session;

enum xdt_telemetry_attach_mode {
	XDT_TELEMETRY_ATTACH_MODE_SKB = 0,
	XDT_TELEMETRY_ATTACH_MODE_NATIVE = 1,
};

struct xdt_telemetry_attach_opts {
	const char *ifname;
	const char *prog_path;
	enum xdt_telemetry_attach_mode mode;
	bool pin_maps;
	bool pin_maps_set;
	const char *pin_path;
};

struct xdt_telemetry_rule {
	struct lpm_v4_key key;
	__u32 action;
	__u32 label_id;
	bool replace;
};

struct xdt_telemetry_rule_list {
	struct xdt_telemetry_rule *rules;
	size_t count;
};

struct xdt_telemetry_event_filter {
	const __u32 *label_ids;
	size_t label_id_count;
};

struct xdt_telemetry_packet {
	struct xdp_label_meta meta;
	const void *data;
	size_t data_len;
	__u64 timestamp_ns;
	__u32 ifindex;
	__u32 queue_id;
	bool forward_to_kernel;
};

typedef void (*xdt_telemetry_event_cb)(struct xdt_telemetry_packet *packet,
				      void *user_data);

int xdt_telemetry_device_open(struct xdt_telemetry_device **device,
			     const struct xdt_telemetry_attach_opts *attach_opts);
void xdt_telemetry_device_close(struct xdt_telemetry_device *device);

int xdt_telemetry_device_attach(const struct xdt_telemetry_device *device);
int xdt_telemetry_device_detach(const struct xdt_telemetry_device *device);

int xdt_telemetry_rule_session_open(const struct xdt_telemetry_device *device,
				   struct xdt_telemetry_rule_session **session);
void xdt_telemetry_rule_session_close(struct xdt_telemetry_rule_session *session);

int xdt_telemetry_rule_upsert(struct xdt_telemetry_rule_session *session,
			     const struct xdt_telemetry_rule *rule);
int xdt_telemetry_rule_bulk_upsert(struct xdt_telemetry_rule_session *session,
				  const struct xdt_telemetry_rule *rules,
				  size_t rule_count);
int xdt_telemetry_rule_remove(struct xdt_telemetry_rule_session *session,
			     const struct lpm_v4_key *key);
int xdt_telemetry_rule_list(struct xdt_telemetry_rule_session *session,
			   struct xdt_telemetry_rule_list *out);
void xdt_telemetry_rule_list_free(struct xdt_telemetry_rule_list *list);

int xdt_telemetry_event_session_open(const struct xdt_telemetry_device *device,
				    struct xdt_telemetry_event_session **session);
void xdt_telemetry_event_session_close(struct xdt_telemetry_event_session *session);

int xdt_telemetry_events_subscribe(struct xdt_telemetry_event_session *session,
				  const struct xdt_telemetry_event_filter *filter,
				  xdt_telemetry_event_cb callback,
				  void *user_data);
int xdt_telemetry_events_poll(struct xdt_telemetry_event_session *session,
			     int timeout_ms);
int xdt_telemetry_events_unsubscribe(struct xdt_telemetry_event_session *session);

int xdt_telemetry_stats_get(struct xdt_telemetry_rule_session *session,
			   __u32 label_id, __u64 *hit_count);
