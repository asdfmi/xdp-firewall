#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifndef __VMLINUX_H__
#include <linux/if_link.h>
#include <linux/types.h>
#endif

#define XDP_LABELING_DEFAULT_OBJECT "build/xdp_labeler.bpf.o"
#define XDP_LABELING_PIN_ROOT_DEFAULT "/sys/fs/bpf/xdp-labeling"

#include "label_meta.h"
#include "rule.h"

struct xdp_labeling_device;
struct xdp_labeling_rule_session;
struct xdp_labeling_event_session;

enum xdp_labeling_attach_mode {
	XDP_LABELING_ATTACH_MODE_SKB = 0,
	XDP_LABELING_ATTACH_MODE_NATIVE = 1,
};

struct xdp_labeling_attach_opts {
	const char *ifname;
	const char *prog_path;
	enum xdp_labeling_attach_mode mode;
	bool pin_maps;
	bool pin_maps_set;
	const char *pin_path;
};

struct xdp_labeling_rule {
	struct lpm_v4_key key;
	__u32 action;
	__u32 label_id;
	bool replace;
};

struct xdp_labeling_rule_list {
	struct xdp_labeling_rule *rules;
	size_t count;
};

struct xdp_labeling_event_filter {
	const __u32 *label_ids;
	size_t label_id_count;
};

struct xdp_label_packet {
	struct xdp_label_meta meta;
	const void *data;
	size_t data_len;
	__u64 timestamp_ns;
	__u32 ifindex;
	__u32 queue_id;
};

typedef void (*xdp_labeling_event_cb)(const struct xdp_label_packet *packet,
				      void *user_data);

int xdp_labeling_device_open(struct xdp_labeling_device **device,
			     const struct xdp_labeling_attach_opts *attach_opts);
void xdp_labeling_device_close(struct xdp_labeling_device *device);

int xdp_labeling_device_attach(const struct xdp_labeling_device *device);
int xdp_labeling_device_detach(const struct xdp_labeling_device *device);

int xdp_labeling_rule_session_open(const struct xdp_labeling_device *device,
				   struct xdp_labeling_rule_session **session);
void xdp_labeling_rule_session_close(struct xdp_labeling_rule_session *session);

int xdp_labeling_rule_upsert(struct xdp_labeling_rule_session *session,
			     const struct xdp_labeling_rule *rule);
int xdp_labeling_rule_bulk_upsert(struct xdp_labeling_rule_session *session,
				  const struct xdp_labeling_rule *rules,
				  size_t rule_count);
int xdp_labeling_rule_remove(struct xdp_labeling_rule_session *session,
			     const struct lpm_v4_key *key);
int xdp_labeling_rule_list(struct xdp_labeling_rule_session *session,
			   struct xdp_labeling_rule_list *out);
void xdp_labeling_rule_list_free(struct xdp_labeling_rule_list *list);

int xdp_labeling_event_session_open(const struct xdp_labeling_device *device,
				    struct xdp_labeling_event_session **session);
void xdp_labeling_event_session_close(struct xdp_labeling_event_session *session);

int xdp_labeling_events_subscribe(struct xdp_labeling_event_session *session,
				  const struct xdp_labeling_event_filter *filter,
				  xdp_labeling_event_cb callback,
				  void *user_data);
int xdp_labeling_events_poll(struct xdp_labeling_event_session *session,
			     int timeout_ms);
int xdp_labeling_events_unsubscribe(struct xdp_labeling_event_session *session);

int xdp_labeling_stats_get(struct xdp_labeling_rule_session *session,
			   __u32 label_id, __u64 *hit_count);
