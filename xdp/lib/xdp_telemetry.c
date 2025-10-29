#define _GNU_SOURCE

#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <linux/if_link.h>
#include <linux/limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#ifdef __has_include
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif
#endif
#ifndef LIBBPF_MAJOR_VERSION
#define LIBBPF_MAJOR_VERSION 0
#endif
#include "xdp_telemetry.h"
#include "telemetry_event.h"

/* forward decl for ringbuf callback */
static int meta_matches_filter(const struct xdp_telemetry_event_session *session,
                   const struct xdp_label_meta *meta);

struct xdp_telemetry_device {
	char ifname[IF_NAMESIZE];
	unsigned int ifindex;
	char prog_path[PATH_MAX];
	enum xdp_telemetry_attach_mode mode;
	bool pin_maps;
	char pin_root[PATH_MAX];
};

struct xdp_telemetry_rule_session {
	const struct xdp_telemetry_device *device;
	int rules_map_fd;
};

struct xdp_telemetry_event_session {
    const struct xdp_telemetry_device *device;
    int ringbuf_map_fd;
    struct ring_buffer *ringbuf;
    bool use_ringbuf;
    __u32 queue_id;

    xdp_telemetry_event_cb event_cb;
    void *event_user_data;

    __u32 *event_filter_label_ids;
    size_t event_filter_count;
};

static int ringbuf_sample_cb(void *ctx, void *data, size_t size)
{
    struct xdp_telemetry_event_session *session = ctx;
    const struct xdt_ringbuf_event *ev = data;
    struct xdp_telemetry_packet pkt = {0};
    size_t sample_len;

    if (!session || !session->event_cb)
        return 0;
    if (!ev || size < sizeof(*ev))
        return 0;

    if (!meta_matches_filter(session, &ev->meta))
        return 0;

    sample_len = ev->data_len;
    if (sample_len > XDT_RINGBUF_SAMPLE_SIZE)
        sample_len = XDT_RINGBUF_SAMPLE_SIZE;

    pkt.meta = ev->meta;
    pkt.data = ev->sample;
    pkt.data_len = sample_len;
    pkt.timestamp_ns = ev->ts_ns; /* monotonic; good enough for display */
    pkt.ifindex = session->device ? session->device->ifindex : 0;
    pkt.queue_id = ev->queue_id;
    pkt.forward_to_kernel = false; /* ringbuf path is mirror-only */
    pkt.addr_family = ev->addr_family;
    pkt.ip_proto = ev->ip_proto;
    pkt.src_port = ev->src_port;
    pkt.dst_port = ev->dst_port;
    pkt.src_ipv4 = ev->src_ipv4;
    pkt.dst_ipv4 = ev->dst_ipv4;

    session->event_cb(&pkt, session->event_user_data);
    return 0;
}

static const char *pin_root_or_default(const char *pin_root)
{
	if (pin_root && pin_root[0])
		return pin_root;
	return XDP_TELEMETRY_PIN_ROOT_DEFAULT;
}

static int ensure_pin_dir(const char *pin_root)
{
	const char *root = pin_root_or_default(pin_root);

	if (mkdir(root, 0755) && errno != EEXIST)
		return -errno;

	return 0;
}

static int build_map_path(const char *pin_root, const char *ifname,
			  const char *suffix, char *buf, size_t buf_sz)
{
	const char *root = pin_root_or_default(pin_root);

	if (!ifname || !ifname[0])
		return -EINVAL;

	if (snprintf(buf, buf_sz, "%s/%s_%s", root, ifname, suffix) >=
	    (int)buf_sz)
		return -ENAMETOOLONG;

	return 0;
}

static int ensure_rules_map_fd(struct xdp_telemetry_rule_session *session)
{
	char path[PATH_MAX];
	int fd;
	int err;
	const struct xdp_telemetry_device *device;

	if (!session || !session->device)
		return -EINVAL;

	device = session->device;

	if (session->rules_map_fd >= 0)
		return session->rules_map_fd;

	err = build_map_path(device->pin_root, device->ifname, "rules_v4",
			     path, sizeof(path));
	if (err)
		return err;

	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;

	session->rules_map_fd = fd;
	return session->rules_map_fd;
}

static void close_rules_map_fd(struct xdp_telemetry_rule_session *session)
{
	if (session && session->rules_map_fd >= 0) {
		close(session->rules_map_fd);
		session->rules_map_fd = -1;
	}
}

/* AF_XDP path removed in ringbuf-only mode */

#if defined(LIBBPF_MAJOR_VERSION) && LIBBPF_MAJOR_VERSION >= 1
#define HAVE_LIBBPF_XDP_ATTACH 1
#endif

static int attach_xdp_program(int ifindex, int prog_fd, __u32 flags)
{
#ifdef HAVE_LIBBPF_XDP_ATTACH
	return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
#else
	return bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
#endif
}

static int detach_xdp_program(int ifindex, __u32 flags)
{
#ifdef HAVE_LIBBPF_XDP_ATTACH
	return bpf_xdp_detach(ifindex, flags, NULL);
#else
	return bpf_set_link_xdp_fd(ifindex, -1, flags);
#endif
}

/* AF_XDP path removed in ringbuf-only mode */

/* AF_XDP path removed in ringbuf-only mode */

static void copy_string(char *dst, size_t dst_sz, const char *src)
{
	if (!dst || !dst_sz)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}
	strncpy(dst, src, dst_sz - 1);
	dst[dst_sz - 1] = '\0';
}

int xdp_telemetry_device_open(struct xdp_telemetry_device **devicep,
			     const struct xdp_telemetry_attach_opts *attach_opts)
{
	struct xdp_telemetry_device *device;

	if (!devicep)
		return -EINVAL;

	device = calloc(1, sizeof(*device));
	if (!device)
		return -ENOMEM;

	device->mode = XDP_TELEMETRY_ATTACH_MODE_SKB;
	device->pin_maps = true;

	if (attach_opts) {
		if (attach_opts->ifname) {
			copy_string(device->ifname, sizeof(device->ifname),
				    attach_opts->ifname);
			device->ifindex = if_nametoindex(attach_opts->ifname);
			if (!device->ifindex) {
				free(device);
				return -errno;
			}
		}
		copy_string(device->prog_path, sizeof(device->prog_path),
			    attach_opts->prog_path);
		device->mode = attach_opts->mode;
		if (attach_opts->pin_maps_set)
			device->pin_maps = attach_opts->pin_maps;
		copy_string(device->pin_root, sizeof(device->pin_root),
			    attach_opts->pin_path);
	} else {
		device->pin_maps = true;
	}

	*devicep = device;
	return 0;
}

void xdp_telemetry_device_close(struct xdp_telemetry_device *device)
{
	if (!device)
		return;
	free(device);
}

int xdp_telemetry_device_attach(const struct xdp_telemetry_device *device)
{
	char rules_path[PATH_MAX];
		struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *rules_map;
    struct bpf_map *events_map;
	int prog_fd;
	const char *obj_path;
	int err;
	int flags;

	if (!device)
		return -EINVAL;
	if (!device->ifname[0] || !device->ifindex)
		return -EINVAL;

	if (device->pin_maps) {
		err = ensure_pin_dir(device->pin_root);
		if (err)
			return err;
	}

	obj_path = device->prog_path[0] ? device->prog_path :
					  XDP_TELEMETRY_DEFAULT_OBJECT;

	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj)
		return -errno;

	rules_map = bpf_object__find_map_by_name(obj, "rules_v4");
	if (!rules_map) {
		fprintf(stderr,
			"xdp_telemetry_attach: rules_v4 map not found in object\n");
		err = -ENOENT;
		goto out_close;
	}

    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr,
                "xdp_telemetry_attach: events ringbuf map not found in object\n");
        err = -ENOENT;
        goto out_close;
    }

	if (device->pin_maps) {
		err = build_map_path(device->pin_root, device->ifname,
				     "rules_v4", rules_path,
				     sizeof(rules_path));
		if (err) {
			goto out_close;
		}
		unlink(rules_path);
		if (bpf_map__set_pin_path(rules_map, rules_path)) {
			fprintf(stderr,
				"xdp_telemetry_attach: failed to set pin path for rules_v4 map\n");
			err = -errno;
			goto out_close;
		}

        /* Pin ringbuf events map */
        {
            char events_path[PATH_MAX];
            err = build_map_path(device->pin_root, device->ifname, "events",
                         events_path, sizeof(events_path));
            if (err) {
                goto out_close;
            }
            unlink(events_path);
            if (bpf_map__set_pin_path(events_map, events_path)) {
                fprintf(stderr,
                        "xdp_telemetry_attach: failed to set pin path for events map\n");
                err = -errno;
                goto out_close;
            }
        }
	}

	err = bpf_object__load(obj);
	if (err)
		goto out_close;

	prog = bpf_object__find_program_by_name(obj, "xdp_labeler");
	if (!prog) {
		err = -ENOENT;
		goto out_close;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		err = prog_fd;
		goto out_close;
	}

	flags = device->mode == XDP_TELEMETRY_ATTACH_MODE_NATIVE ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

	err = attach_xdp_program(device->ifindex, prog_fd, flags);
	if (err)
		goto out_close;

	err = 0;

out_close:
	bpf_object__close(obj);
	return err;
}

int xdp_telemetry_device_detach(const struct xdp_telemetry_device *device)
{
    char rules_path[PATH_MAX];
        char events_path[PATH_MAX];
    int flags;
    int err;

	if (!device || !device->ifindex)
		return -EINVAL;

	flags = device->mode == XDP_TELEMETRY_ATTACH_MODE_NATIVE ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

	err = detach_xdp_program(device->ifindex, flags);
	if (err && err != -ENOENT && err != -ENODEV)
		return err;

    if (device->pin_maps) {
        if (!build_map_path(device->pin_root, device->ifname, "rules_v4",
                    rules_path, sizeof(rules_path)) &&
            unlink(rules_path) && errno != ENOENT) {
            fprintf(stderr,
                    "xdp_telemetry_detach: warning: failed to unlink %s: %s\n",
                    rules_path, strerror(errno));
        }
                if (!build_map_path(device->pin_root, device->ifname, "events",
                    events_path, sizeof(events_path)) &&
            unlink(events_path) && errno != ENOENT) {
            fprintf(stderr,
                    "xdp_telemetry_detach: warning: failed to unlink %s: %s\n",
                    events_path, strerror(errno));
        }
    }

	return 0;
}

int xdp_telemetry_rule_session_open(const struct xdp_telemetry_device *device,
				   struct xdp_telemetry_rule_session **sessionp)
{
	struct xdp_telemetry_rule_session *session;

	if (!device || !sessionp)
		return -EINVAL;

	session = calloc(1, sizeof(*session));
	if (!session)
		return -ENOMEM;

	session->device = device;
	session->rules_map_fd = -1;

	*sessionp = session;
	return 0;
}

void xdp_telemetry_rule_session_close(struct xdp_telemetry_rule_session *session)
{
	if (!session)
		return;

	close_rules_map_fd(session);
	free(session);
}

static int map_update_rule(int map_fd, const struct xdp_telemetry_rule *rule)
{
	struct rule_value value = {
	};
	int flags;

	if (!rule)
		return -EINVAL;

	flags = rule->replace ? BPF_ANY : BPF_NOEXIST;

	value.action = rule->action;
	value.label_id = rule->label_id;
	value.prefixlen = rule->key.prefixlen;
	value.addr = rule->key.addr;

	if (bpf_map_update_elem(map_fd, &rule->key, &value, flags) < 0)
		return -errno;

	return 0;
}

int xdp_telemetry_rule_upsert(struct xdp_telemetry_rule_session *session,
			     const struct xdp_telemetry_rule *rule)
{
	int map_fd;
	int err;

	if (!session || !session->device || !rule)
		return -EINVAL;

	map_fd = ensure_rules_map_fd(session);
	if (map_fd < 0)
		return map_fd;

	err = map_update_rule(map_fd, rule);
	if (err < 0)
		return err;

	return 0;
}

int xdp_telemetry_rule_bulk_upsert(struct xdp_telemetry_rule_session *session,
				  const struct xdp_telemetry_rule *rules,
				  size_t rule_count)
{
	size_t i;
	int err = 0;

	if (!session || !session->device || (!rules && rule_count))
		return -EINVAL;

	for (i = 0; i < rule_count; i++) {
		err = xdp_telemetry_rule_upsert(session, &rules[i]);
		if (err)
			break;
	}

	return err;
}

int xdp_telemetry_rule_remove(struct xdp_telemetry_rule_session *session,
			     const struct lpm_v4_key *key)
{
	int map_fd;

	if (!session || !session->device || !key)
		return -EINVAL;

	map_fd = ensure_rules_map_fd(session);
	if (map_fd < 0)
		return map_fd;

	if (bpf_map_delete_elem(map_fd, key) < 0)
		return -errno;

	return 0;
}

int xdp_telemetry_rule_list(struct xdp_telemetry_rule_session *session,
			   struct xdp_telemetry_rule_list *out)
{
	struct lpm_v4_key key = {0};
	struct lpm_v4_key next_key = {0};
	struct rule_value value;
	struct xdp_telemetry_rule *rules = NULL;
	size_t count = 0;
	size_t capacity = 0;
	bool have_key = false;
	int map_fd;
	int err;

	if (!session || !session->device || !out)
		return -EINVAL;

	out->rules = NULL;
	out->count = 0;

	map_fd = ensure_rules_map_fd(session);
	if (map_fd < 0)
		return map_fd;

	while (true) {
		err = bpf_map_get_next_key(map_fd, have_key ? &key : NULL,
					   &next_key);
		if (err) {
			if (errno == ENOENT)
				break;
			err = -errno;
			goto err_out;
		}

		if (bpf_map_lookup_elem(map_fd, &next_key, &value) < 0) {
			err = -errno;
			goto err_out;
		}

		if (count == capacity) {
			size_t new_cap = capacity ? capacity * 2 : 16;
			void *tmp = realloc(rules,
					    new_cap * sizeof(*rules));
			if (!tmp) {
				err = -ENOMEM;
				goto err_out;
			}
			rules = tmp;
			capacity = new_cap;
		}

		rules[count].key = next_key;
		rules[count].action = value.action;
		rules[count].label_id = value.label_id;
		rules[count].replace = true;
		count++;

		key = next_key;
		have_key = true;
	}

	out->rules = rules;
	out->count = count;
	return 0;

err_out:
	free(rules);
	return err;
}

void xdp_telemetry_rule_list_free(struct xdp_telemetry_rule_list *list)
{
	if (!list)
		return;
	free(list->rules);
	list->rules = NULL;
	list->count = 0;
}

static int ensure_events_map(struct xdp_telemetry_event_session *session)
{
    char path[PATH_MAX];
    int fd;
    int err;

    if (!session || !session->device)
        return -EINVAL;

    if (session->ringbuf_map_fd >= 0)
        return session->ringbuf_map_fd;

    err = build_map_path(session->device->pin_root,
                 session->device->ifname, "events", path,
                 sizeof(path));
    if (err)
        return err;

    fd = bpf_obj_get(path);
    if (fd < 0)
        return -errno;

    session->ringbuf_map_fd = fd;
    return session->ringbuf_map_fd;
}

static int meta_matches_filter(const struct xdp_telemetry_event_session *session,
			       const struct xdp_label_meta *meta)
{
	size_t i;

	if (!session->event_filter_label_ids ||
	    session->event_filter_count == 0)
		return 1;

	for (i = 0; i < session->event_filter_count; i++) {
		if (session->event_filter_label_ids[i] == meta->label_id)
			return 1;
	}
	return 0;
}

static __u64 realtime_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;

	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

int xdp_telemetry_event_session_open(const struct xdp_telemetry_device *device,
                    struct xdp_telemetry_event_session **sessionp)
{
    struct xdp_telemetry_event_session *session;

	if (!device || !sessionp)
		return -EINVAL;

	session = calloc(1, sizeof(*session));
	if (!session)
		return -ENOMEM;

    session->device = device;
    session->ringbuf_map_fd = -1;
    session->ringbuf = NULL;
    session->use_ringbuf = true;
    session->queue_id = 0;

	*sessionp = session;
	return 0;
}

void xdp_telemetry_event_session_close(struct xdp_telemetry_event_session *session)
{
    if (!session)
        return;

    xdp_telemetry_events_unsubscribe(session);
    if (session->ringbuf_map_fd >= 0) {
        close(session->ringbuf_map_fd);
        session->ringbuf_map_fd = -1;
    }
    free(session);
}

int xdp_telemetry_events_subscribe(struct xdp_telemetry_event_session *session,
                  const struct xdp_telemetry_event_filter *filter,
                  xdp_telemetry_event_cb callback,
                  void *user_data)
{
    /* Ringbuf (mirror) only */
    int ev_map_fd;
    size_t bytes;

    if (!session || !session->device || !callback)
        return -EINVAL;
    if (session->ringbuf)
        return -EALREADY;

    ev_map_fd = ensure_events_map(session);
    if (ev_map_fd < 0)
        return ev_map_fd;

    session->event_cb = callback;
    session->event_user_data = user_data;

    free(session->event_filter_label_ids);
    session->event_filter_label_ids = NULL;
    session->event_filter_count = 0;
    if (filter && filter->label_ids && filter->label_id_count) {
        bytes = filter->label_id_count * sizeof(*filter->label_ids);
        session->event_filter_label_ids = malloc(bytes);
        if (!session->event_filter_label_ids)
            return -ENOMEM;
        memcpy(session->event_filter_label_ids, filter->label_ids, bytes);
        session->event_filter_count = filter->label_id_count;
    }

    session->ringbuf = ring_buffer__new(ev_map_fd, ringbuf_sample_cb, session, NULL);
    if (!session->ringbuf)
        return -errno;
    session->use_ringbuf = true;
    session->ringbuf_map_fd = ev_map_fd;
    return 0;
}

int xdp_telemetry_events_poll(struct xdp_telemetry_event_session *session,
                 int timeout_ms)
{
    if (!session || !session->ringbuf)
        return -EINVAL;
    {
        int ret = ring_buffer__poll(session->ringbuf, timeout_ms);
        if (ret < 0)
            return ret; /* libbpf-style negative error */
        return 0;
    }
}

int xdp_telemetry_events_unsubscribe(struct xdp_telemetry_event_session *session)
{
    if (!session)
        return -EINVAL;

    if (session->ringbuf) {
        ring_buffer__free(session->ringbuf);
        session->ringbuf = NULL;
    }
    if (session->ringbuf_map_fd >= 0) {
        close(session->ringbuf_map_fd);
        session->ringbuf_map_fd = -1;
    }
    session->event_cb = NULL;
    session->event_user_data = NULL;
    free(session->event_filter_label_ids);
    session->event_filter_label_ids = NULL;
    session->event_filter_count = 0;

    return 0;
}

int xdp_telemetry_stats_get(struct xdp_telemetry_rule_session *session,
			   __u32 label_id, __u64 *hit_count)
{
	(void)session;
	(void)label_id;
	(void)hit_count;

	return -ENOTSUP;
}
