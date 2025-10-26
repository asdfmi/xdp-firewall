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
#if __has_include(<xdp/xsk.h>)
#include <xdp/xsk.h>
#elif __has_include(<bpf/xsk.h>)
#include <bpf/xsk.h>
#elif __has_include(<xsk.h>)
#include <xsk.h>
#else
#error "AF_XDP headers not found"
#endif
#else
#include <xdp/xsk.h>
#endif

#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP 0
#endif

#include "xdp_labeling.h"

struct xdp_labeling_device {
	char ifname[IF_NAMESIZE];
	unsigned int ifindex;
	char prog_path[PATH_MAX];
	enum xdp_labeling_attach_mode mode;
	bool pin_maps;
	char pin_root[PATH_MAX];
};

struct xdp_labeling_rule_session {
	const struct xdp_labeling_device *device;
	int rules_map_fd;
};

#define XSK_FRAME_COUNT 1024u
#define XSK_FRAME_SIZE 2048u
#define XSK_RING_DEPTH 256u
#define XSK_BATCH_SIZE 64u
#define XSK_FRAME_HEADROOM 256u

struct xdp_labeling_event_session {
	const struct xdp_labeling_device *device;
	int xsks_map_fd;

	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	void *umem_area;
	size_t umem_area_size;
	__u32 queue_id;

	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	int xsk_fd;

	xdp_labeling_event_cb event_cb;
	void *event_user_data;

	__u32 *event_filter_label_ids;
	size_t event_filter_count;
};

static const char *pin_root_or_default(const char *pin_root)
{
	if (pin_root && pin_root[0])
		return pin_root;
	return XDP_LABELING_PIN_ROOT_DEFAULT;
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

static int ensure_rules_map_fd(struct xdp_labeling_rule_session *session)
{
	char path[PATH_MAX];
	int fd;
	int err;
	const struct xdp_labeling_device *device;

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

static void close_rules_map_fd(struct xdp_labeling_rule_session *session)
{
	if (session && session->rules_map_fd >= 0) {
		close(session->rules_map_fd);
		session->rules_map_fd = -1;
	}
}

static void close_xsks_map_fd(struct xdp_labeling_event_session *session)
{
	if (session && session->xsks_map_fd >= 0) {
		close(session->xsks_map_fd);
		session->xsks_map_fd = -1;
	}
}

static void detach_xsk_from_map(struct xdp_labeling_event_session *session)
{
	if (!session || session->xsks_map_fd < 0)
		return;

	(void)bpf_map_delete_elem(session->xsks_map_fd, &session->queue_id);
}

static void destroy_event_transport(struct xdp_labeling_event_session *session)
{
	if (!session)
		return;

	if (session->xsk) {
		xsk_socket__delete(session->xsk);
		session->xsk = NULL;
	}
	session->xsk_fd = -1;

	if (session->umem) {
		xsk_umem__delete(session->umem);
		session->umem = NULL;
	}

	if (session->umem_area) {
		free(session->umem_area);
		session->umem_area = NULL;
		session->umem_area_size = 0;
	}
}

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

int xdp_labeling_device_open(struct xdp_labeling_device **devicep,
			     const struct xdp_labeling_attach_opts *attach_opts)
{
	struct xdp_labeling_device *device;

	if (!devicep)
		return -EINVAL;

	device = calloc(1, sizeof(*device));
	if (!device)
		return -ENOMEM;

	device->mode = XDP_LABELING_ATTACH_MODE_SKB;
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

void xdp_labeling_device_close(struct xdp_labeling_device *device)
{
	if (!device)
		return;
	free(device);
}

int xdp_labeling_device_attach(const struct xdp_labeling_device *device)
{
	char rules_path[PATH_MAX];
	char xsks_path[PATH_MAX];
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *rules_map;
	struct bpf_map *xsks_map;
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
					  XDP_LABELING_DEFAULT_OBJECT;

	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj)
		return -errno;

	rules_map = bpf_object__find_map_by_name(obj, "rules_v4");
	if (!rules_map) {
		fprintf(stderr,
			"xdp_labeling_attach: rules_v4 map not found in object\n");
		err = -ENOENT;
		goto out_close;
	}

	xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
	if (!xsks_map) {
		fprintf(stderr,
			"xdp_labeling_attach: xsks_map not found in object\n");
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
				"xdp_labeling_attach: failed to set pin path for rules_v4 map\n");
			err = -errno;
			goto out_close;
		}

		err = build_map_path(device->pin_root, device->ifname, "xsks",
				     xsks_path, sizeof(xsks_path));
		if (err) {
			goto out_close;
		}
		unlink(xsks_path);
		if (bpf_map__set_pin_path(xsks_map, xsks_path)) {
			fprintf(stderr,
				"xdp_labeling_attach: failed to set pin path for xsks map\n");
			err = -errno;
			goto out_close;
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

	flags = device->mode == XDP_LABELING_ATTACH_MODE_NATIVE ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

	err = bpf_xdp_attach(device->ifindex, prog_fd, flags, NULL);
	if (err)
		goto out_close;

	err = 0;

out_close:
	bpf_object__close(obj);
	return err;
}

int xdp_labeling_device_detach(const struct xdp_labeling_device *device)
{
	char rules_path[PATH_MAX];
	char xsks_path[PATH_MAX];
	int flags;
	int err;

	if (!device || !device->ifindex)
		return -EINVAL;

	flags = device->mode == XDP_LABELING_ATTACH_MODE_NATIVE ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

	err = bpf_xdp_detach(device->ifindex, flags, NULL);
	if (err && err != -ENOENT && err != -ENODEV)
		return err;

	if (device->pin_maps) {
		if (!build_map_path(device->pin_root, device->ifname, "rules_v4",
				    rules_path, sizeof(rules_path)) &&
		    unlink(rules_path) && errno != ENOENT) {
			fprintf(stderr,
				"xdp_labeling_detach: warning: failed to unlink %s: %s\n",
				rules_path, strerror(errno));
		}
		if (!build_map_path(device->pin_root, device->ifname, "xsks",
				    xsks_path, sizeof(xsks_path)) &&
		    unlink(xsks_path) && errno != ENOENT) {
			fprintf(stderr,
				"xdp_labeling_detach: warning: failed to unlink %s: %s\n",
				xsks_path, strerror(errno));
		}
	}

	return 0;
}

int xdp_labeling_rule_session_open(const struct xdp_labeling_device *device,
				   struct xdp_labeling_rule_session **sessionp)
{
	struct xdp_labeling_rule_session *session;

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

void xdp_labeling_rule_session_close(struct xdp_labeling_rule_session *session)
{
	if (!session)
		return;

	close_rules_map_fd(session);
	free(session);
}

static int map_update_rule(int map_fd, const struct xdp_labeling_rule *rule)
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

int xdp_labeling_rule_upsert(struct xdp_labeling_rule_session *session,
			     const struct xdp_labeling_rule *rule)
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

int xdp_labeling_rule_bulk_upsert(struct xdp_labeling_rule_session *session,
				  const struct xdp_labeling_rule *rules,
				  size_t rule_count)
{
	size_t i;
	int err = 0;

	if (!session || !session->device || (!rules && rule_count))
		return -EINVAL;

	for (i = 0; i < rule_count; i++) {
		err = xdp_labeling_rule_upsert(session, &rules[i]);
		if (err)
			break;
	}

	return err;
}

int xdp_labeling_rule_remove(struct xdp_labeling_rule_session *session,
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

int xdp_labeling_rule_list(struct xdp_labeling_rule_session *session,
			   struct xdp_labeling_rule_list *out)
{
	struct lpm_v4_key key = {0};
	struct lpm_v4_key next_key = {0};
	struct rule_value value;
	struct xdp_labeling_rule *rules = NULL;
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

void xdp_labeling_rule_list_free(struct xdp_labeling_rule_list *list)
{
	if (!list)
		return;
	free(list->rules);
	list->rules = NULL;
	list->count = 0;
}

static int ensure_xsks_map(struct xdp_labeling_event_session *session)
{
	char path[PATH_MAX];
	int fd;
	int err;

	if (!session || !session->device)
		return -EINVAL;

	if (session->xsks_map_fd >= 0)
		return session->xsks_map_fd;

	err = build_map_path(session->device->pin_root,
			     session->device->ifname, "xsks", path,
			     sizeof(path));
	if (err)
		return err;

	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;

	session->xsks_map_fd = fd;
	return session->xsks_map_fd;
}

static int meta_matches_filter(const struct xdp_labeling_event_session *session,
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

static int event_session_prepare_umem(struct xdp_labeling_event_session *session)
{
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_DEPTH,
		.comp_size = XSK_RING_DEPTH,
		.frame_size = XSK_FRAME_SIZE,
		.frame_headroom = XSK_FRAME_HEADROOM,
		.flags = 0,
	};
	size_t size;
	void *area;
	int err;
	int ret;

	if (!session)
		return -EINVAL;

	size = (size_t)XSK_FRAME_SIZE * XSK_FRAME_COUNT;
	ret = posix_memalign(&area, getpagesize(), size);
	if (ret)
		return -ret;

	memset(area, 0, size);

	err = xsk_umem__create(&session->umem, area, size,
			       &session->fq, &session->cq, &cfg);
	if (err) {
		free(area);
		session->umem = NULL;
		return err;
	}

	session->umem_area = area;
	session->umem_area_size = size;
	return 0;
}

static int event_session_prime_fill_queue(struct xdp_labeling_event_session *session)
{
	__u64 addr = 0;

	while (addr < XSK_FRAME_COUNT) {
		__u32 idx;
		unsigned int chunk = XSK_FRAME_COUNT - addr;
		unsigned int reserved;
		unsigned int i;

		reserved = xsk_ring_prod__reserve(&session->fq, chunk, &idx);
		if (!reserved)
			continue;

		for (i = 0; i < reserved; i++)
			*xsk_ring_prod__fill_addr(&session->fq, idx + i) =
				(addr + i) * XSK_FRAME_SIZE;

		xsk_ring_prod__submit(&session->fq, reserved);
		addr += reserved;
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

static void event_session_reclaim_tx(struct xdp_labeling_event_session *session)
{
	__u64 addrs[XSK_BATCH_SIZE];
	unsigned int idx_cq;
	unsigned int completed;
	unsigned int i;

	if (!session)
		return;

	while ((completed = xsk_ring_cons__peek(&session->cq,
						XSK_BATCH_SIZE, &idx_cq)) > 0) {
		for (i = 0; i < completed; i++)
			addrs[i] = *xsk_ring_cons__comp_addr(&session->cq,
							     idx_cq + i);

		xsk_ring_cons__release(&session->cq, completed);

		for (i = 0; i < completed;) {
			__u32 idx_fq;
			unsigned int reserved =
				xsk_ring_prod__reserve(&session->fq,
						       completed - i,
						       &idx_fq);
			unsigned int j;

			if (!reserved)
				continue;

			for (j = 0; j < reserved; j++)
				*xsk_ring_prod__fill_addr(&session->fq,
							  idx_fq + j) =
					addrs[i + j];

			xsk_ring_prod__submit(&session->fq, reserved);
			i += reserved;
		}
	}
}

static int event_session_process_rx(struct xdp_labeling_event_session *session)
{
	__u64 addrs[XSK_BATCH_SIZE];
	__u32 lengths[XSK_BATCH_SIZE];
	bool forward_flags[XSK_BATCH_SIZE];
	unsigned int handled = 0;
	__u32 idx_rx;
	unsigned int rcvd;
	unsigned int i;
	bool kick_tx = false;

	event_session_reclaim_tx(session);

	rcvd = xsk_ring_cons__peek(&session->rx, XSK_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return 0;

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc =
			xsk_ring_cons__rx_desc(&session->rx, idx_rx + i);
		__u64 base_addr = xsk_umem__extract_addr(desc->addr);
		__u64 offset = xsk_umem__extract_offset(desc->addr);
		unsigned char *base = xsk_umem__get_data(session->umem_area,
							 base_addr);
		unsigned char *data = base ? base + offset : NULL;
		const struct xdp_label_meta *meta;
		struct xdp_label_packet packet = {0};

		forward_flags[i] = false;
		addrs[i] = desc->addr;
		lengths[i] = desc->len;

		if (!data)
			continue;

		meta = (const struct xdp_label_meta *)(data -
						       sizeof(*meta));
		if ((const void *)meta < session->umem_area)
			continue;
		if ((const void *)meta < (const void *)base)
			continue;
		if ((const unsigned char *)(meta + 1) > data)
			continue;

		if (!meta_matches_filter(session, meta))
			continue;

		if (!session->event_cb)
			continue;

		packet.meta = *meta;
		packet.data = data;
		packet.data_len = desc->len;
		packet.timestamp_ns = realtime_now_ns();
		packet.ifindex = session->device->ifindex;
		packet.queue_id = session->queue_id;
		packet.forward_to_kernel = false;

		session->event_cb(&packet, session->event_user_data);
		if (packet.forward_to_kernel)
			forward_flags[i] = true;
		handled++;
	}

	xsk_ring_cons__release(&session->rx, rcvd);

	for (i = 0; i < rcvd; i++) {
		if (forward_flags[i]) {
			struct xdp_desc *tx_desc;
			__u32 idx_tx;

			while (!xsk_ring_prod__reserve(&session->tx, 1,
						       &idx_tx))
				event_session_reclaim_tx(session);

			tx_desc = xsk_ring_prod__tx_desc(&session->tx, idx_tx);
			tx_desc->addr = addrs[i];
			tx_desc->len = lengths[i];

			xsk_ring_prod__submit(&session->tx, 1);
			if (xsk_ring_prod__needs_wakeup(&session->tx))
				kick_tx = true;
		} else {
			__u32 idx_fq;

			while (!xsk_ring_prod__reserve(&session->fq, 1,
						       &idx_fq))
				event_session_reclaim_tx(session);

			*xsk_ring_prod__fill_addr(&session->fq, idx_fq) =
				addrs[i];
			xsk_ring_prod__submit(&session->fq, 1);
		}
	}

	if (kick_tx && session->xsk_fd >= 0)
		(void)sendto(session->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

	return (int)handled;
}

int xdp_labeling_event_session_open(const struct xdp_labeling_device *device,
				    struct xdp_labeling_event_session **sessionp)
{
	struct xdp_labeling_event_session *session;

	if (!device || !sessionp)
		return -EINVAL;

	session = calloc(1, sizeof(*session));
	if (!session)
		return -ENOMEM;

	session->device = device;
	session->xsks_map_fd = -1;
	session->queue_id = 0;
	session->xsk_fd = -1;

	*sessionp = session;
	return 0;
}

void xdp_labeling_event_session_close(struct xdp_labeling_event_session *session)
{
	if (!session)
		return;

	xdp_labeling_events_unsubscribe(session);
	close_xsks_map_fd(session);
	free(session);
}

int xdp_labeling_events_subscribe(struct xdp_labeling_event_session *session,
				  const struct xdp_labeling_event_filter *filter,
				  xdp_labeling_event_cb callback,
				  void *user_data)
{
	struct xsk_socket_config xsk_cfg = {
		.rx_size = XSK_RING_DEPTH,
		.tx_size = XSK_RING_DEPTH,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = 0,
		.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
	};
	int map_fd;
	size_t bytes;
	int err;
	int xsk_fd;

	if (!session || !session->device || !callback)
		return -EINVAL;
	if (session->xsk)
		return -EALREADY;

	map_fd = ensure_xsks_map(session);
	if (map_fd < 0)
		return map_fd;

	err = event_session_prepare_umem(session);
	if (err)
		goto err_cleanup_map;

	err = xsk_socket__create(&session->xsk, session->device->ifname,
				 session->queue_id, session->umem,
				 &session->rx, &session->tx, &xsk_cfg);
	if (err)
		goto err_cleanup_transport;

	err = event_session_prime_fill_queue(session);
	if (err)
		goto err_cleanup_transport;

	xsk_fd = xsk_socket__fd(session->xsk);
	if (bpf_map_update_elem(map_fd, &session->queue_id, &xsk_fd, 0) < 0) {
		err = -errno;
		goto err_cleanup_transport;
	}
	session->xsk_fd = xsk_fd;

	session->event_cb = callback;
	session->event_user_data = user_data;

	free(session->event_filter_label_ids);
	session->event_filter_label_ids = NULL;
	session->event_filter_count = 0;

	if (filter && filter->label_ids && filter->label_id_count) {
		bytes = filter->label_id_count * sizeof(*filter->label_ids);
		session->event_filter_label_ids = malloc(bytes);
		if (!session->event_filter_label_ids) {
			err = -ENOMEM;
			goto err_cleanup_transport;
		}
		memcpy(session->event_filter_label_ids, filter->label_ids, bytes);
		session->event_filter_count = filter->label_id_count;
	}

	return 0;

err_cleanup_transport:
	detach_xsk_from_map(session);
	destroy_event_transport(session);
err_cleanup_map:
	close_xsks_map_fd(session);
	return err;
}

int xdp_labeling_events_poll(struct xdp_labeling_event_session *session,
			     int timeout_ms)
{
	int processed;

	if (!session || !session->xsk)
		return -EINVAL;

	processed = event_session_process_rx(session);
	if (processed < 0)
		return processed;
	if (processed > 0)
		return 0;

	if (timeout_ms != 0) {
		struct pollfd pfd = {
			.fd = xsk_socket__fd(session->xsk),
			.events = POLLIN,
		};
		int poll_ret = poll(&pfd, 1, timeout_ms);

		if (poll_ret < 0)
			return -errno;
		if (poll_ret == 0)
			return 0;
		if (pfd.revents & POLLERR)
			return -EIO;
	}

	processed = event_session_process_rx(session);
	if (processed < 0)
		return processed;
	return 0;
}

int xdp_labeling_events_unsubscribe(struct xdp_labeling_event_session *session)
{
	if (!session)
		return -EINVAL;

	detach_xsk_from_map(session);
	destroy_event_transport(session);
	close_xsks_map_fd(session);
	session->event_cb = NULL;
	session->event_user_data = NULL;
	free(session->event_filter_label_ids);
	session->event_filter_label_ids = NULL;
	session->event_filter_count = 0;

	return 0;
}

int xdp_labeling_stats_get(struct xdp_labeling_rule_session *session,
			   __u32 label_id, __u64 *hit_count)
{
	(void)session;
	(void)label_id;
	(void)hit_count;

	return -ENOTSUP;
}
