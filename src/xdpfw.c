#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "log_event.h"
#include "xdp_firewall.skel.h"
#include "rate_limit.h"

static volatile sig_atomic_t exiting;

struct config {
	const char *ifname;
	bool enable_log;
	__u32 *deny_v4;
	size_t deny_v4_cnt;
	bool rl_enabled;
	__u32 rl_max_burst;
	__u32 rl_window_ms;
	__u32 rl_ban_ms;
};

static int libbpf_log_fn(enum libbpf_print_level level,
			 const char *fmt, va_list args)
{
	(void)level;
	return vfprintf(stderr, fmt, args);
}

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static void print_mac(char *buf, size_t len, const __u8 mac[6])
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_ipv4(char *buf, size_t len, __u32 addr_be)
{
	unsigned char bytes[4];

	bytes[0] = addr_be & 0xff;
	bytes[1] = (addr_be >> 8) & 0xff;
	bytes[2] = (addr_be >> 16) & 0xff;
	bytes[3] = (addr_be >> 24) & 0xff;

	snprintf(buf, len, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);
}

static const char *detect_service(__u8 l4_proto, __u16 src_port, __u16 dst_port)
{
	if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
		if (src_port == 53 || dst_port == 53)
			return "dns";
	}

	if (l4_proto == IPPROTO_TCP) {
		if (src_port == 80 || dst_port == 80)
			return "http";
		if (src_port == 443 || dst_port == 443)
			return "https";
	}

	if (l4_proto == IPPROTO_UDP) {
		if (src_port == 443 || dst_port == 443)
			return "https-quic";
	}

	return "unknown";
}

static const char *label_ethertype(__u16 ethertype)
{
	switch (ethertype) {
	case 0x0800:
		return "IPv4";
	case 0x86DD:
		return "IPv6";
	case 0x0806:
		return "ARP";
	default:
		return "other";
	}
}

static const char *label_drop_reason(__u8 drop_reason)
{
	switch (drop_reason) {
	case LOG_DROP_DENY:
		return "deny";
	case LOG_DROP_RATELIMIT:
		return "ratelimit";
	default:
		return "-";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct log_event *event = data;
	char src_mac[18];
	char dst_mac[18];
	char src_ip[16] = "N/A";
	char dst_ip[16] = "N/A";
	__u16 src_port = ntohs(event->src_port);
	__u16 dst_port = ntohs(event->dst_port);
	const char *service;
	const char *verdict;
	const char *ethertype_label;
	const char *reason_label;

	(void)ctx;

	if (len < sizeof(*event)) {
		fprintf(stderr, "Received truncated event (%zu bytes)\n", len);
		return 0;
	}

	print_mac(src_mac, sizeof(src_mac), event->src_mac);
	print_mac(dst_mac, sizeof(dst_mac), event->dst_mac);

	if (event->src_ipv4)
		print_ipv4(src_ip, sizeof(src_ip), event->src_ipv4);
	if (event->dst_ipv4)
		print_ipv4(dst_ip, sizeof(dst_ip), event->dst_ipv4);

	service = detect_service(event->l4_proto, src_port, dst_port);
	verdict = event->verdict == LOG_VERDICT_DROP ? "drop" : "pass";
	ethertype_label = label_ethertype(event->ethertype);
	reason_label = label_drop_reason(event->drop_reason);

	printf("ts=%llu ifindex=%u len=%u ethertype=0x%04x(%s) src=%s %s:%u dst=%s %s:%u proto=%u svc=%s verdict=%s reason=%s\n",
	       (unsigned long long)event->timestamp_ns,
	       event->ifindex,
	       event->pkt_len,
	       event->ethertype,
	       ethertype_label,
	       src_mac,
	       src_ip,
	       src_port,
	       dst_mac,
	       dst_ip,
	       dst_port,
	       event->l4_proto,
	       service,
	       verdict,
	       reason_label);

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s <ifname> [options]\n"
		"\n"
		"Options:\n"
		"  --deny-ipv4 <IPv4>   Drop packets with matching source IPv4 (repeatable)\n"
		"  --deny-ipv6 <IPv6>   Not supported (prints error and exits)\n"
		"  --ratelimit C/W      Allow at most C packets per W milliseconds (per source IP)\n"
		"  --ratelimit-ban MS   Ban offending IP for MS milliseconds after burst (optional)\n"
		"  --no-log             Disable ring-buffer logging\n"
		"  --help               Show this message\n",
		prog);
}

static int append_deny_ip(struct config *cfg, __u32 addr_be)
{
	__u32 *tmp;

	tmp = realloc(cfg->deny_v4, (cfg->deny_v4_cnt + 1) * sizeof(*tmp));
	if (!tmp)
		return -1;

	cfg->deny_v4 = tmp;
	cfg->deny_v4[cfg->deny_v4_cnt++] = addr_be;
	return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
	int i;

	if (argc < 2)
		return -1;

	if (!strcmp(argv[1], "--help")) {
		usage(argv[0]);
		return 1;
	}

	cfg->ifname = argv[1];
	cfg->enable_log = true;
	cfg->rl_enabled = false;
	cfg->rl_max_burst = 0;
	cfg->rl_window_ms = 0;
	cfg->rl_ban_ms = 0;

	for (i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--deny-ipv4")) {
			struct in_addr addr;

			if (++i >= argc) {
				fprintf(stderr, "--deny-ipv4 requires an IPv4 argument\n");
				return -1;
			}
			if (inet_pton(AF_INET, argv[i], &addr) != 1) {
				fprintf(stderr, "Invalid IPv4 address: %s\n", argv[i]);
				return -1;
			}
			if (append_deny_ip(cfg, addr.s_addr)) {
				perror("append_deny_ip");
				return -1;
			}
		} else if (!strcmp(argv[i], "--deny-ipv6")) {
			fprintf(stderr, "--deny-ipv6 is not supported in this PoC\n");
			return -1;
		} else if (!strcmp(argv[i], "--ratelimit")) {
			char *endptr;
			unsigned long burst;
			unsigned long window_ms;

			if (++i >= argc) {
				fprintf(stderr, "--ratelimit requires <count>/<window_ms>\n");
				return -1;
			}
			burst = strtoul(argv[i], &endptr, 10);
			if (*endptr != '/' || burst == 0 || burst > UINT32_MAX) {
				fprintf(stderr, "Invalid --ratelimit format: %s\n", argv[i]);
				return -1;
			}
			window_ms = strtoul(endptr + 1, &endptr, 10);
			if (*endptr != '\0' || window_ms == 0 || window_ms > UINT32_MAX) {
				fprintf(stderr, "Invalid --ratelimit window: %s\n", argv[i]);
				return -1;
			}
			cfg->rl_enabled = true;
			cfg->rl_max_burst = (unsigned int)burst;
			cfg->rl_window_ms = (unsigned int)window_ms;
		} else if (!strcmp(argv[i], "--ratelimit-ban")) {
			char *endptr;
			unsigned long ban_ms;

			if (++i >= argc) {
				fprintf(stderr, "--ratelimit-ban requires <milliseconds>\n");
				return -1;
			}
			ban_ms = strtoul(argv[i], &endptr, 10);
			if (*endptr != '\0' || ban_ms > UINT32_MAX) {
				fprintf(stderr, "Invalid --ratelimit-ban value: %s\n", argv[i]);
				return -1;
			}
			cfg->rl_enabled = true;
			cfg->rl_ban_ms = (unsigned int)ban_ms;
		} else if (!strcmp(argv[i], "--no-log")) {
			cfg->enable_log = false;
		} else if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 1;
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			return -1;
		}
	}

	if (cfg->rl_enabled && (cfg->rl_max_burst == 0 || cfg->rl_window_ms == 0)) {
		fprintf(stderr, "--ratelimit must be specified when enabling rate limiting\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct config cfg = {0};
	struct ring_buffer *rb = NULL;
	struct xdp_firewall_bpf *obj = NULL;
	bool attached = false;
	int ifindex, err = 0;
	int map_fd;
	size_t i;

	err = parse_args(argc, argv, &cfg);
	if (err) {
		if (err > 0)
			return EXIT_SUCCESS;
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ifindex = if_nametoindex(cfg.ifname);
	if (!ifindex) {
		fprintf(stderr, "Unknown interface: %s\n", cfg.ifname);
		err = EXIT_FAILURE;
		goto out;
	}

	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set signal handlers\n");
		err = EXIT_FAILURE;
		goto out;
	}

	libbpf_set_print(libbpf_log_fn);
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (bump_memlock_rlimit()) {
		perror("bump_memlock_rlimit");
		err = EXIT_FAILURE;
		goto out;
	}

	obj = xdp_firewall_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF object\n");
		err = EXIT_FAILURE;
		goto out;
	}

	map_fd = bpf_map__fd(obj->maps.deny_v4);
	for (i = 0; i < cfg.deny_v4_cnt; i++) {
		__u32 key = cfg.deny_v4[i];
		__u8 value = 1;

		if (bpf_map_update_elem(map_fd, &key, &value, 0)) {
			perror("bpf_map_update_elem");
			err = EXIT_FAILURE;
			goto out;
		}
	}

	{
		struct rate_limit_config rl_cfg = {0};
		__u32 rl_key = 0;
		int rl_fd = bpf_map__fd(obj->maps.rl_config);

		if (cfg.rl_enabled) {
			rl_cfg.max_burst = cfg.rl_max_burst;
			rl_cfg.window_ns = (__u64)cfg.rl_window_ms * 1000000ULL;
			rl_cfg.ban_ns = (__u64)cfg.rl_ban_ms * 1000000ULL;
		}

		if (bpf_map_update_elem(rl_fd, &rl_key, &rl_cfg, 0)) {
			perror("bpf_map_update_elem");
			err = EXIT_FAILURE;
			goto out;
		}
	}

	err = bpf_xdp_attach(ifindex,
			     bpf_program__fd(obj->progs.xdp_firewall),
			     XDP_FLAGS_SKB_MODE,
			     NULL);
	if (err) {
		fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
		goto out;
	}
	attached = true;

	if (cfg.enable_log) {
		rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, NULL, NULL);
		if (!rb) {
			fprintf(stderr, "Failed to create ring buffer\n");
			err = EXIT_FAILURE;
			goto out;
		}

		while (!exiting) {
			int ret = ring_buffer__poll(rb, 100);

			if (ret == -EINTR || ret == -EAGAIN)
				break;
			if (ret < 0) {
				fprintf(stderr, "ring_buffer__poll failed: %s\n", strerror(-ret));
				err = EXIT_FAILURE;
				goto out;
			}
		}
	} else {
		while (!exiting)
			sleep(1);
	}

out:
	if (rb)
		ring_buffer__free(rb);

	if (attached)
		bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

	xdp_firewall_bpf__destroy(obj);
	free(cfg.deny_v4);

	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
