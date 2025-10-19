#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "log_event.h"

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1024);
} deny_v4 SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, struct log_event *event)
{
	struct iphdr *iph = data;
	__u8 ihl;

	if ((void *)(iph + 1) > data_end)
		return 0;

	ihl = iph->ihl;
	if (ihl < 5)
		return 0;

	if ((void *)iph + ihl * 4 > data_end)
		return 0;

	event->src_ipv4 = iph->saddr;
	event->dst_ipv4 = iph->daddr;
	event->l4_proto = iph->protocol;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph = (void *)iph + ihl * 4;

		if ((void *)(tcph + 1) > data_end)
			break;
		event->src_port = tcph->source;
		event->dst_port = tcph->dest;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = (void *)iph + ihl * 4;

		if ((void *)(udph + 1) > data_end)
			break;
		event->src_port = udph->source;
		event->dst_port = udph->dest;
		break;
	}
	case IPPROTO_ICMP:
	default:
		break;
	}

	return 1;
}

static __always_inline void fill_eth(struct ethhdr *eth,
				    struct log_event *event)
{
	__builtin_memcpy(event->src_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(event->dst_mac, eth->h_dest, ETH_ALEN);
	event->ethertype = bpf_ntohs(eth->h_proto);
}

static __always_inline struct log_event *
reserve_event(struct xdp_md *ctx, void *data, void *data_end, struct ethhdr *eth)
{
	struct log_event *event;

	if ((void *)(eth + 1) > data_end)
		return NULL;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return NULL;

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->ifindex = ctx->ingress_ifindex;
	event->pkt_len = data_end - data;

	fill_eth(eth, event);

	return event;
}

static __always_inline int apply_ipv4_policy(struct log_event *event, void *data,
					     void *data_end)
{
	if (!parse_ipv4(data, data_end, event))
		return XDP_PASS;

	if (bpf_map_lookup_elem(&deny_v4, &event->src_ipv4))
		return XDP_DROP;

	return XDP_PASS;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct log_event *event;
	int action = XDP_PASS;

	event = reserve_event(ctx, data, data_end, eth);
	if (!event)
		return XDP_PASS;

	switch (event->ethertype) {
	case ETH_P_IP:
		action = apply_ipv4_policy(event, eth + 1, data_end);
		break;
	default:
		break;
	}

	event->verdict = action == XDP_DROP ? LOG_VERDICT_DROP : LOG_VERDICT_PASS;

	bpf_ringbuf_submit(event, 0);

	return action;
}
