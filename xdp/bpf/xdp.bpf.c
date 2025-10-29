#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include "rule.h"
#include "label_meta.h"
#include "telemetry_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct rule_value);
	__uint(max_entries, 1024);
} rules_v4 SEC(".maps");

/* Ring buffer for telemetry events (mirror mode) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 << 20); /* 8 MiB */
} events SEC(".maps");

SEC("xdp")
int xdp_labeler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 action = XDP_PASS;
    __u32 label_id = 0;
    __u32 pkt_len0 = 0;

    if (data < data_end)
        pkt_len0 = (__u32)((long)data_end - (long)data);

    /* Rule lookup omitted in ringbuf-mirror mode; always PASS traffic. */

    /* Mirror packet metadata and a small sample into ringbuf (no redirect). */
    {
        __u32 qid = ctx->rx_queue_index;
        __u32 copied = 0;
        struct xdt_ringbuf_event *ev;

        ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (ev) {
            __u32 i;
            __u8 addr_family = 0;
            __u8 ip_proto = 0;
            __u16 src_port = 0;
            __u16 dst_port = 0;
            __u32 src_ipv4 = 0;
            __u32 dst_ipv4 = 0;
            ev->version = XDT_RINGBUF_VERSION;
            ev->meta.action = action;
            ev->meta.label_id = label_id;
            ev->ts_ns = bpf_ktime_get_ns();
            ev->queue_id = qid;

            /* Copy up to SAMPLE_SIZE bytes safely */
#pragma unroll
            for (i = 0; i < XDT_RINGBUF_SAMPLE_SIZE; i++) {
                if ((void *)((char *)data + i + 1) > data_end)
                    break;
                ev->sample[i] = *(__u8 *)((char *)data + i);
                copied++;
            }
            ev->data_len = copied;

            /* Minimal L3/L4 parse for IPv4 */
            if ((void *)(eth + 1) <= data_end) {
                __u16 h_proto = bpf_ntohs(eth->h_proto);
                if (h_proto == ETH_P_IP) {
                    struct iphdr *iph = (void *)(eth + 1);
                    if ((void *)(iph + 1) <= data_end) {
                        addr_family = 2; /* AF_INET */
                        ip_proto = iph->protocol;
                        src_ipv4 = iph->saddr;
                        dst_ipv4 = iph->daddr;
                        /* L4 ports */
                        {
                            unsigned char *l4 = (unsigned char *)iph + iph->ihl * 4;
                            if ((void *)l4 <= data_end) {
                                if (ip_proto == IPPROTO_TCP) {
                                    struct tcphdr *th = (struct tcphdr *)l4;
                                    if ((void *)(th + 1) <= data_end) {
                                        src_port = bpf_ntohs(th->source);
                                        dst_port = bpf_ntohs(th->dest);
                                    }
                                } else if (ip_proto == IPPROTO_UDP) {
                                    struct udphdr *uh = (struct udphdr *)l4;
                                    if ((void *)(uh + 1) <= data_end) {
                                        src_port = bpf_ntohs(uh->source);
                                        dst_port = bpf_ntohs(uh->dest);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            ev->addr_family = addr_family;
            ev->ip_proto = ip_proto;
            ev->src_port = src_port;
            ev->dst_port = dst_port;
            ev->src_ipv4 = src_ipv4;
            ev->dst_ipv4 = dst_ipv4;
            bpf_ringbuf_submit(ev, 0);
        }
    }

    return action;
}

char LICENSE[] SEC("license") = "GPL";
