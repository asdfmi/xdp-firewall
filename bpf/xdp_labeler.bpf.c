#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include "rule.h"
#include "label_meta.h"

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, struct rule_value);
	__uint(max_entries, 1024);
} rules_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_labeler(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u32 action = XDP_PASS;
	__u32 label_id = 0;

	if ((void *)(eth + 1) <= data_end) {
		__u16 h_proto = bpf_ntohs(eth->h_proto);

		if (h_proto == ETH_P_IP) {
			struct iphdr *iph = (void *)(eth + 1);

			if ((void *)(iph + 1) <= data_end) {
				struct lpm_v4_key key = {
					.prefixlen = 32,
					.addr = iph->daddr,
				};
				struct rule_value *rule;

				rule = bpf_map_lookup_elem(&rules_v4, &key);
				if (!rule && iph->saddr) {
					key.addr = iph->saddr;
					rule = bpf_map_lookup_elem(&rules_v4, &key);
				}

				if (rule) {
					switch (rule->action) {
					case XDP_ABORTED:
					case XDP_DROP:
					case XDP_PASS:
					case XDP_TX:
					case XDP_REDIRECT:
						action = rule->action;
						break;
					default:
						action = XDP_PASS;
						break;
					}
					label_id = rule->label_id;
				}
			}
		}
	}

	{
		__u32 qid = ctx->rx_queue_index;
		void *xsks = bpf_map_lookup_elem(&xsks_map, &qid);

		if (xsks) {
			if (!bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_label_meta))) {
				void *meta_ptr = (void *)(long)ctx->data_meta;
				void *data_ptr = (void *)(long)ctx->data;

				if (meta_ptr && meta_ptr <= data_ptr) {
					struct xdp_label_meta *meta = meta_ptr;

					if ((void *)(meta + 1) <= data_ptr) {
						meta->action = action;
						meta->label_id = label_id;
						return bpf_redirect_map(&xsks_map, qid, 0);
					}
				}

				bpf_xdp_adjust_meta(ctx, sizeof(struct xdp_label_meta));
			}
		}
	}

	return action;
}

char LICENSE[] SEC("license") = "GPL";
