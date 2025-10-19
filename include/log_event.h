#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define LOG_EVENT_VERSION 1

enum log_l4_proto {
	LOG_L4_NONE = 0,
	LOG_L4_TCP = 6,
	LOG_L4_UDP = 17,
	LOG_L4_ICMP = 1,
};

enum log_verdict {
	LOG_VERDICT_PASS = 0,
	LOG_VERDICT_DROP = 1,
};

enum log_drop_reason {
	LOG_DROP_NONE = 0,
	LOG_DROP_DENY = 1,
	LOG_DROP_RATELIMIT = 2,
};

struct log_event {
	__u64 timestamp_ns;
	__u32 ifindex;
	__u32 pkt_len;

	__u8  src_mac[6];
	__u8  dst_mac[6];
	__u16 ethertype;

	__u32 src_ipv4;
	__u32 dst_ipv4;

	__u16 src_port;
	__u16 dst_port;
	__u8  l4_proto;
	__u8  verdict;
	__u8  drop_reason;
	__u8  pad[1];
};
