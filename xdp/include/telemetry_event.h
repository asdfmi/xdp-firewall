#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#include "label_meta.h"

/* Versioned event structure for ringbuf streaming */
#define XDT_RINGBUF_VERSION 1
#define XDT_RINGBUF_SAMPLE_SIZE 128

struct xdt_ringbuf_event {
    __u32 version;        /* XDT_RINGBUF_VERSION */
    struct xdp_label_meta meta;
    __u64 ts_ns;          /* bpf_ktime_get_ns() */
    __u32 queue_id;       /* rx queue id */
    __u32 data_len;       /* copied sample length (<= SAMPLE_SIZE) */

    /* Pre-parsed header metadata (optional; 0 if unknown) */
    __u8  addr_family;    /* AF_INET(2) or 0 */
    __u8  ip_proto;       /* IPPROTO_* or 0 */
    __u16 src_port;       /* TCP/UDP src, host order */
    __u16 dst_port;       /* TCP/UDP dst, host order */
    __u32 src_ipv4;       /* IPv4 saddr (network order) */
    __u32 dst_ipv4;       /* IPv4 daddr (network order) */

    __u8  sample[XDT_RINGBUF_SAMPLE_SIZE]; /* first N bytes of frame */
};
