#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct rule_value {
	__u32 action;
	__u32 label_id;
	__u32 prefixlen;
	__u32 addr;
};

struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};
