#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct rate_limit_config {
	__u64 window_ns;
	__u64 ban_ns;
	__u32 max_burst;
	__u32 pad;
};

struct rate_limit_state {
	__u64 last_ns;
	__u64 ban_until_ns;
	__u32 burst;
	__u32 pad;
};

