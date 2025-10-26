#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct xdp_label_meta {
	__u32 action;
	__u32 label_id;
};
