#pragma once

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include "xdp_labeling.h"
#include "params.h"

struct helpopt {
	const char *command;
};

extern const struct helpopt defaults_help;
extern struct prog_option help_options[];
int do_help(const void *cfg, const char *pin_root_path);

struct attachopt {
	struct iface iface;
	enum xdp_labeling_attach_mode mode;
	const char *object_path;
};

extern const struct attachopt defaults_attach;
extern struct prog_option attach_options[];
int do_attach(const void *cfg, const char *pin_root_path);

struct detachopt {
	struct iface iface;
};

extern const struct detachopt defaults_detach;
extern struct prog_option detach_options[];
int do_detach(const void *cfg, const char *pin_root_path);

struct logopt {
	struct iface iface;
	bool follow;
};

extern const struct logopt defaults_log;
extern struct prog_option log_options[];
int do_log(const void *cfg, const char *pin_root_path);

struct addopt {
	struct iface iface;
	struct string_list cidrs;
	const char *label_id;
	__u32 action;
	bool replace;
};

extern const struct addopt defaults_add;
extern struct prog_option add_options[];
int do_add(const void *cfg, const char *pin_root_path);

struct listopt {
	struct iface iface;
};

extern const struct listopt defaults_list;
extern struct prog_option list_options[];
int do_list(const void *cfg, const char *pin_root_path);

extern const struct prog_command cmds[];
