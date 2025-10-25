#pragma once

#include <stdbool.h>
#include <stddef.h>

enum option_type {
	OPT_NONE = 0,
	OPT_BOOL,
	OPT_STRING,
	OPT_STRING_MULTI,
	OPT_ENUM,
	OPT_IFNAME,
};

struct string_list {
	const char **items;
	size_t count;
	size_t capacity;
};

struct prog_option {
	enum option_type type;
	size_t cfg_offset;
	size_t cfg_size;
	const char *name;
	char short_opt;
	const char *help;
	const char *metavar;
	void *typearg;
	bool required;
	bool positional;
	int num_set;
};

struct enum_val {
	const char *name;
	unsigned int value;
};

struct flag_val;

struct iface {
	const char *ifname;
	int ifindex;
};

struct prog_command {
	const char *name;
	int (*func)(const void *cfg, const char *pin_root_path);
	struct prog_option *options;
	const void *default_cfg;
	size_t cfg_size;
	const char *doc;
	bool no_cfg;
};

#define textify(x) #x
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

#define DEFINE_OPTION(_name, _type, _cfgtype, _cfgmember, ...)               \
	{                                                                    \
		.type = _type, .cfg_offset = offsetof(_cfgtype, _cfgmember), \
		.cfg_size = sizeof_field(_cfgtype, _cfgmember),             \
		.name = _name, __VA_ARGS__                                  \
	}

#define END_OPTIONS                                                           \
	{                                                                     \
		.type = OPT_NONE                                              \
	}

#define DEFINE_COMMAND_NAME(_name, _func, _doc)                               \
	{                                                                     \
		.name = _name,                                                 \
		.func = do_##_func,                                            \
		.options = _func##_options,                                    \
		.default_cfg = &defaults_##_func,                              \
		.cfg_size = sizeof(defaults_##_func),                          \
		.doc = _doc,                                                   \
	}

#define DEFINE_COMMAND(_name, _doc)                                           \
	DEFINE_COMMAND_NAME(textify(_name), _name, _doc)

#define DEFINE_COMMAND_NODEF(_name, _doc)                                     \
	{                                                                     \
		.name = textify(_name),                                       \
		.func = do_##_name,                                           \
		.options = _name##_options,                                   \
		.cfg_size = 0,                                                \
		.doc = _doc,                                                  \
	}

#define END_COMMANDS                                                          \
	{                                                                     \
		.name = NULL                                                   \
	}

int parse_cmdline_args(int argc, char **argv, struct prog_option *options,
	       void *cfg, size_t cfg_capacity, size_t cfg_struct_size,
	       const char *prog_name, const char *usage_cmd, const char *doc,
	       const void *defaults);

int dispatch_commands(const char *argv0, int argc, char **argv,
		      const struct prog_command *cmds, size_t cfg_size,
		      const char *prog_name);

void usage(const char *prog_name, const char *doc,
	   const struct prog_option *options, bool full);
