#pragma once

#include <stdbool.h>

#include <net/if.h>
#include <linux/limits.h>

struct agent_options {
	char ifname[IF_NAMESIZE];
	char pin_root[PATH_MAX];
	char central_host[256];
	unsigned short central_port;
	bool verbose;
};

int agent_options_parse(int argc, char **argv, struct agent_options *opts);
void agent_options_print_usage(const char *prog);
