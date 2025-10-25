#define _GNU_SOURCE

#include "options.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xdp_labeling.h"

static void set_defaults(struct agent_options *opts)
{
	memset(opts, 0, sizeof(*opts));
	strncpy(opts->central_host, "127.0.0.1", sizeof(opts->central_host) - 1);
	opts->central_port = 50051;
	strncpy(opts->pin_root, XDP_LABELING_PIN_ROOT_DEFAULT,
		sizeof(opts->pin_root) - 1);
	opts->verbose = false;
}

static int parse_endpoint(const char *arg, struct agent_options *opts)
{
	char buf[512];
	char *colon;
	long port;
	char *endptr;

	if (!arg || !opts)
		return -EINVAL;

	if (strlen(arg) >= sizeof(buf))
		return -ENAMETOOLONG;

	strcpy(buf, arg);
	colon = strrchr(buf, ':');
	if (!colon)
		return -EINVAL;

	*colon = '\0';
	port = strtol(colon + 1, &endptr, 10);
	if (*endptr != '\0' || port <= 0 || port > 65535)
		return -EINVAL;

	strncpy(opts->central_host, buf, sizeof(opts->central_host) - 1);
	opts->central_host[sizeof(opts->central_host) - 1] = '\0';
	opts->central_port = (unsigned short)port;
	return 0;
}

void agent_options_print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\n"
		"Required:\n"
		"  -i, --interface <ifname>   Interface to attach to\n"
		"\n"
		"Optional:\n"
		"  -c, --central <host:port>  Central endpoint (default 127.0.0.1:50051)\n"
		"  -p, --pin-root <path>      bpffs pin root (default %s)\n"
		"  -v, --verbose              Enable verbose logging\n"
		"  -h, --help                 Show this help\n",
		prog, XDP_LABELING_PIN_ROOT_DEFAULT);
}

int agent_options_parse(int argc, char **argv, struct agent_options *opts)
{
	static const struct option long_opts[] = {
		{"interface", required_argument, NULL, 'i'},
		{"central", required_argument, NULL, 'c'},
		{"pin-root", required_argument, NULL, 'p'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};
	int c;
	int ret = 0;

	if (!opts)
		return -EINVAL;

	set_defaults(opts);

	while ((c = getopt_long(argc, argv, "i:c:p:vh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			strncpy(opts->ifname, optarg, sizeof(opts->ifname) - 1);
			opts->ifname[sizeof(opts->ifname) - 1] = '\0';
			break;
		case 'c':
			ret = parse_endpoint(optarg, opts);
			if (ret) {
				fprintf(stderr,
					"agent: invalid --central value '%s'\n",
					optarg);
				return ret;
			}
			break;
		case 'p':
			strncpy(opts->pin_root, optarg, sizeof(opts->pin_root) - 1);
			opts->pin_root[sizeof(opts->pin_root) - 1] = '\0';
			break;
		case 'v':
			opts->verbose = true;
			break;
		case 'h':
			agent_options_print_usage(argv[0]);
			return 1;
		default:
			agent_options_print_usage(argv[0]);
			return -EINVAL;
		}
	}

	if (!opts->ifname[0]) {
		fprintf(stderr, "agent: --interface is required\n");
		agent_options_print_usage(argv[0]);
		return -EINVAL;
	}

	return 0;
}
