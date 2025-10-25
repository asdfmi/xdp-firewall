#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "cli_shared.h"
#include "xdp-labeling.h"

const struct detachopt defaults_detach = {};

struct prog_option detach_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct detachopt, iface,
		.short_opt = 'i',
		.metavar = "<ifname>",
		.required = true,
		.help = "Detach from interface <ifname>"),
	END_OPTIONS
};

int do_detach(const void *cfg, __unused const char *pin_root_path)
{
	const struct detachopt *opt = cfg;
	struct xdp_labeling_attach_opts lib_opts = {
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = PIN_DIR,
	};
	struct xdp_labeling_device *device = NULL;
	int err;

	if (!opt || !opt->iface.ifname || !opt->iface.ifindex) {
		fprintf(stderr, "detach: interface is not set\n");
		return EXIT_FAILURE;
	}

	lib_opts.ifname = opt->iface.ifname;
	lib_opts.mode = XDP_LABELING_ATTACH_MODE_SKB;

	err = xdp_labeling_device_open(&device, &lib_opts);
	if (err) {
		fprintf(stderr, "detach: failed to prepare context for %s: %s\n",
			opt->iface.ifname, strerror(-err));
		return EXIT_FAILURE;
	}

	err = xdp_labeling_device_detach(device);
	if (err) {
		if (err == -ENOENT) {
			fprintf(stderr,
				"detach: no XDP program found on %s\n",
				opt->iface.ifname);
		} else {
			fprintf(stderr,
				"detach: failed to detach program on %s: %s\n",
				opt->iface.ifname, strerror(-err));
		}
		xdp_labeling_device_close(device);
		return EXIT_FAILURE;
	}

	xdp_labeling_device_close(device);
	printf("Detached XDP program from %s.\n", opt->iface.ifname);
	return EXIT_SUCCESS;
}
