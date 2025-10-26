#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#include "cli_shared.h"
#include "xdt.h"

static const struct enum_val attach_modes[] = {
	{ "skb", XDT_TELEMETRY_ATTACH_MODE_SKB },
	{ "native", XDT_TELEMETRY_ATTACH_MODE_NATIVE },
	{ NULL, 0 },
};

const struct attachopt defaults_attach = {
	.mode = XDT_TELEMETRY_ATTACH_MODE_SKB,
	.object_path = DEFAULT_BPF_OBJECT,
};

struct prog_option attach_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct attachopt, mode,
		.short_opt = 'm',
		.metavar = "<mode>",
		.typearg = (void *)attach_modes,
		.help = "Attach mode (skb|native); default skb"),
	DEFINE_OPTION("object", OPT_STRING, struct attachopt, object_path,
		.metavar = "<file>",
		.help = "Path to XDP object file"),
	DEFINE_OPTION("interface", OPT_IFNAME, struct attachopt, iface,
		.short_opt = 'i',
		.metavar = "<ifname>",
		.required = true,
		.help = "Attach to interface <ifname>"),
	END_OPTIONS
};

int do_attach(const void *cfg, __unused const char *pin_root_path)
{
	const struct attachopt *opt = cfg;
	struct xdt_telemetry_attach_opts lib_opts = {
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = PIN_DIR,
	};
	struct xdt_telemetry_device *device = NULL;
	int err;

	if (!opt || !opt->iface.ifname || !opt->iface.ifindex) {
		fprintf(stderr, "attach: interface is not set\n");
		return EXIT_FAILURE;
	}

	lib_opts.ifname = opt->iface.ifname;
	lib_opts.prog_path = opt->object_path && opt->object_path[0]
				   ? opt->object_path
				   : DEFAULT_BPF_OBJECT;
	lib_opts.mode = opt->mode;

	err = xdt_telemetry_device_open(&device, &lib_opts);
	if (err) {
		fprintf(stderr, "attach: failed to prepare context for %s: %s\n",
			opt->iface.ifname, strerror(-err));
		return EXIT_FAILURE;
	}

	err = xdt_telemetry_device_attach(device);
	if (err) {
		fprintf(stderr, "attach: failed to attach program on %s: %s\n",
			opt->iface.ifname, strerror(-err));
		xdt_telemetry_device_close(device);
		return EXIT_FAILURE;
	}

	xdt_telemetry_device_close(device);
printf("Attached XDP Telemetry program to %s.\n", opt->iface.ifname);
	return EXIT_SUCCESS;
}
