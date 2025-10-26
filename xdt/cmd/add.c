#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdint.h>

#include "cli_shared.h"
#include "xdt.h"
#include "rule.h"

static const char *action_to_str(__u32 action)
{
	switch (action) {
	case XDP_ABORTED:
		return "aborted";
	case XDP_DROP:
		return "drop";
	case XDP_PASS:
		return "pass";
	case XDP_TX:
		return "tx";
	case XDP_REDIRECT:
		return "redirect";
	default:
		return "unknown";
	}
}

static const struct enum_val add_action_vals[] = {
	{ "pass", XDP_PASS },
	{ "drop", XDP_DROP },
	{ NULL, 0 },
};

const struct addopt defaults_add = {
	.action = XDP_PASS,
	.replace = false,
};

static int parse_ipv4_cidr(const char *cidr, struct lpm_v4_key *key)
{
	char addr_str[INET_ADDRSTRLEN];
	const char *slash;
	char *endptr;
	unsigned long prefixlen;
	struct in_addr addr;
	__u32 addr_host;

	if (!cidr || !key)
		return -EINVAL;

	slash = strchr(cidr, '/');
	if (!slash || slash == cidr || *(slash + 1) == '\0')
		return -EINVAL;

	if ((size_t)(slash - cidr) >= sizeof(addr_str))
		return -EINVAL;

	memcpy(addr_str, cidr, slash - cidr);
	addr_str[slash - cidr] = '\0';

	prefixlen = strtoul(slash + 1, &endptr, 10);
	if (*endptr != '\0' || prefixlen > 32)
		return -EINVAL;

	if (inet_pton(AF_INET, addr_str, &addr) != 1)
		return -EINVAL;

	addr_host = ntohl(addr.s_addr);
	if (prefixlen == 0) {
		addr_host = 0;
	} else {
		__u32 mask = ~((1u << (32 - prefixlen)) - 1);
		addr_host &= mask;
	}

	addr.s_addr = htonl(addr_host);
	key->prefixlen = (__u32)prefixlen;
	key->addr = addr.s_addr;
	return 0;
}

struct prog_option add_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct addopt, iface,
		.short_opt = 'i',
		.metavar = "<ifname>",
		.required = true,
		.help = "Interface whose IPv4 LPM map to update"),
	DEFINE_OPTION("cidr", OPT_STRING_MULTI, struct addopt, cidrs,
		.metavar = "<CIDR>",
		.required = true,
		.help = "IPv4 CIDR prefix (repeatable; e.g. --cidr 192.0.2.0/24)"),
	DEFINE_OPTION("label-id", OPT_STRING, struct addopt, label_id,
		.metavar = "<id>",
		.required = true,
		.help = "Label identifier associated with the rule"),
	DEFINE_OPTION("action", OPT_ENUM, struct addopt, action,
		.metavar = "<action>",
		.typearg = (void *)add_action_vals,
		.help = "Action for matching packets (pass|drop); default pass"),
	DEFINE_OPTION("replace", OPT_BOOL, struct addopt, replace,
		.help = "Replace existing rule instead of failing"),
	END_OPTIONS
};

int do_add(const void *cfg, __unused const char *pin_root_path)
{
	const struct addopt *opt = cfg;
	struct xdt_telemetry_attach_opts lib_opts = {
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = PIN_DIR,
	};
	struct xdt_telemetry_device *device = NULL;
	struct xdt_telemetry_rule_session *rules = NULL;
	struct lpm_v4_key key = {};
	struct xdt_telemetry_rule rule = {};
	unsigned long label_ul;
	char *endptr;
	int ctx_err;
	int err = EXIT_FAILURE;
	size_t i;

	if (!opt || !opt->iface.ifindex || !opt->label_id ||
	    opt->cidrs.count == 0) {
		fprintf(stderr,
			"add: interface, at least one --cidr, and label-id are required\n");
		return EXIT_FAILURE;
	}

	label_ul = strtoul(opt->label_id, &endptr, 10);
	if (*opt->label_id == '\0' || *endptr != '\0' || label_ul > UINT32_MAX) {
		fprintf(stderr, "add: invalid label-id '%s'\n", opt->label_id);
		return EXIT_FAILURE;
	}

	lib_opts.ifname = opt->iface.ifname;
	lib_opts.mode = XDT_TELEMETRY_ATTACH_MODE_SKB;

	ctx_err = xdt_telemetry_device_open(&device, &lib_opts);
	if (ctx_err) {
		fprintf(stderr,
			"add: failed to prepare context for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		return EXIT_FAILURE;
	}

	ctx_err = xdt_telemetry_rule_session_open(device, &rules);
	if (ctx_err) {
		fprintf(stderr,
			"add: failed to open rule session for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		err = EXIT_FAILURE;
		goto out;
	}

	rule.action = opt->action;
	rule.label_id = (__u32)label_ul;
	rule.replace = opt->replace;

	err = EXIT_FAILURE;
	for (i = 0; i < opt->cidrs.count; i++) {
		const char *cidr = opt->cidrs.items[i];
		int rc;

		if (!cidr)
			continue;

		if (parse_ipv4_cidr(cidr, &key)) {
			fprintf(stderr, "add: invalid IPv4 CIDR '%s'\n", cidr);
			goto out;
		}

		rule.key = key;

		rc = xdt_telemetry_rule_upsert(rules, &rule);
		if (rc) {
			if (!opt->replace && rc == -EEXIST) {
				fprintf(stderr,
					"add: rule already exists for %s on %s (use --replace)\n",
					cidr, opt->iface.ifname);
			} else {
				fprintf(stderr, "add: failed to update rule for %s: %s\n",
					cidr, strerror(-rc));
			}
			goto out;
		}

			printf("Added rule on %s: cidr=%s label_id=%u action=%s%s\n",
			       opt->iface.ifname,
			       cidr,
			       (unsigned int)rule.label_id,
			       action_to_str(rule.action),
			       opt->replace ? " (replaced)" : "");
	}

	err = EXIT_SUCCESS;

out:
	xdt_telemetry_rule_session_close(rules);
	xdt_telemetry_device_close(device);

	if (opt) {
		struct string_list *list = (struct string_list *)&opt->cidrs;
		free(list->items);
		list->items = NULL;
		list->count = 0;
		list->capacity = 0;
	}

	return err;
}
