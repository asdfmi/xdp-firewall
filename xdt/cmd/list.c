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

static int rule_entry_cmp(const void *a, const void *b)
{
	const struct xdp_telemetry_rule *ra = a;
	const struct xdp_telemetry_rule *rb = b;

	if (ra->label_id != rb->label_id)
		return (ra->label_id > rb->label_id) -
		       (ra->label_id < rb->label_id);
	if (ra->action != rb->action)
		return (ra->action > rb->action) -
		       (ra->action < rb->action);
	if (ra->key.prefixlen != rb->key.prefixlen)
		return (ra->key.prefixlen > rb->key.prefixlen) -
		       (ra->key.prefixlen < rb->key.prefixlen);
	if (ra->key.addr != rb->key.addr)
		return (ra->key.addr > rb->key.addr) -
		       (ra->key.addr < rb->key.addr);
	return 0;
}

const struct listopt defaults_list = {};

struct prog_option list_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct listopt, iface,
		.short_opt = 'f',
		.metavar = "<ifname>",
		.required = true,
		.help = "Interface whose IPv4 rules map to display"),
	END_OPTIONS
};

int do_list(const void *cfg, __unused const char *pin_root_path)
{
	const struct listopt *opt = cfg;
	struct xdp_telemetry_attach_opts lib_opts = {
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = PIN_DIR,
	};
	struct xdp_telemetry_rule_list list = {};
	struct xdp_telemetry_device *device = NULL;
	struct xdp_telemetry_rule_session *rules = NULL;
	char addr_buf[INET_ADDRSTRLEN];
	int ctx_err;
	int err = EXIT_FAILURE;
	size_t i;

	if (!opt || !opt->iface.ifindex) {
		fprintf(stderr, "list: --interface is required\n");
		return EXIT_FAILURE;
	}

	lib_opts.ifname = opt->iface.ifname;
	lib_opts.mode = XDP_TELEMETRY_ATTACH_MODE_SKB;

	ctx_err = xdp_telemetry_device_open(&device, &lib_opts);
	if (ctx_err) {
		fprintf(stderr,
			"list: failed to prepare context for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		return EXIT_FAILURE;
	}

	ctx_err = xdp_telemetry_rule_session_open(device, &rules);
	if (ctx_err) {
		fprintf(stderr,
			"list: failed to open rule session for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		err = EXIT_FAILURE;
		goto out;
	}

	printf("Rules on %s:\n", opt->iface.ifname);

	err = xdp_telemetry_rule_list(rules, &list);
	if (err) {
		fprintf(stderr, "list: failed to read rules: %s\n",
			strerror(-err));
		goto out;
	}

	if (list.count == 0) {
		printf("  (no entries)\n");
		err = EXIT_SUCCESS;
		goto out;
	}

	qsort(list.rules, list.count, sizeof(*list.rules), rule_entry_cmp);

	{
		__u32 current_label = UINT32_MAX;

		for (i = 0; i < list.count; i++) {
			struct in_addr addr = {
				.s_addr = list.rules[i].key.addr,
			};

			if (list.rules[i].label_id != current_label) {
				current_label = list.rules[i].label_id;
				printf("label_id=%u\n", current_label);
			}

			if (!inet_ntop(AF_INET, &addr, addr_buf,
				       sizeof(addr_buf)))
				snprintf(addr_buf, sizeof(addr_buf), "invalid");

			printf("  action=%s (%u) cidr=%s/%u\n",
			       action_to_str(list.rules[i].action),
			       list.rules[i].action,
			       addr_buf,
			       list.rules[i].key.prefixlen);
		}
	}

	err = EXIT_SUCCESS;

out:
	xdp_telemetry_rule_list_free(&list);
	xdp_telemetry_rule_session_close(rules);
	xdp_telemetry_device_close(device);
	return err;
}
