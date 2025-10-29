#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/if_ether.h>

#include "cli_shared.h"
#include "xdt.h"

const struct logopt defaults_log = {};

struct prog_option log_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct logopt, iface,
		.short_opt = 'i',
		.metavar = "<ifname>",
		.required = true,
		.help = "Interface to read events from"),
	DEFINE_OPTION("follow", OPT_BOOL, struct logopt, follow,
		.short_opt = 'f',
		.help = "Keep streaming until interrupted"),
	END_OPTIONS
};

struct log_print_context {
    __u32 filter_ifindex;
    bool saw_event;
};

static void log_event_cb(struct xdp_telemetry_packet *pkt, void *user_data)
{
	struct log_print_context *state = user_data;
	char src_ip[INET_ADDRSTRLEN] = "-";
	char dst_ip[INET_ADDRSTRLEN] = "-";
	const unsigned char *data;
	const unsigned char *data_end;
	const struct ethhdr *eth;
	const struct iphdr *iph;
	const unsigned char *l4;
	__u8 addr_family = 0;
	__u8 ip_proto = 0;
	__u16 src_port = 0;
	__u16 dst_port = 0;

	if (!pkt || !state)
		return;

	if (state->filter_ifindex && pkt->ifindex != state->filter_ifindex)
		return;

	state->saw_event = true;

    /* Prefer pre-parsed fields if available (ringbuf path), else parse sample */
    if (pkt->addr_family == AF_INET && pkt->src_ipv4 && pkt->dst_ipv4) {
        addr_family = pkt->addr_family;
        ip_proto = pkt->ip_proto;
        src_port = pkt->src_port;
        dst_port = pkt->dst_port;
        if (!inet_ntop(AF_INET, &pkt->src_ipv4, src_ip, sizeof(src_ip)))
            snprintf(src_ip, sizeof(src_ip), "invalid");
        if (!inet_ntop(AF_INET, &pkt->dst_ipv4, dst_ip, sizeof(dst_ip)))
            snprintf(dst_ip, sizeof(dst_ip), "invalid");
    } else {
        data = pkt->data;
        if (!data)
            goto out_print;

        data_end = data + pkt->data_len;
        if (pkt->data_len < sizeof(*eth))
            goto out_print;

        eth = (const struct ethhdr *)data;
        if ((const unsigned char *)(eth + 1) > data_end)
            goto out_print;

        if (ntohs(eth->h_proto) != ETH_P_IP)
            goto out_print;

        iph = (const struct iphdr *)(eth + 1);
        if ((const unsigned char *)(iph + 1) > data_end)
            goto out_print;

        addr_family = AF_INET;
        ip_proto = iph->protocol;
        if (!inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip)))
            snprintf(src_ip, sizeof(src_ip), "invalid");
        if (!inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip)))
            snprintf(dst_ip, sizeof(dst_ip), "invalid");

        l4 = (const unsigned char *)iph + iph->ihl * 4;
        if (l4 > data_end)
            goto out_print;

        if (ip_proto == IPPROTO_TCP) {
            const struct tcphdr *th = (const struct tcphdr *)l4;

            if ((const unsigned char *)(th + 1) > data_end)
                goto out_print;
            src_port = ntohs(th->source);
            dst_port = ntohs(th->dest);
        } else if (ip_proto == IPPROTO_UDP) {
            const struct udphdr *uh = (const struct udphdr *)l4;

            if ((const unsigned char *)(uh + 1) > data_end)
                goto out_print;
            src_port = ntohs(uh->source);
            dst_port = ntohs(uh->dest);
        }
    }

out_print:
	printf("timestamp=%llu ifindex=%u queue=%u len=%zu action=%u label_id=%u "
	       "addr_family=%u ip_proto=%u src_port=%u dst_port=%u src_ipv4=%s dst_ipv4=%s\n",
	       (unsigned long long)pkt->timestamp_ns,
	       pkt->ifindex,
	       pkt->queue_id,
	       pkt->data_len,
	       pkt->meta.action,
	       pkt->meta.label_id,
	       addr_family,
	       ip_proto,
	       src_port,
	       dst_port,
	       src_ip,
	       dst_ip);
	fflush(stdout);

	pkt->forward_to_kernel = true;
}

int do_log(const void *cfg, __unused const char *pin_root_path)
{
	const struct logopt *opt = cfg;
	struct xdp_telemetry_attach_opts lib_opts = {
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = PIN_DIR,
	};
	struct log_print_context cb_ctx = {
		.filter_ifindex = opt->iface.ifindex,
		.saw_event = false,
	};
	struct xdp_telemetry_device *device = NULL;
	struct xdp_telemetry_event_session *events = NULL;
	int ctx_err;
	int err = EXIT_FAILURE;
	int poll_ret;

	if (!opt || !opt->iface.ifindex) {
		fprintf(stderr, "log: --interface is required\n");
		return EXIT_FAILURE;
	}

	lib_opts.ifname = opt->iface.ifname;
	lib_opts.mode = XDP_TELEMETRY_ATTACH_MODE_SKB;

	ctx_err = xdp_telemetry_device_open(&device, &lib_opts);
	if (ctx_err) {
		fprintf(stderr,
			"log: failed to prepare context for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		return EXIT_FAILURE;
	}

	ctx_err = xdp_telemetry_event_session_open(device, &events);
	if (ctx_err) {
		fprintf(stderr,
			"log: failed to open event session for %s: %s\n",
			opt->iface.ifname, strerror(-ctx_err));
		goto out;
	}

	err = xdp_telemetry_events_subscribe(events, NULL, log_event_cb, &cb_ctx);
	if (err) {
		fprintf(stderr,
			"log: failed to subscribe for events on %s: %s\n",
			opt->iface.ifname, strerror(-err));
		goto out;
	}

	if (opt->follow) {
		printf("Streaming events from %s (Ctrl+C to stop)\n",
		       opt->iface.ifname);
		while (1) {
			poll_ret = xdp_telemetry_events_poll(events, 1000);
			if (poll_ret == -EINTR)
				break;
			if (poll_ret < 0) {
				fprintf(stderr, "log: poll error: %s\n",
					strerror(-poll_ret));
				goto out;
			}
		}
		err = EXIT_SUCCESS;
	} else {
		poll_ret = xdp_telemetry_events_poll(events, 100);
		if (poll_ret == -EINTR) {
			err = EXIT_SUCCESS;
		} else if (poll_ret < 0) {
			fprintf(stderr, "log: poll error: %s\n",
				strerror(-poll_ret));
		} else {
			if (!cb_ctx.saw_event)
				printf("No events available on %s.\n",
				       opt->iface.ifname);
			err = EXIT_SUCCESS;
		}
	}

out:
	if (events) {
		xdp_telemetry_events_unsubscribe(events);
		xdp_telemetry_event_session_close(events);
	}
	xdp_telemetry_device_close(device);
	return err;
}
