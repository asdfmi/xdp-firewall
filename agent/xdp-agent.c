#define _GNU_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>

#include "options.h"
#include "xdp_labeling.h"

#define AGENT_POLL_TIMEOUT_MS 1000

static volatile sig_atomic_t stop_agent;

struct send_context {
	const struct agent_options *opts;
};

static void handle_signal(int signo)
{
	(void)signo;
	stop_agent = 1;
}

static void print_packet_stub(const struct xdp_label_packet *pkt,
			      const struct send_context *ctx)
{
	char src_ip[INET_ADDRSTRLEN] = "-";
	char dst_ip[INET_ADDRSTRLEN] = "-";
	const unsigned char *data = pkt->data;
	const unsigned char *data_end = data + pkt->data_len;
	const struct ethhdr *eth;
	const struct iphdr *iph;
	const char *host = ctx->opts->central_host;
	unsigned short port = ctx->opts->central_port;

	if (!data || pkt->data_len < sizeof(*eth))
		goto out_print;

	eth = (const struct ethhdr *)data;
	if ((const unsigned char *)(eth + 1) > data_end ||
	    ntohs(eth->h_proto) != ETH_P_IP)
		goto out_print;

	iph = (const struct iphdr *)(eth + 1);
	if ((const unsigned char *)(iph + 1) > data_end)
		goto out_print;

	if (!inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip)))
		strncpy(src_ip, "invalid", sizeof(src_ip));
	if (!inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip)))
		strncpy(dst_ip, "invalid", sizeof(dst_ip));

out_print:
	printf("[central %s:%u] ts=%llu ifindex=%u queue=%u action=%u label=%u len=%zu src=%s dst=%s\n",
	       host, port,
	       (unsigned long long)pkt->timestamp_ns,
	       pkt->ifindex,
	       pkt->queue_id,
	       pkt->meta.action,
	       pkt->meta.label_id,
	       pkt->data_len,
	       src_ip,
	       dst_ip);
	fflush(stdout);
}

static void event_dispatch_cb(const struct xdp_label_packet *pkt, void *user_data)
{
	struct send_context *ctx = user_data;

	if (!pkt || !ctx)
		return;

	print_packet_stub(pkt, ctx);
}

static int run_agent(const struct agent_options *opts)
{
	struct xdp_labeling_device *device = NULL;
	struct xdp_labeling_event_session *events = NULL;
	struct send_context send_ctx = {
		.opts = opts,
	};
	struct xdp_labeling_attach_opts attach_opts = {
		.ifname = opts->ifname,
		.mode = XDP_LABELING_ATTACH_MODE_SKB,
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = opts->pin_root,
	};
	int err;

	err = xdp_labeling_device_open(&device, &attach_opts);
	if (err) {
		fprintf(stderr, "agent: failed to prepare device context: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	err = xdp_labeling_event_session_open(device, &events);
	if (err) {
		fprintf(stderr, "agent: failed to open event session: %s\n",
			strerror(-err));
		goto out;
	}

	err = xdp_labeling_events_subscribe(events, NULL,
					    event_dispatch_cb, &send_ctx);
	if (err) {
		fprintf(stderr, "agent: failed to subscribe to events: %s\n",
			strerror(-err));
		goto out;
	}

	while (!stop_agent) {
		err = xdp_labeling_events_poll(events, AGENT_POLL_TIMEOUT_MS);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "agent: poll error: %s\n",
				strerror(-err));
			break;
		}
	}

	xdp_labeling_events_unsubscribe(events);

out:
	if (events)
		xdp_labeling_event_session_close(events);
	xdp_labeling_device_close(device);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct agent_options opts;
	int ret;

	ret = agent_options_parse(argc, argv, &opts);
	if (ret == 1)
		return EXIT_SUCCESS;
	if (ret)
		return EXIT_FAILURE;

	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		perror("signal");
		return EXIT_FAILURE;
	}

	return run_agent(&opts);
}
