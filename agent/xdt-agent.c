#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "options.h"
#include "telemetry_client.h"
#include "xdt_telemetry.h"

#define AGENT_POLL_TIMEOUT_MS 1000

static volatile sig_atomic_t stop_agent;

struct send_context {
    const struct agent_options *opts;
    struct telemetry_client *client;
    bool verbose;
    bool warned_client;
};

static void handle_signal(int signo)
{
	(void)signo;
	stop_agent = 1;
}

static void print_packet_stub(const struct telemetry_packet *packet,
			      const struct send_context *ctx)
{
	const char *host = ctx->opts->central_host;
	unsigned short port = ctx->opts->central_port;
	const char *src_ip = packet->src_ip[0] ? packet->src_ip : "-";
	const char *dst_ip = packet->dst_ip[0] ? packet->dst_ip : "-";

	printf("[central %s:%u] ts=%llu ifindex=%u queue=%u action=%u label=%u len=%u src=%s dst=%s src_port=%u dst_port=%u\n",
	       host, port,
	       (unsigned long long)packet->timestamp_ns,
	       packet->ifindex,
	       packet->queue_id,
	       packet->action,
	       packet->label_id,
	       packet->data_len,
	       src_ip,
	       dst_ip,
	       packet->src_port,
	       packet->dst_port);
	fflush(stdout);
}

static void prepare_telemetry_packet(const struct xdt_telemetry_packet *pkt,
				     struct telemetry_packet *out)
{
	const unsigned char *data = pkt->data;
	const unsigned char *data_end = data ? data + pkt->data_len : NULL;
	const struct ethhdr *eth;

	memset(out, 0, sizeof(*out));

	out->timestamp_ns = pkt->timestamp_ns;
	out->ifindex = pkt->ifindex;
	out->queue_id = pkt->queue_id;
	out->action = pkt->meta.action;
	out->label_id = pkt->meta.label_id;
	out->data_len = pkt->data_len;

	if (!data || pkt->data_len < sizeof(*eth))
		return;

	out->payload_len = pkt->data_len < TELEMETRY_MAX_PAYLOAD ?
		pkt->data_len : TELEMETRY_MAX_PAYLOAD;
	memcpy(out->payload, data, out->payload_len);

	eth = (const struct ethhdr *)data;
	if ((const unsigned char *)(eth + 1) > data_end)
		return;

	if (ntohs(eth->h_proto) == ETH_P_IP) {
		const struct iphdr *iph = (const struct iphdr *)(eth + 1);
		const unsigned char *l4;

		if ((const unsigned char *)(iph + 1) > data_end)
			return;

		if (!inet_ntop(AF_INET, &iph->saddr, out->src_ip,
			       sizeof(out->src_ip)))
			snprintf(out->src_ip, sizeof(out->src_ip), "invalid");
		if (!inet_ntop(AF_INET, &iph->daddr, out->dst_ip,
			       sizeof(out->dst_ip)))
			snprintf(out->dst_ip, sizeof(out->dst_ip), "invalid");

		l4 = (const unsigned char *)iph + iph->ihl * 4;
		if (l4 > data_end)
			return;

		if (iph->protocol == IPPROTO_TCP) {
			const struct tcphdr *th = (const struct tcphdr *)l4;

			if ((const unsigned char *)(th + 1) > data_end)
				return;

			out->src_port = ntohs(th->source);
			out->dst_port = ntohs(th->dest);
		} else if (iph->protocol == IPPROTO_UDP) {
			const struct udphdr *uh = (const struct udphdr *)l4;

			if ((const unsigned char *)(uh + 1) > data_end)
				return;

			out->src_port = ntohs(uh->source);
			out->dst_port = ntohs(uh->dest);
		}
	}
}

static void event_dispatch_cb(struct xdt_telemetry_packet *pkt, void *user_data)
{
	struct send_context *ctx = user_data;
	struct telemetry_packet packet;
	int ret;

	if (!pkt || !ctx)
		return;

	prepare_telemetry_packet(pkt, &packet);
	strncpy(packet.agent_id, ctx->opts->agent_id,
		sizeof(packet.agent_id) - 1);
	packet.agent_id[sizeof(packet.agent_id) - 1] = '\0';

    if (ctx->client) {
        ret = telemetry_client_send(ctx->client, &packet);
        if (ret == 0) {
            ctx->warned_client = false;
        } else if (!ctx->warned_client) {
            fprintf(stderr,
                "agent: failed to send telemetry event to central %s:%u\n",
                ctx->opts->central_host,
                ctx->opts->central_port);
            ctx->warned_client = true;
        }
    }

	if (ctx->verbose)
		print_packet_stub(&packet, ctx);

	pkt->forward_to_kernel = true;
}

static int run_agent(const struct agent_options *opts)
{
	struct xdt_telemetry_device *device = NULL;
	struct xdt_telemetry_event_session *events = NULL;
	struct send_context send_ctx = {
		.opts = opts,
		.client = NULL,
		.verbose = opts->verbose,
		.warned_client = false,
	};
	struct xdt_telemetry_attach_opts attach_opts = {
		.ifname = opts->ifname,
		.mode = XDT_TELEMETRY_ATTACH_MODE_SKB,
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = opts->pin_root,
	};
    int err;

    if (telemetry_client_create(&send_ctx.client, opts->central_host,
                opts->central_port) != 0) {
        fprintf(stderr,
            "agent: failed to connect telemetry client to %s:%u\n",
            opts->central_host, opts->central_port);
    }

	err = xdt_telemetry_device_open(&device, &attach_opts);
	if (err) {
		fprintf(stderr, "agent: failed to prepare device context: %s\n",
			strerror(-err));
		return EXIT_FAILURE;
	}

	err = xdt_telemetry_event_session_open(device, &events);
	if (err) {
		fprintf(stderr, "agent: failed to open event session: %s\n",
			strerror(-err));
		goto out;
	}

	err = xdt_telemetry_events_subscribe(events, NULL,
					    event_dispatch_cb, &send_ctx);
	if (err) {
		fprintf(stderr, "agent: failed to subscribe to events: %s\n",
			strerror(-err));
		goto out;
	}

	while (!stop_agent) {
		err = xdt_telemetry_events_poll(events, AGENT_POLL_TIMEOUT_MS);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "agent: poll error: %s\n",
				strerror(-err));
			break;
		}
	}

	xdt_telemetry_events_unsubscribe(events);

out:
	if (events)
		xdt_telemetry_event_session_close(events);
	xdt_telemetry_device_close(device);
	telemetry_client_destroy(send_ctx.client);
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
