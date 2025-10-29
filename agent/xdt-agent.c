#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/limits.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <sched.h>
#include <fcntl.h>

#include "params.h"
#include "telemetry_client.h"
#include "xdp_telemetry.h"
#include <limits.h>

#define AGENT_POLL_TIMEOUT_MS 1000
#define AGENT_DEFAULT_CENTRAL "127.0.0.1:50051"

struct agent_options {
	char ifname[IF_NAMESIZE];
	char pin_root[PATH_MAX];
	char central_host[256];
	unsigned short central_port;
	char agent_id[64];
	int netns_pid; /* 0 if not set */
	bool verbose;
};

struct agent_cli_config {
	struct iface iface;
	const char *central;
	const char *pin_root;
	const char *agent_id;
	const char *netns_pid; /* string value parsed into opts */
	bool verbose;
};

static struct prog_option agent_prog_options[] = {
	DEFINE_OPTION("interface", OPT_IFNAME, struct agent_cli_config, iface,
		.short_opt = 'i',
		.metavar = "<ifname>",
		.required = true,
		.help = "Interface to attach to"),
	DEFINE_OPTION("central", OPT_STRING, struct agent_cli_config, central,
		.short_opt = 'c',
		.metavar = "<host:port>",
		.help = "Central endpoint (default " AGENT_DEFAULT_CENTRAL ")"),
	DEFINE_OPTION("pin-root", OPT_STRING, struct agent_cli_config, pin_root,
		.short_opt = 'p',
		.metavar = "<path>",
		.help = "bpffs pin root (default " XDP_TELEMETRY_PIN_ROOT_DEFAULT ")"),
	DEFINE_OPTION("agent-id", OPT_STRING, struct agent_cli_config, agent_id,
		.short_opt = 'a',
		.metavar = "<id>",
		.help = "Identifier reported to central"),
	DEFINE_OPTION("netns-pid", OPT_STRING, struct agent_cli_config, netns_pid,
		.short_opt = 'n',
		.metavar = "<pid>",
		.help = "Temporarily enter target netns by PID to attach (e.g. service pod eth0)"),
	DEFINE_OPTION("verbose", OPT_BOOL, struct agent_cli_config, verbose,
		.short_opt = 'v',
		.help = "Enable verbose logging"),
	END_OPTIONS
};

static int parse_central_endpoint(const char *arg, struct agent_options *opts)
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

static int agent_options_parse(int argc, char **argv, struct agent_options *opts)
{
	static char hostname_buf[sizeof(((struct agent_options *)0)->agent_id)];
	struct agent_cli_config cfg;
	struct agent_cli_config defaults = {
		.central = AGENT_DEFAULT_CENTRAL,
		.pin_root = XDP_TELEMETRY_PIN_ROOT_DEFAULT,
		.agent_id = NULL,
		.verbose = false,
	};
	const char *prog = (argc > 0 && argv && argv[0]) ? argv[0] : "xdt-agent";
	int ret;

	if (!opts)
		return -EINVAL;

	memset(opts, 0, sizeof(*opts));
	memset(&cfg, 0, sizeof(cfg));

	if (gethostname(hostname_buf, sizeof(hostname_buf) - 1) == 0) {
		hostname_buf[sizeof(hostname_buf) - 1] = '\0';
		defaults.agent_id = hostname_buf;
	}

	ret = parse_cmdline_args(argc, argv, agent_prog_options, &cfg,
				 sizeof(cfg), sizeof(cfg), "xdt-agent", prog,
				 "XDP telemetry agent options", &defaults);
	if (ret)
		return ret;

	if (!cfg.central)
		cfg.central = AGENT_DEFAULT_CENTRAL;

	ret = parse_central_endpoint(cfg.central, opts);
	if (ret) {
		fprintf(stderr, "agent: invalid --central value '%s'\n",
			cfg.central);
		return ret;
	}

	if (!cfg.pin_root)
		cfg.pin_root = XDP_TELEMETRY_PIN_ROOT_DEFAULT;
	strncpy(opts->pin_root, cfg.pin_root, sizeof(opts->pin_root) - 1);
	opts->pin_root[sizeof(opts->pin_root) - 1] = '\0';

	if (cfg.agent_id && cfg.agent_id[0]) {
		strncpy(opts->agent_id, cfg.agent_id,
			sizeof(opts->agent_id) - 1);
		opts->agent_id[sizeof(opts->agent_id) - 1] = '\0';
	} else {
		opts->agent_id[0] = '\0';
	}

	opts->verbose = cfg.verbose;

    /* Parse optional netns-pid */
    if (cfg.netns_pid && cfg.netns_pid[0]) {
        char *end = NULL;
        long v = strtol(cfg.netns_pid, &end, 10);
        if (!end || *end != '\0' || v <= 0 || v > INT_MAX) {
            fprintf(stderr, "agent: invalid --netns-pid value '%s'\n", cfg.netns_pid);
            return -EINVAL;
        }
        opts->netns_pid = (int)v;
    } else {
        opts->netns_pid = 0;
    }

    if (!cfg.iface.ifname) {
        const char *env_if = getenv("INTERFACE_NAME");
        if (!env_if || !env_if[0]) {
            fprintf(stderr, "agent: --interface is required (or set INTERFACE_NAME)\n");
            return -EINVAL;
        }
        strncpy(opts->ifname, env_if, sizeof(opts->ifname) - 1);
        opts->ifname[sizeof(opts->ifname) - 1] = '\0';
    } else {
        /* Support literal "$(INTERFACE_NAME)" by falling back to env */
        if (strcmp(cfg.iface.ifname, "$(INTERFACE_NAME)") == 0) {
            const char *env_if = getenv("INTERFACE_NAME");
            if (env_if && env_if[0])
                strncpy(opts->ifname, env_if, sizeof(opts->ifname) - 1);
            else
                strncpy(opts->ifname, cfg.iface.ifname, sizeof(opts->ifname) - 1);
        } else {
            strncpy(opts->ifname, cfg.iface.ifname, sizeof(opts->ifname) - 1);
        }
        opts->ifname[sizeof(opts->ifname) - 1] = '\0';
    }

	return 0;
}

static volatile sig_atomic_t stop_agent;

struct send_context {
    const struct agent_options *opts;
    struct telemetry_client *client;
    bool verbose;
    bool warned_client;
    long long mono_to_real_ns;
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

static void prepare_telemetry_packet(const struct xdp_telemetry_packet *pkt,
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

    /* Prefer pre-parsed fields from ringbuf if present */
    if (pkt->addr_family == AF_INET && pkt->src_ipv4 && pkt->dst_ipv4) {
        if (!inet_ntop(AF_INET, &pkt->src_ipv4, out->src_ip,
                       sizeof(out->src_ip)))
            snprintf(out->src_ip, sizeof(out->src_ip), "invalid");
        if (!inet_ntop(AF_INET, &pkt->dst_ipv4, out->dst_ip,
                       sizeof(out->dst_ip)))
            snprintf(out->dst_ip, sizeof(out->dst_ip), "invalid");
        out->src_port = pkt->src_port;
        out->dst_port = pkt->dst_port;
        /* payload sample */
        if (data && pkt->data_len > 0) {
            out->payload_len = pkt->data_len < TELEMETRY_MAX_PAYLOAD ?
                               pkt->data_len : TELEMETRY_MAX_PAYLOAD;
            memcpy(out->payload, data, out->payload_len);
        }
        return;
    }

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

static void event_dispatch_cb(struct xdp_telemetry_packet *pkt, void *user_data)
{
    struct send_context *ctx = user_data;
    struct telemetry_packet packet;
    int ret;

	if (!pkt || !ctx)
		return;

    prepare_telemetry_packet(pkt, &packet);
    /* Convert monotonic ns (from BPF/ktime) to realtime ns for UI bucketing */
    if (ctx && ctx->mono_to_real_ns) {
        unsigned long long adj = (unsigned long long)((long long)packet.timestamp_ns + ctx->mono_to_real_ns);
        packet.timestamp_ns = adj;
    }
	strncpy(packet.agent_id, ctx->opts->agent_id,
		sizeof(packet.agent_id) - 1);
	packet.agent_id[sizeof(packet.agent_id) - 1] = '\0';

    /* Ensure client is connected; attempt lazy connect on first event */
    if (!ctx->client) {
        if (telemetry_client_create(&ctx->client,
                    ctx->opts->central_host,
                    ctx->opts->central_port) != 0) {
            if (!ctx->warned_client) {
                fprintf(stderr,
                    "agent: failed to connect telemetry client to %s:%u\n",
                    ctx->opts->central_host,
                    ctx->opts->central_port);
                ctx->warned_client = true;
            }
        } else {
            ctx->warned_client = false;
        }
    }

    if (ctx->client) {
        ret = telemetry_client_send(ctx->client, &packet);
        if (ret != 0) {
            /* Reconnect once on failure */
            telemetry_client_destroy(ctx->client);
            ctx->client = NULL;
            if (telemetry_client_create(&ctx->client,
                        ctx->opts->central_host,
                        ctx->opts->central_port) == 0) {
                ret = telemetry_client_send(ctx->client, &packet);
            }
        }
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
    struct xdp_telemetry_device *device = NULL;
    struct xdp_telemetry_event_session *events = NULL;
	struct send_context send_ctx = {
		.opts = opts,
		.client = NULL,
		.verbose = opts->verbose,
		.warned_client = false,
	};
	struct xdp_telemetry_attach_opts attach_opts = {
		.ifname = opts->ifname,
		.mode = XDP_TELEMETRY_ATTACH_MODE_SKB,
		.pin_maps = true,
		.pin_maps_set = true,
		.pin_path = opts->pin_root,
	};
    int err;
    int i;
    int orig_netns_fd = -1;
    int target_netns_fd = -1;
    struct timespec ts_mono = {0}, ts_real = {0};

    /* If requested, temporarily enter target netns before resolving ifindex and attaching */
    if (opts->netns_pid > 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/ns/net", opts->netns_pid);
        orig_netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
        target_netns_fd = open(path, O_RDONLY | O_CLOEXEC);
        if (orig_netns_fd < 0 || target_netns_fd < 0) {
            fprintf(stderr, "agent: failed to open netns fds (pid=%d)\n", opts->netns_pid);
            if (target_netns_fd >= 0) close(target_netns_fd);
            if (orig_netns_fd >= 0) close(orig_netns_fd);
            return EXIT_FAILURE;
        }
        if (setns(target_netns_fd, CLONE_NEWNET) != 0) {
            perror("agent: setns(CLONE_NEWNET)");
            close(target_netns_fd);
            close(orig_netns_fd);
            return EXIT_FAILURE;
        }
        /* We are now in target netns; proceed to open/attach, then restore */
    }

    /* Defer central connection until after potential netns restore (to use host netns) */

    err = xdp_telemetry_device_open(&device, &attach_opts);
    if (err) {
        fprintf(stderr, "agent: failed to prepare device context: %s\n",
                strerror(-err));
        goto out_restore_netns;
    }

    /* Attach XDP with simple retries (interface/bpffs readiness) */
    for (i = 0; i < 10; i++) {
        err = xdp_telemetry_device_attach(device);
        if (!err)
            break;
        fprintf(stderr, "agent: attach failed on %s: %s (retry %d)\n",
                opts->ifname, strerror(-err), i + 1);
        sleep(1);
    }
    if (err) {
        fprintf(stderr, "agent: giving up attach on %s\n", opts->ifname);
        goto out_restore_netns;
    }

    /* Restore to original netns so that userland sockets (central TCP) use host netns */
out_restore_netns:
    if (opts->netns_pid > 0) {
        if (orig_netns_fd >= 0) {
            if (setns(orig_netns_fd, CLONE_NEWNET) != 0) {
                perror("agent: restore setns(CLONE_NEWNET)");
            }
            close(orig_netns_fd);
        }
        if (target_netns_fd >= 0) close(target_netns_fd);
    }

    if (err)
        goto out;

    /* Now connect telemetry client from (restored) host netns */
    if (telemetry_client_create(&send_ctx.client, opts->central_host,
                opts->central_port) != 0) {
        fprintf(stderr,
            "agent: failed to connect telemetry client to %s:%u\n",
            opts->central_host, opts->central_port);
    }

    /* Calibrate monotonic->realtime offset once (used for UI wall-clock bucketing) */
    if (clock_gettime(CLOCK_MONOTONIC, &ts_mono) == 0 &&
        clock_gettime(CLOCK_REALTIME, &ts_real) == 0) {
        long long mono_ns = (long long)ts_mono.tv_sec * 1000000000LL + (long long)ts_mono.tv_nsec;
        long long real_ns = (long long)ts_real.tv_sec * 1000000000LL + (long long)ts_real.tv_nsec;
        send_ctx.mono_to_real_ns = real_ns - mono_ns;
    } else {
        send_ctx.mono_to_real_ns = 0;
    }

    err = xdp_telemetry_event_session_open(device, &events);
    if (err) {
        fprintf(stderr, "agent: failed to open event session: %s\n",
                strerror(-err));
        goto out;
	}

	err = xdp_telemetry_events_subscribe(events, NULL,
					    event_dispatch_cb, &send_ctx);
	if (err) {
		fprintf(stderr, "agent: failed to subscribe to events: %s\n",
			strerror(-err));
		goto out;
	}

	while (!stop_agent) {
		err = xdp_telemetry_events_poll(events, AGENT_POLL_TIMEOUT_MS);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "agent: poll error: %s\n",
				strerror(-err));
			break;
		}
	}

	xdp_telemetry_events_unsubscribe(events);

out:
    if (events)
        xdp_telemetry_event_session_close(events);
    if (device) {
        (void)xdp_telemetry_device_detach(device);
        xdp_telemetry_device_close(device);
    }
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
