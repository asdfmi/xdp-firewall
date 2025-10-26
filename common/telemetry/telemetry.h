#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TELEMETRY_MAX_IP_STR 64
#define TELEMETRY_MAX_AGENT_ID 64
#define TELEMETRY_MAX_PAYLOAD 256

struct telemetry_packet {
	uint64_t timestamp_ns;
	uint32_t ifindex;
	uint32_t queue_id;
	uint32_t action;
	uint32_t label_id;
	uint32_t data_len;
	size_t payload_len;
	unsigned char payload[TELEMETRY_MAX_PAYLOAD];
	char src_ip[TELEMETRY_MAX_IP_STR];
	char dst_ip[TELEMETRY_MAX_IP_STR];
	uint32_t src_port;
	uint32_t dst_port;
	char agent_id[TELEMETRY_MAX_AGENT_ID];
};

void telemetry_packet_init(struct telemetry_packet *pkt);
int telemetry_packet_encode(const struct telemetry_packet *pkt,
			    unsigned char *buf, size_t buf_sz,
			    size_t *encoded_len);
int telemetry_packet_decode(struct telemetry_packet *pkt,
			    const unsigned char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif
