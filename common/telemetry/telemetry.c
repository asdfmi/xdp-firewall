#define _GNU_SOURCE

#include "telemetry.h"

#include <string.h>

static void write_u16_le(unsigned char *dst, uint16_t value)
{
	dst[0] = (unsigned char)(value & 0xffu);
	dst[1] = (unsigned char)((value >> 8) & 0xffu);
}

static void write_u32_le(unsigned char *dst, uint32_t value)
{
	dst[0] = (unsigned char)(value & 0xffu);
	dst[1] = (unsigned char)((value >> 8) & 0xffu);
	dst[2] = (unsigned char)((value >> 16) & 0xffu);
	dst[3] = (unsigned char)((value >> 24) & 0xffu);
}

static void write_u64_le(unsigned char *dst, uint64_t value)
{
	write_u32_le(dst, (uint32_t)(value & 0xffffffffu));
	write_u32_le(dst + 4, (uint32_t)((value >> 32) & 0xffffffffu));
}

static uint32_t read_u32_le(const unsigned char *src)
{
	return (uint32_t)src[0] |
	       ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) |
	       ((uint32_t)src[3] << 24);
}

static uint64_t read_u64_le(const unsigned char *src)
{
	uint64_t lo = read_u32_le(src);
	uint64_t hi = read_u32_le(src + 4);
	return lo | (hi << 32);
}

static uint16_t read_u16_le(const unsigned char *src)
{
	return (uint16_t)src[0] | ((uint16_t)src[1] << 8);
}

void telemetry_packet_init(struct telemetry_packet *pkt)
{
	if (!pkt)
		return;

	memset(pkt, 0, sizeof(*pkt));
}

int telemetry_packet_encode(const struct telemetry_packet *pkt,
			    unsigned char *buf, size_t buf_sz,
			    size_t *encoded_len)
{
	size_t src_ip_len;
	size_t dst_ip_len;
	size_t agent_id_len;
	size_t needed;
	unsigned char *p;

	if (!pkt || !buf)
		return -1;

	src_ip_len = strnlen(pkt->src_ip, TELEMETRY_MAX_IP_STR);
	dst_ip_len = strnlen(pkt->dst_ip, TELEMETRY_MAX_IP_STR);
	agent_id_len = strnlen(pkt->agent_id, TELEMETRY_MAX_AGENT_ID);
	if (src_ip_len > 255 || dst_ip_len > 255)
		return -1;
	if (agent_id_len > 255)
		return -1;
	if (pkt->payload_len > TELEMETRY_MAX_PAYLOAD)
		return -1;

	needed = 8 + 4 * 5 + 2 + pkt->payload_len +
		 1 + agent_id_len +
		 1 + src_ip_len +
		 1 + dst_ip_len +
		 4 + 4;
	if (buf_sz < needed)
		return -1;

	p = buf;
	write_u64_le(p, pkt->timestamp_ns);
	p += 8;
	write_u32_le(p, pkt->ifindex);
	p += 4;
	write_u32_le(p, pkt->queue_id);
	p += 4;
	write_u32_le(p, pkt->action);
	p += 4;
	write_u32_le(p, pkt->label_id);
	p += 4;
	write_u32_le(p, pkt->data_len);
	p += 4;
	*p++ = (unsigned char)agent_id_len;
	if (agent_id_len) {
		memcpy(p, pkt->agent_id, agent_id_len);
		p += agent_id_len;
	}
	write_u16_le(p, (uint16_t)pkt->payload_len);
	p += 2;
	if (pkt->payload_len) {
		memcpy(p, pkt->payload, pkt->payload_len);
		p += pkt->payload_len;
	}
	*p++ = (unsigned char)src_ip_len;
	if (src_ip_len) {
		memcpy(p, pkt->src_ip, src_ip_len);
		p += src_ip_len;
	}
	*p++ = (unsigned char)dst_ip_len;
	if (dst_ip_len) {
		memcpy(p, pkt->dst_ip, dst_ip_len);
		p += dst_ip_len;
	}
	write_u32_le(p, pkt->src_port);
	p += 4;
	write_u32_le(p, pkt->dst_port);
	p += 4;

	if (encoded_len)
		*encoded_len = (size_t)(p - buf);

	return 0;
}

int telemetry_packet_decode(struct telemetry_packet *pkt,
			    const unsigned char *buf, size_t buf_sz)
{
	size_t payload_len;
	size_t src_len;
	size_t dst_len;
	const unsigned char *p;

	if (!pkt || !buf)
		return -1;

	if (buf_sz < 8 + 4 * 5 + 2 + 1 + 1 + 1 + 4 + 4)
		return -1;

	p = buf;
	pkt->timestamp_ns = read_u64_le(p);
	p += 8;
	pkt->ifindex = read_u32_le(p);
	p += 4;
	pkt->queue_id = read_u32_le(p);
	p += 4;
	pkt->action = read_u32_le(p);
	p += 4;
	pkt->label_id = read_u32_le(p);
	p += 4;
	pkt->data_len = read_u32_le(p);
	p += 4;

	if ((size_t)(p - buf) >= buf_sz)
		return -1;
	size_t agent_len = *p++;
	if ((size_t)(p - buf) + agent_len > buf_sz || agent_len >= TELEMETRY_MAX_AGENT_ID)
		return -1;
	if (agent_len) {
		memcpy(pkt->agent_id, p, agent_len);
		pkt->agent_id[agent_len] = '\0';
		p += agent_len;
	} else {
		pkt->agent_id[0] = '\0';
	}

	payload_len = read_u16_le(p);
	p += 2;
	if (payload_len > TELEMETRY_MAX_PAYLOAD)
		return -1;
	if ((size_t)(p - buf) + payload_len > buf_sz)
		return -1;
	pkt->payload_len = payload_len;
	if (payload_len)
		memcpy(pkt->payload, p, payload_len);
	p += payload_len;

	if ((size_t)(p - buf) >= buf_sz)
		return -1;
	src_len = *p++;
	if ((size_t)(p - buf) + src_len > buf_sz || src_len >= TELEMETRY_MAX_IP_STR)
		return -1;
	if (src_len) {
		memcpy(pkt->src_ip, p, src_len);
		pkt->src_ip[src_len] = '\0';
		p += src_len;
	} else {
		pkt->src_ip[0] = '\0';
	}

	if ((size_t)(p - buf) >= buf_sz)
		return -1;
	dst_len = *p++;
	if ((size_t)(p - buf) + dst_len > buf_sz || dst_len >= TELEMETRY_MAX_IP_STR)
		return -1;
	if (dst_len) {
		memcpy(pkt->dst_ip, p, dst_len);
		pkt->dst_ip[dst_len] = '\0';
		p += dst_len;
	} else {
		pkt->dst_ip[0] = '\0';
	}

	if ((size_t)(p - buf) + 8 > buf_sz)
		return -1;
	pkt->src_port = read_u32_le(p);
	p += 4;
	pkt->dst_port = read_u32_le(p);
	p += 4;

	return 0;
}
