#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-buffer.h"
#include "decode.h"
#include "detect-ics.h"
#include "output.h"
#include "output-redis-ics.h"

#include <hiredis/hiredis.h>
#include <tlv_box.h>

int ICSRadisLogger(ThreadVars *t, void *data, const Packet *p);
int ICSRadisLogCondition(ThreadVars *t, void *data, const Packet *p);
TmEcode ICSRadisLogThreadInit(ThreadVars *t, const void *initdata, void **data);
TmEcode ICSRadisLogThreadDeinit(ThreadVars *t, void *data);
void ICSRadisLogRegister(void);

static int ICSSendRedisLog(redisContext *c, ics_mode_t mode, uint8_t *data, size_t data_len)
{
	int ret = TM_ECODE_OK;
	redisReply *reply = NULL;

	switch(mode) {
		case ICS_MODE_NORMAL:
			reply = redisCommand(c, "%s %s %b", REDIS_PUBLISH_CMD, ICS_AUDIT_CHANNEL, data, data_len);
			if (reply == NULL) {
				SCLogNotice("publish %s with data error.\n", ICS_AUDIT_CHANNEL);
				ret = TM_ECODE_FAILED;
				goto out;
			}
			freeReplyObject(reply);
			break;
		case ICS_MODE_STUDY:
			reply = redisCommand(c, "%s %s %b", REDIS_PUBLISH_CMD, ICS_STUDY_CHANNEL, data, data_len);
			if (reply == NULL) {
				SCLogNotice("public %s with data error.\n", ICS_STUDY_CHANNEL);
				ret = TM_ECODE_FAILED;
				goto out;
			}
			break;
		case ICS_MODE_WARNING:
			reply = redisCommand(c, "%s %s %b", REDIS_PUBLISH_CMD, ICS_WARN_CHANNEL, data, data_len);
			if (reply == NULL) {
				SCLogNotice("public %s with data error.\n", ICS_WARN_CHANNEL);
				ret = TM_ECODE_FAILED;
				goto out;
			}
			break;
		default:
			break;
	}
out:
	return ret;
}

static inline uint32_t TluHash(uint32_t u1, uint32_t u2)
{
    uint32_t a,b,c;
    a = u2 + 0x9e3779b9;
    b = u1 + 0x9e3779b9;
    c = 0;
    a = a - b; a = a - c; a = a ^ (c >> 13);
    b = b - c; b = b - a; b = b ^ (a << 8);
    c = c - a; c = c - b; c = c ^ (b >> 13);
    a = a - b; a = a - c; a = a ^ (c >> 12);
    b = b - c; b = b - a; b = b ^ (a << 16);
    c = c - a; c = c - b; c = c ^ (b >> 5);
    a = a - b; a = a - c; a = a ^ (c >> 3);
    b = b - c; b = b - a; b = b ^ (a << 10);
    c = c - a; c = c - b; c = c ^ (b >> 15);
    return (c);
}

static tlv_box_t* serialize_audit_common_data(const Packet *p, int template_id)
{
	tlv_box_t *box = NULL;
	char eth_src[19] = {0}, eth_dst[19] = {0};
	uint32_t flow_hash = 0;

	box = tlv_box_create();
	tlv_box_put_int(box, BEGIN, 0);
	tlv_box_put_int(box, TEMPLATE_ID, template_id);
	if (p->ethh != NULL) {
		(void) snprintf(eth_src, sizeof(eth_src), "%02x:%02x:%02x:%02x:%02x:%02x",
			p->ethh->eth_src[0], p->ethh->eth_src[1],
			p->ethh->eth_src[2], p->ethh->eth_src[3],
			p->ethh->eth_src[4], p->ethh->eth_src[5]);
		(void) snprintf(eth_dst, sizeof(eth_dst), "%02x:%02x:%02x:%02x:%02x:%02x",
			p->ethh->eth_dst[0], p->ethh->eth_dst[1],
			p->ethh->eth_dst[2], p->ethh->eth_dst[3],
			p->ethh->eth_dst[4], p->ethh->eth_dst[5]);
	} else {
		(void) snprintf(eth_src, sizeof(eth_src), "%02x:%02x:%02x:%02x:%02x:%02x",
			0, 0, 0, 0, 0, 0);
		(void) snprintf(eth_dst, sizeof(eth_dst), "%02x:%02x:%02x:%02x:%02x:%02x",
			0, 0, 0, 0, 0, 0);
	}
	tlv_box_put_string(box, SRC_MAC, eth_src);
	tlv_box_put_string(box, DST_MAC, eth_dst);
	tlv_box_put_uint(box, SRC_IPv4, GET_IPV4_SRC_ADDR_U32(p));
	tlv_box_put_uint(box, DST_IPv4, GET_IPV4_DST_ADDR_U32(p));
	tlv_box_put_ushort(box, SRC_PORT, GET_TCP_SRC_PORT(p));
	tlv_box_put_ushort(box, DST_PORT, GET_TCP_DST_PORT(p));
	tlv_box_put_uchar(box, PROTO, IP_GET_IPPROTO(p));
	flow_hash = TluHash(GET_IPV4_SRC_ADDR_U32(p), GET_IPV4_DST_ADDR_U32(p));
	flow_hash ^= TluHash(GET_TCP_SRC_PORT(p), GET_TCP_DST_PORT(p));
	flow_hash ^= TluHash(IP_GET_IPPROTO(p), 0xFFFFFFFF);
	tlv_box_put_uint(box, FLOW_HASH, flow_hash);
	tlv_box_put_uint(box, PKTLEN, p->pktlen);
	tlv_box_put_ushort(box, PAYLOAD_LEN, p->payload_len);
	return box;
}

static tlv_box_t* serialize_study_common_data(const Packet *p, int template_id)
{
	tlv_box_t *box = NULL;

	box = tlv_box_create();
	tlv_box_put_int(box, BEGIN, 0);
	tlv_box_put_int(box, TEMPLATE_ID, template_id);
	tlv_box_put_uint(box, SRC_IPv4, GET_IPV4_SRC_ADDR_U32(p));
	tlv_box_put_uint(box, DST_IPv4, GET_IPV4_DST_ADDR_U32(p));
	tlv_box_put_uchar(box, PROTO, IP_GET_IPPROTO(p));
	return box;
}

static tlv_box_t* serialize_warning_common_data(const Packet *p, int template_id)
{
	tlv_box_t *box = NULL;

	box = tlv_box_create();
	tlv_box_put_int(box, BEGIN, 0);
	tlv_box_put_int(box, TEMPLATE_ID, template_id);
	tlv_box_put_uint(box, SRC_IPv4, GET_IPV4_SRC_ADDR_U32(p));
	tlv_box_put_uint(box, DST_IPv4, GET_IPV4_DST_ADDR_U32(p));
	tlv_box_put_uchar(box, PROTO, IP_GET_IPPROTO(p));
	return box;
}

#if 0
static void debug_audit_modbus_data(ics_modbus_t *modbus)
{
	SCLogNotice("funcode = %u", modbus->funcode);
	switch(modbus->funcode) {
		case 1:
		case 2:
		case 3:
		case 4:
			SCLogNotice("address = %u, quantity = %u", modbus->u.addr_quan.address, modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			SCLogNotice("address = %u, quantity = %u", modbus->u.addr_data.address, modbus->u.addr_data.data);
			break;
		case 8:
			SCLogNotice("subfunction = %u", modbus->u.subfunc.subfunction);
			break;
		case 15:
			SCLogNotice("address = %u, quantity = %u, data_len = %u, data = ", modbus->u.addr_quan_data.address, modbus->u.addr_quan_data.quantity, modbus->u.addr_quan_data.data_len);
			for (uint32_t i = 0; i < modbus->u.addr_quan_data.data_len; i++)
				SCLogNotice("%02x ", modbus->u.addr_quan_data.data[i]);
			break;
		case 16:
			SCLogNotice("address = %u, quantity = %u", modbus->u.addr_quan.address, modbus->u.addr_quan.quantity);
			break;
		case 22:
			SCLogNotice("and_mask = %u, or_mask = %u", modbus->u.and_or_mask.and_mask, modbus->u.and_or_mask.or_mask);
			break;
		case 23:
			SCLogNotice("r_address = %u, r_quantity = %u, w_address = %u, w_quantity = %u",
				modbus->u.rw_addr_quan.read_address, modbus->u.rw_addr_quan.read_quantity,
				modbus->u.rw_addr_quan.write_address, modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			break;
	}
}

static void debug_audit_dnp3_data(ics_dnp3_t *dnp3)
{
	SCLogNotice("funcode = %u", dnp3->function_code);
	SCLogNotice("object_count = %u", dnp3->object_count);
	for (uint32_t i = 0; i < dnp3->object_count; i++) {
		SCLogNotice("group[%d] = %u, variation[%d] = %u", i, dnp3->objects[i].group, i, dnp3->objects[i].variation);
		if (dnp3->objects[i].point_count > 0) {
			for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
				SCLogNotice("group[%d] = %u, variation[%d] = %u, index[%d][%d] = %u, size[%d][%d] = %u",
					i, dnp3->objects[i].group, i, dnp3->objects[i].variation, i, j, dnp3->objects[i].points[j].index, i, j, dnp3->objects[i].points[j].size);
			}
		} else {
			SCLogNotice("group[%d] = %u, variation[%d] = %u, index[%d][0] = 0, size[%d][0] = 0",
				i, dnp3->objects[i].group, i, dnp3->objects[i].variation, i ,i);
		}
	}
}

static void debug_audit_trdp_data(ics_trdp_t *trdp)
{
	SCLogNotice("packet_type = %s", (trdp->packet_type == PD_PDU) ? "PD" : "MD");
	SCLogNotice("sequence_counter = %u", trdp->u.pd.header.sequence_counter);
	SCLogNotice("protocol_version = %u", trdp->u.pd.header.protocol_version);
	SCLogNotice("msg_type = %u", trdp->u.pd.header.msg_type);
	SCLogNotice("com_id = %u", trdp->u.pd.header.com_id);
	SCLogNotice("ebt_topo_cnt = %u", trdp->u.pd.header.ebt_topo_cnt);
	SCLogNotice("op_trn_topo_cnt = %u", trdp->u.pd.header.op_trn_topo_cnt);
	SCLogNotice("dataset_length = %u", trdp->u.pd.header.dataset_length);
	SCLogNotice("reserved = %u", trdp->u.pd.header.reserved);
	SCLogNotice("reply_com_id = %u", trdp->u.pd.header.reply_com_id);
	SCLogNotice("reply_ip_address = %u", trdp->u.pd.header.reply_ip_address);
	SCLogNotice("frame_checksum = 0x%x", trdp->u.pd.header.frame_checksum);
	SCLogNotice("data = ");
	for (uint32_t i = 0; i < trdp->u.pd.header.dataset_length; i++)
		SCLogNotice("%02x", trdp->u.pd.data[i]);
}

static void debug_study_modbus_data(modbus_ht_item_t *modbus)
{
	SCLogNotice("sip = %u, dip = %u, proto = %u, funcode = %u, address = %x, quantity = %x",
		modbus->sip,
		modbus->dip,
		modbus->proto,
		modbus->funcode,
		modbus->address,
		modbus->quantity);
}

static void debug_study_dnp3_data(dnp3_ht_items_t *dnp3)
{
	SCLogNotice("dnp3_count = %u", dnp3->dnp3_ht_count);
	for (uint32_t i = 0; i < dnp3->dnp3_ht_count; i++) {
		SCLogNotice("sip = %u, dip = %u, proto = %u, group = %u, variation = %u, index = %u, size = %u",
			dnp3->items[i].sip,
			dnp3->items[i].dip,
			dnp3->items[i].proto,
			dnp3->items[i].group,
			dnp3->items[i].variation,
			dnp3->items[i].index,
			dnp3->items[i].size);
	}
}

static void debug_study_trdp_data(trdp_ht_item_t *trdp)
{
	SCLogNotice("sip = %u, dip = %u, proto = %u, packet_type = %u, protocol_version = %u, msg_type = %u, com_id = %u",
		trdp->sip,
		trdp->dip,
		trdp->proto,
		trdp->packet_type,
		trdp->protocol_version,
		trdp->msg_type,
		trdp->com_id);
}

static void debug_warning_modbus_data(modbus_ht_item_t *modbus)
{
	SCLogNotice("sip = %u, dip = %u, proto = %u, funcode = %u, address = %x, quantity = %x",
		modbus->sip,
		modbus->dip,
		modbus->proto,
		modbus->funcode,
		modbus->address,
		modbus->quantity);
}

static void debug_warning_dnp3_data(dnp3_ht_item_t *dnp3)
{
	SCLogNotice("sip = %u, dip = %u, proto = %u, group = %u, variation = %u, index = %u, size = %u",
		dnp3->sip,
		dnp3->dip,
		dnp3->proto,
		dnp3->group,
		dnp3->variation,
		dnp3->index,
		dnp3->size);
}

static void debug_warning_trdp_data(trdp_ht_item_t *trdp)
{
	SCLogNotice("sip = %u, dip = %u, proto = %u, packet_type = %u, protocol_version = %u, msg_type = %u, com_id = %u",
		trdp->sip,
		trdp->dip,
		trdp->proto,
		trdp->packet_type,
		trdp->protocol_version,
		trdp->msg_type,
		trdp->com_id);
}
#endif

static int serialize_audit_modbus_data(const Packet *p, int template_id, ics_modbus_t *modbus, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;

	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, MODBUS);
	tlv_box_put_bytes(box, MODBUS_AUDIT_DATA, (unsigned char *)modbus, sizeof(ics_modbus_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_study_modbus_data(const Packet *p, int template_id, modbus_ht_item_t *modbus, uint8_t **study_data, int *study_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *study_data_ptr = NULL;

	box = serialize_study_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, MODBUS);
	tlv_box_put_bytes(box, MODBUS_STUDY_DATA, (unsigned char *)modbus, sizeof(modbus_ht_item_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*study_data_len = tlv_box_get_size(box);
	if ((*study_data = SCMalloc(*study_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*study_data, 0x00, *study_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*study_data), *study_data_len, "%d:", *study_data_len);
	study_data_ptr = (uint8_t *)strchr((char *)(*study_data), ':');
	study_data_ptr++;
	memcpy(study_data_ptr, tlv_box_get_buffer(box), *study_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_warning_modbus_data(const Packet *p, int template_id, modbus_ht_item_t *modbus, uint8_t **warning_data, int *warning_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *warning_data_ptr = NULL;

	box = serialize_warning_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, MODBUS);
	tlv_box_put_bytes(box, MODBUS_WARNING_DATA, (unsigned char *)modbus, sizeof(modbus_ht_item_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*warning_data_len = tlv_box_get_size(box);
	if ((*warning_data = SCMalloc(*warning_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*warning_data, 0x00, *warning_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*warning_data), *warning_data_len, "%d:", *warning_data_len);
	warning_data_ptr = (uint8_t *)strchr((char *)(*warning_data), ':');
	warning_data_ptr++;
	memcpy(warning_data_ptr, tlv_box_get_buffer(box), *warning_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

#define DNP3_DATA_BUFFER_LENGTH		2048
static int serialize_audit_dnp3_data(const Packet *p, int template_id, ics_dnp3_t *dnp3, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;
	MemBuffer *dnp3_data_buffer = NULL;

	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, DNP3);
	dnp3_data_buffer = MemBufferCreateNew(DNP3_DATA_BUFFER_LENGTH);
	if (dnp3_data_buffer == NULL) {
		SCLogNotice("create DNP3 Data MemBuffer error.");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	MemBufferWriteRaw(dnp3_data_buffer, &dnp3->function_code, sizeof(uint8_t));
	MemBufferWriteRaw(dnp3_data_buffer, &dnp3->object_count, sizeof(uint32_t));
	if (dnp3->object_count > 0) {
		for (uint32_t i = 0; i < dnp3->object_count; i++) {
			if (MEMBUFFER_OFFSET(dnp3_data_buffer) + sizeof(uint8_t)*2 + sizeof(uint32_t) >= MEMBUFFER_SIZE(dnp3_data_buffer))
				MemBufferExpand(&dnp3_data_buffer, DNP3_DATA_BUFFER_LENGTH);
			MemBufferWriteRaw(dnp3_data_buffer, &dnp3->objects[i].group, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_data_buffer, &dnp3->objects[i].variation, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_data_buffer, &dnp3->objects[i].point_count, sizeof(uint32_t));
			for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
				if (MEMBUFFER_OFFSET(dnp3_data_buffer) + sizeof(uint32_t)*2 >= MEMBUFFER_SIZE(dnp3_data_buffer))
					MemBufferExpand(&dnp3_data_buffer, DNP3_DATA_BUFFER_LENGTH);
				MemBufferWriteRaw(dnp3_data_buffer, &dnp3->objects[i].points[j].index, sizeof(uint32_t));
				MemBufferWriteRaw(dnp3_data_buffer, &dnp3->objects[i].points[j].size, sizeof(uint32_t));
			}
		}
	}
	tlv_box_put_bytes(box, DNP3_AUDIT_DATA, MEMBUFFER_BUFFER(dnp3_data_buffer), MEMBUFFER_OFFSET(dnp3_data_buffer));
	MemBufferFree(dnp3_data_buffer);
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_study_dnp3_data(const Packet *p, int template_id, dnp3_ht_items_t *dnp3, uint8_t **study_data, int *study_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *study_data_ptr = NULL;
	MemBuffer *dnp3_data_buffer = NULL;

	if (dnp3->dnp3_ht_count == 0) {
		ret = TM_ECODE_FAILED;
		goto out;
	}
	box = serialize_study_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, DNP3);
	dnp3_data_buffer = MemBufferCreateNew(DNP3_DATA_BUFFER_LENGTH);
	if (dnp3_data_buffer == NULL) {
		SCLogNotice("create DNP3 Data MemBuffer error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	MemBufferWriteRaw(dnp3_data_buffer, &dnp3->dnp3_ht_count, sizeof(uint32_t));
	for (uint32_t i = 0; i < dnp3->dnp3_ht_count; i++) {
		if (MEMBUFFER_OFFSET(dnp3_data_buffer) + sizeof(uint8_t)*3 + sizeof(uint32_t)*2 >= MEMBUFFER_SIZE(dnp3_data_buffer))
			MemBufferExpand(&dnp3_data_buffer, DNP3_DATA_BUFFER_LENGTH);
		MemBufferWriteRaw(dnp3_data_buffer, &dnp3->items[i].funcode, sizeof(uint8_t));
		MemBufferWriteRaw(dnp3_data_buffer, &dnp3->items[i].group, sizeof(uint8_t));
		MemBufferWriteRaw(dnp3_data_buffer, &dnp3->items[i].variation, sizeof(uint8_t));
		MemBufferWriteRaw(dnp3_data_buffer, &dnp3->items[i].index, sizeof(uint32_t));
		MemBufferWriteRaw(dnp3_data_buffer, &dnp3->items[i].size, sizeof(uint32_t));
	}
	tlv_box_put_bytes(box, DNP3_STUDY_DATA, MEMBUFFER_BUFFER(dnp3_data_buffer), MEMBUFFER_OFFSET(dnp3_data_buffer));
	MemBufferFree(dnp3_data_buffer);
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*study_data_len = tlv_box_get_size(box);
	if ((*study_data = SCMalloc(*study_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*study_data, 0x00, *study_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*study_data), *study_data_len, "%d:", *study_data_len);
	study_data_ptr = (uint8_t *)strchr((char *)(*study_data), ':');
	study_data_ptr++;
	memcpy(study_data_ptr, tlv_box_get_buffer(box), *study_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_warning_dnp3_data(const Packet *p, int template_id, dnp3_ht_item_t *dnp3, uint8_t **warning_data, int *warning_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *warning_data_ptr = NULL;

	box = serialize_warning_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, DNP3);
	tlv_box_put_bytes(box, DNP3_WARNING_DATA, (unsigned char *)dnp3, sizeof(dnp3_ht_item_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*warning_data_len = tlv_box_get_size(box);
	if ((*warning_data = SCMalloc(*warning_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*warning_data, 0x00, *warning_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*warning_data), *warning_data_len, "%d:", *warning_data_len);
	warning_data_ptr = (uint8_t *)strchr((char *)(*warning_data), ':');
	warning_data_ptr++;
	memcpy(warning_data_ptr, tlv_box_get_buffer(box), *warning_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_audit_trdp_data(const Packet *p, int template_id, ics_trdp_t *trdp, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;

	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, TRDP);
	tlv_box_put_bytes(box, TRDP_AUDIT_DATA, (unsigned char *)trdp, sizeof(ics_trdp_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_study_trdp_data(const Packet *p, int template_id, trdp_ht_item_t *trdp, uint8_t **study_data, int *study_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *study_data_ptr = NULL;

	box = serialize_study_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, TRDP);
	tlv_box_put_bytes(box, TRDP_STUDY_DATA, (unsigned char *)trdp, sizeof(trdp_ht_item_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*study_data_len = tlv_box_get_size(box);
	if ((*study_data = SCMalloc(*study_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*study_data, 0x00, *study_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*study_data), *study_data_len, "%d:", *study_data_len);
	study_data_ptr = (uint8_t *)strchr((char *)(*study_data), ':');
	study_data_ptr++;
	memcpy(study_data_ptr, tlv_box_get_buffer(box), *study_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;

}

static int serialize_warning_trdp_data(const Packet *p, int template_id, trdp_ht_item_t *trdp, uint8_t **warning_data, int *warning_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *warning_data_ptr = NULL;

	box = serialize_warning_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, TRDP);
	tlv_box_put_bytes(box, TRDP_WARNING_DATA, (unsigned char *)trdp, sizeof(trdp_ht_item_t));
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*warning_data_len = tlv_box_get_size(box);
	if ((*warning_data = SCMalloc(*warning_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*warning_data, 0x00, *warning_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*warning_data), *warning_data_len, "%d:", *warning_data_len);
	warning_data_ptr = (uint8_t *)strchr((char *)(*warning_data), ':');
	warning_data_ptr++;
	memcpy(warning_data_ptr, tlv_box_get_buffer(box), *warning_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_audit_http1_data(const Packet *p, int template_id, ics_http1_t *http1, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;

	if (http1->http_uri == NULL) {
		ret = TM_ECODE_FAILED;
		goto out;
	}
	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, HTTP1);
	tlv_box_put_bytes(box, HTTP1_AUDIT_DATA, (unsigned char *)http1->http_uri, http1->http_uri_len);
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_audit_ftp_data(const Packet *p, int template_id, ics_ftp_t *ftp, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL, *inner_box = NULL;
	uint8_t *audit_data_ptr = NULL;

	if (ftp->command == NULL || ftp->command_length == 0) {
		ret = TM_ECODE_FAILED;
		goto out;
	}
	inner_box = tlv_box_create();
	tlv_box_put_uchar(inner_box, FTP_COMMAND_LENGTH, ftp->command_length);
	tlv_box_put_string(inner_box, FTP_COMMAND, ftp->command);
	tlv_box_put_uint(inner_box, FTP_PARAMS_LENGTH, ftp->params_length);
	if (ftp->params_length > 0)
		tlv_box_put_string(inner_box, FTP_PARAMS, ftp->params);
	else
		tlv_box_put_string(inner_box, FTP_PARAMS, (char *)"");
	if (tlv_box_serialize(inner_box) != 0) {
		ret = TM_ECODE_FAILED;
		goto out;
	}
	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, FTP);
	tlv_box_put_object(box, FTP_AUDIT_DATA, inner_box);
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (inner_box)
		tlv_box_destroy(inner_box);
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int serialize_audit_telnet_data(const Packet *p, int template_id, ics_telnet_t *telnet, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL, *inner_box = NULL;
	uint8_t *audit_data_ptr = NULL;

	if (telnet->data_length == 0)
		goto out;
	inner_box = tlv_box_create();
	tlv_box_put_int(inner_box, TELNET_DATA_LENGTH, telnet->data_length);
	tlv_box_put_bytes(inner_box, TELNET_DATA, (unsigned char *)telnet->data, telnet->data_length);
	if (tlv_box_serialize(inner_box) != 0) {
		ret = TM_ECODE_FAILED;
		goto out;
	}
	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, TELNET);
	tlv_box_put_object(box, TELNET_AUDIT_DATA, inner_box);
	if (tlv_box_serialize(box)) {
		SCLogNotice("tlv box serialized failed.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*audit_data_len = tlv_box_get_size(box);
	if ((*audit_data = SCMalloc(*audit_data_len+sizeof(int)+sizeof(char))) == NULL) {
		SCLogNotice("SCMalloc error.\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memset(*audit_data, 0x00, *audit_data_len+sizeof(int)+sizeof(char));
	snprintf((char *)(*audit_data), *audit_data_len, "%d:", *audit_data_len);
	audit_data_ptr = (uint8_t *)strchr((char *)(*audit_data), ':');
	audit_data_ptr++;
	memcpy(audit_data_ptr, tlv_box_get_buffer(box), *audit_data_len);
out:
	if (inner_box)
		tlv_box_destroy(inner_box);
	if (box)
		tlv_box_destroy(box);
	return ret;
}

static int create_modbus_audit_data(const Packet *p, ics_modbus_t *modbus, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_modbus_data(p, 0, modbus, audit_data, audit_data_len);
}

static int create_modbus_study_data(const Packet *p, int template_id, modbus_ht_item_t *modbus, uint8_t **study_data, int *study_data_len)
{
	return serialize_study_modbus_data(p, template_id, modbus, study_data, study_data_len);
}

static int create_modbus_warning_data(const Packet *p, int template_id, modbus_ht_item_t *modbus, uint8_t **warning_data, int *warning_data_len)
{
	return serialize_warning_modbus_data(p, template_id, modbus, warning_data, warning_data_len);
}

static int create_dnp3_audit_data(const Packet *p, ics_dnp3_t *dnp3, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_dnp3_data(p, 0, dnp3, audit_data, audit_data_len);
}

static int create_dnp3_study_data(const Packet *p, int template_id, dnp3_ht_items_t *dnp3, uint8_t **study_data, int *study_data_len)
{
	return serialize_study_dnp3_data(p, template_id, dnp3, study_data, study_data_len);
}

static int create_dnp3_warning_data(const Packet *p, int template_id, dnp3_ht_item_t *dnp3, uint8_t **warning_data, int *warning_data_len)
{
	return serialize_warning_dnp3_data(p, template_id, dnp3, warning_data, warning_data_len);
}

static int create_trdp_audit_data(const Packet *p, ics_trdp_t *trdp, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_trdp_data(p, 0, trdp, audit_data, audit_data_len);
}

static int create_trdp_study_data(const Packet *p, int template_id, trdp_ht_item_t *trdp, uint8_t **study_data, int *study_data_len)
{
	return serialize_study_trdp_data(p, template_id, trdp, study_data, study_data_len);
}

static int create_trdp_warning_data(const Packet *p, int template_id, trdp_ht_item_t *trdp, uint8_t **warning_data, int *warning_data_len)
{
	return serialize_warning_trdp_data(p, template_id, trdp, warning_data, warning_data_len);
}

static int create_http1_audit_data(const Packet *p, ics_http1_t *http1, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_http1_data(p, 0, http1, audit_data, audit_data_len);
}

static int create_ftp_audit_data(const Packet *p, ics_ftp_t *ftp, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_ftp_data(p, 0, ftp, audit_data, audit_data_len);
}

static int create_telnet_audit_data(const Packet *p, ics_telnet_t *telnet, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_telnet_data(p, 0, telnet, audit_data, audit_data_len);
}

int ICSRadisLogger(ThreadVars *t, void *data, const Packet *p)
{
	int ret = TM_ECODE_OK;
	redisContext *c = (redisContext *)data;
	ics_adu_t *ics_adu = NULL;
	uint8_t *audit_data = NULL, *study_data = NULL, *warning_data = NULL;
	int audit_data_len = 0, study_data_len = 0, warning_data_len = 0;

	if (p->flow == NULL || p->flow->ics_adu == NULL)
		goto out;

	ics_adu = p->flow->ics_adu;
	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			ret = create_modbus_audit_data(p, ics_adu->audit.modbus, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					ret = create_modbus_study_data(p, ics_adu->template_id, ics_adu->study.modbus, &study_data, &study_data_len);
					if (ret != TM_ECODE_OK)
						goto out;
					ICSSendRedisLog(c, ICS_MODE_STUDY, study_data, study_data_len);
					break;
				case ICS_MODE_WARNING:
					if (ics_adu->flags & ICS_ADU_WARNING_INVALID_FLAG) {
						ret = create_modbus_warning_data(p, ics_adu->template_id, ics_adu->warning.modbus, &warning_data, &warning_data_len);
						if (ret != TM_ECODE_OK)
							goto out;
						ICSSendRedisLog(c, ICS_MODE_WARNING, warning_data, warning_data_len);
					}
					break;
				default:
					break;
			}
			break;
		case ALPROTO_DNP3:
			ret = create_dnp3_audit_data(p, ics_adu->audit.dnp3, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					ret = create_dnp3_study_data(p, ics_adu->template_id, ics_adu->study.dnp3, &study_data, &study_data_len);
					if (ret != TM_ECODE_OK)
						goto out;
					ICSSendRedisLog(c, ICS_MODE_STUDY, study_data, study_data_len);
					break;
				case ICS_MODE_WARNING:
					if (ics_adu->flags & ICS_ADU_WARNING_INVALID_FLAG) {
						ret = create_dnp3_warning_data(p, ics_adu->template_id, ics_adu->warning.dnp3, &warning_data, &warning_data_len);
						if (ret != TM_ECODE_OK)
							goto out;
						ICSSendRedisLog(c, ICS_MODE_WARNING, warning_data, warning_data_len);
					}
					break;
				default:
					break;
			}
			break;
		case ALPROTO_TRDP:
			ret = create_trdp_audit_data(p, ics_adu->audit.trdp, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					ret = create_trdp_study_data(p, ics_adu->template_id, ics_adu->study.trdp, &study_data, &study_data_len);
					if (ret != TM_ECODE_OK)
						goto out;
					ICSSendRedisLog(c, ICS_MODE_STUDY, study_data, study_data_len);
					break;
				case ICS_MODE_WARNING:
					if (ics_adu->flags & ICS_ADU_WARNING_INVALID_FLAG) {
						ret = create_trdp_warning_data(p, ics_adu->template_id, ics_adu->warning.trdp, &warning_data, &warning_data_len);
						if (ret != TM_ECODE_OK)
							goto out;
						ICSSendRedisLog(c, ICS_MODE_WARNING, warning_data, warning_data_len);
					}
					break;
				default:
					break;
			}
			break;
		case ALPROTO_HTTP1:
			ret = create_http1_audit_data(p, ics_adu->audit.http1, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			break;
		case ALPROTO_FTP:
		case ALPROTO_FTPDATA:
			ret = create_ftp_audit_data(p, ics_adu->audit.ftp, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			break;
		case ALPROTO_TELNET:
			ret = create_telnet_audit_data(p, ics_adu->audit.telnet, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			break;
		default:
			goto out;
	}
out:
	if (audit_data)
		SCFree(audit_data);
	if (study_data)
		SCFree(study_data);
	if (warning_data)
		SCFree(warning_data);
	return TM_ECODE_OK;
}

int ICSRadisLogCondition(ThreadVars *t, void *data, const Packet *p)
{
	int ret = FALSE;

	if (p == NULL || p->flow == NULL) {
		goto out;
	}

	switch(p->flow->alproto) {
		case ALPROTO_MODBUS:
		case ALPROTO_DNP3:
		case ALPROTO_TRDP:
		case ALPROTO_HTTP1:
		case ALPROTO_FTP:
		case ALPROTO_FTPDATA:
		case ALPROTO_TELNET:
			if (p->flowflags & FLOW_PKT_TOSERVER)
				ret = TRUE;
			break;
		default:
			break;
	}
out:
	return ret;
}

TmEcode ICSRadisLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
	TmEcode ret = TM_ECODE_OK;
	redisContext *c = NULL;

	c = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
	if (c != NULL && c->err) {
		SCLogDebug("Error connect to redis server %s:%d : %s\n", REDIS_SERVER_IP, REDIS_SERVER_PORT, c->errstr);
		ret = TM_ECODE_FAILED;
		goto out;
	}
	*data = (void *)c;
out:
	return ret;
}

TmEcode ICSRadisLogThreadDeinit(ThreadVars *t, void *data)
{
	redisContext *c = (redisContext *)data;

	if (c != NULL) {
		redisFree(c);
	}
	return TM_ECODE_OK;
}

void ICSRedisLogRegister(void)
{
	OutputRegisterPacketModule(LOGGER_RADIS_ICS, MODULE_NAME, "ics-redis",
		NULL, ICSRadisLogger, ICSRadisLogCondition, ICSRadisLogThreadInit, ICSRadisLogThreadDeinit, NULL);
}
