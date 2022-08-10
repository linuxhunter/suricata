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

static int serialize_audit_modbus_data(const Packet *p, int template_id, ics_modbus_t *modbus, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;

	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, MODBUS);
	tlv_box_put_uchar(box, MODBUS_FUNCODE, modbus->funcode);
	switch(modbus->funcode) {
		case 1:
		case 2:
		case 3:
		case 4:
			tlv_box_put_ushort(box, MODBUS_RADDR, modbus->u.addr_quan.address);
			tlv_box_put_ushort(box, MODBUS_RQUANTITY, modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_data.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, (uint16_t)1);
			tlv_box_put_uchar(box, MODBUS_DATA_LEN, sizeof(uint16_t));
			tlv_box_put_ushort(box, MODBUS_DATA, modbus->u.addr_data.data);
			break;
		case 8:
			tlv_box_put_ushort(box, MODBUS_SUBFUNC, modbus->u.subfunc.subfunction);
			break;
		case 15:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_quan_data.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.addr_quan_data.quantity);
			tlv_box_put_uchar(box, MODBUS_DATA_LEN, modbus->u.addr_quan_data.data_len);
			tlv_box_put_bytes(box, MODBUS_DATA, modbus->u.addr_quan_data.data, modbus->u.addr_quan_data.data_len);
			break;
		case 16:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_quan.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.addr_quan.quantity);
			break;
		case 22:
			tlv_box_put_ushort(box, MODBUS_AND_MASK, modbus->u.and_or_mask.and_mask);
			tlv_box_put_ushort(box, MODBUS_OR_MASK, modbus->u.and_or_mask.or_mask);
			break;
		case 23:
			tlv_box_put_ushort(box, MODBUS_RADDR, modbus->u.rw_addr_quan.read_address);
			tlv_box_put_ushort(box, MODBUS_RQUANTITY, modbus->u.rw_addr_quan.read_quantity);
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.rw_addr_quan.write_address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			break;
	}
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

static int serialize_study_modbus_data(const Packet *p, int template_id, ics_modbus_t *modbus, uint8_t **study_data, int *study_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *study_data_ptr = NULL;

	box = serialize_study_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, MODBUS);
	tlv_box_put_uchar(box, MODBUS_FUNCODE, modbus->funcode);
	switch(modbus->funcode) {
		case 1:
		case 2:
		case 3:
		case 4:
			tlv_box_put_ushort(box, MODBUS_RADDR, modbus->u.addr_quan.address);
			tlv_box_put_ushort(box, MODBUS_RQUANTITY, modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_data.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, (uint16_t)1);
			break;
		case 15:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_quan_data.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.addr_quan_data.quantity);
			break;
		case 16:
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.addr_quan.address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.addr_quan.quantity);
			break;
		case 23:
			tlv_box_put_ushort(box, MODBUS_RADDR, modbus->u.rw_addr_quan.read_address);
			tlv_box_put_ushort(box, MODBUS_RQUANTITY, modbus->u.rw_addr_quan.read_quantity);
			tlv_box_put_ushort(box, MODBUS_WADDR, modbus->u.rw_addr_quan.write_address);
			tlv_box_put_ushort(box, MODBUS_WQUANTITY, modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			break;
	}
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
	tlv_box_put_uchar(box, MODBUS_FUNCODE, modbus->funcode);
	tlv_box_put_ushort(box, MODBUS_RADDR, modbus->address);
	tlv_box_put_ushort(box, MODBUS_RQUANTITY, modbus->quantity);
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

#define DNP3_OBJECT_BUFFER_LENGTH	1024
static int serialize_audit_dnp3_data(const Packet *p, int template_id, ics_dnp3_t *dnp3, uint8_t **audit_data, int *audit_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *audit_data_ptr = NULL;
	MemBuffer *dnp3_object_buffer = NULL;

	box = serialize_audit_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, DNP3);
	tlv_box_put_uchar(box, DNP3_FUNCODE, dnp3->function_code);
	tlv_box_put_uint(box, DNP3_OBJECT_COUNTS, dnp3->object_count);
	if (dnp3->object_count > 0) {
		dnp3_object_buffer = MemBufferCreateNew(DNP3_OBJECT_BUFFER_LENGTH);
		if (dnp3_object_buffer == NULL) {
			SCLogNotice("create DNP3 Object MemBuffer error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
		for (uint32_t i = 0; i < dnp3->object_count; i++) {
			if (MEMBUFFER_OFFSET(dnp3_object_buffer) + sizeof(uint8_t)*2 + sizeof(uint32_t) >= MEMBUFFER_SIZE(dnp3_object_buffer))
				MemBufferExpand(&dnp3_object_buffer, DNP3_OBJECT_BUFFER_LENGTH);
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].group, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].variation, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].point_count, sizeof(uint32_t));
			for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
				if (MEMBUFFER_OFFSET(dnp3_object_buffer) + sizeof(uint32_t)*2 >= MEMBUFFER_SIZE(dnp3_object_buffer))
					MemBufferExpand(&dnp3_object_buffer, DNP3_OBJECT_BUFFER_LENGTH);
				MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].points[j].index, sizeof(uint32_t));
				MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].points[j].size, sizeof(uint32_t));
			}
		}
		tlv_box_put_bytes(box, DNP3_OBJECTS, MEMBUFFER_BUFFER(dnp3_object_buffer), MEMBUFFER_OFFSET(dnp3_object_buffer));
		MemBufferFree(dnp3_object_buffer);
	}
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

static int serialize_study_dnp3_data(const Packet *p, int template_id, ics_dnp3_t *dnp3, uint8_t **study_data, int *study_data_len)
{
	int ret = TM_ECODE_OK;
	tlv_box_t *box = NULL;
	uint8_t *study_data_ptr = NULL;
	MemBuffer *dnp3_object_buffer = NULL;

	box = serialize_study_common_data(p, template_id);
	tlv_box_put_uchar(box, APP_PROTO, DNP3);
	tlv_box_put_uchar(box, DNP3_FUNCODE, dnp3->function_code);
	tlv_box_put_uint(box, DNP3_OBJECT_COUNTS, dnp3->object_count);
	if (dnp3->object_count > 0) {
		dnp3_object_buffer = MemBufferCreateNew(DNP3_OBJECT_BUFFER_LENGTH);
		if (dnp3_object_buffer == NULL) {
			SCLogNotice("create DNP3 Object MemBuffer error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
		for (uint32_t i = 0; i < dnp3->object_count; i++) {
			if (MEMBUFFER_OFFSET(dnp3_object_buffer) + sizeof(uint8_t)*2 + sizeof(uint32_t) >= MEMBUFFER_SIZE(dnp3_object_buffer))
				MemBufferExpand(&dnp3_object_buffer, DNP3_OBJECT_BUFFER_LENGTH);
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].group, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].variation, sizeof(uint8_t));
			MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].point_count, sizeof(uint32_t));
			for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
				if (MEMBUFFER_OFFSET(dnp3_object_buffer) + sizeof(uint32_t)*2 >= MEMBUFFER_SIZE(dnp3_object_buffer))
					MemBufferExpand(&dnp3_object_buffer, DNP3_OBJECT_BUFFER_LENGTH);
				MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].points[j].index, sizeof(uint32_t));
				MemBufferWriteRaw(dnp3_object_buffer, &dnp3->objects[i].points[j].size, sizeof(uint32_t));
			}
		}
		tlv_box_put_bytes(box, DNP3_OBJECTS, MEMBUFFER_BUFFER(dnp3_object_buffer), MEMBUFFER_OFFSET(dnp3_object_buffer));
		MemBufferFree(dnp3_object_buffer);
	}
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
	tlv_box_put_uchar(box, DNP3_FUNCODE, dnp3->funcode);
	tlv_box_put_uchar(box, DNP3_GROUP, dnp3->group);
	tlv_box_put_uchar(box, DNP3_VARIATION, dnp3->variation);
	tlv_box_put_uint(box, DNP3_INDEX, dnp3->index);
	tlv_box_put_uint(box, DNP3_SIZE, dnp3->size);
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

static int create_modbus_audit_data(const Packet *p, ics_modbus_t *modbus, uint8_t **audit_data, int *audit_data_len)
{
	return serialize_audit_modbus_data(p, 0, modbus, audit_data, audit_data_len);
}

static int create_modbus_study_data(const Packet *p, int template_id, ics_modbus_t *modbus, uint8_t **study_data, int *study_data_len)
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

static int create_dnp3_study_data(const Packet *p, int template_id, ics_dnp3_t *dnp3, uint8_t **study_data, int *study_data_len)
{
	return serialize_study_dnp3_data(p, template_id, dnp3, study_data, study_data_len);
}

static int create_dnp3_warning_data(const Packet *p, int template_id, dnp3_ht_item_t *dnp3, uint8_t **warning_data, int *warning_data_len)
{
	return serialize_warning_dnp3_data(p, template_id, dnp3, warning_data, warning_data_len);
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
			ret = create_modbus_audit_data(p, ics_adu->u.modbus, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					ret = create_modbus_study_data(p, ics_adu->template_id, ics_adu->u.modbus, &study_data, &study_data_len);
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
			ret = create_dnp3_audit_data(p, ics_adu->u.dnp3, &audit_data, &audit_data_len);
			if (ret != TM_ECODE_OK)
				goto out;
			ICSSendRedisLog(c, ICS_MODE_NORMAL, audit_data, audit_data_len);
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					ret = create_dnp3_study_data(p, ics_adu->template_id, ics_adu->u.dnp3, &study_data, &study_data_len);
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
			if (p->flowflags & FLOW_PKT_TOSERVER)
				ret = TRUE;
			break;
		case ALPROTO_DNP3:
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
