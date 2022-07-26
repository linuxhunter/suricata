#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "detect-ics.h"
#include "output.h"
#include "output-redis-ics.h"

#include <hiredis/hiredis.h>

#define MODULE_NAME	"ICSRadisLog"
#define REDIS_SERVER_IP	"127.0.0.1"
#define REDIS_SERVER_PORT	6379
#define REDIS_PUBLISH_CMD	"PUBLISH"
#define ICS_AUDIT_CHANNEL	"ChannelICSAudit"
#define ICS_STUDY_CHANNEL	"ChannelICSStudy"
#define ICS_WARN_CHANNEL	"ChannelICSWarn"
#define ICS_AUDIT_DATA_BUF_MAX	256
#define ICS_STUDY_DATA_BUF_MAX	256
#define ICS_WARN_DATA_BUF_MAX	512

typedef enum {
	ICS_AUDIT_DATA,
	ICS_STUDY_DATA,
	ICS_WARN_DATA,
} ics_data_type_t;

int ICSRadisLogger(ThreadVars *t, void *data, const Packet *p);
int ICSRadisLogCondition(ThreadVars *t, void *data, const Packet *p);
TmEcode ICSRadisLogThreadInit(ThreadVars *t, const void *initdata, void **data);
TmEcode ICSRadisLogThreadDeinit(ThreadVars *t, void *data);
void ICSRadisLogRegister(void);

static int ICSSendRedisLog(redisContext *c, ics_data_type_t type, const char *data)
{
	int ret = TM_ECODE_OK;
	redisReply *reply = NULL;

	switch(type) {
		case ICS_AUDIT_DATA:
			reply = redisCommand(c, "%s %s %s", REDIS_PUBLISH_CMD, ICS_AUDIT_CHANNEL, data);
			if (reply == NULL) {
				SCLogNotice("publish %s with data [%s] error.\n", ICS_AUDIT_CHANNEL, data);
				ret = TM_ECODE_FAILED;
				goto out;
			}
			freeReplyObject(reply);
			break;
		case ICS_STUDY_DATA:
			reply = redisCommand(c, "%s %s %s", REDIS_PUBLISH_CMD, ICS_STUDY_CHANNEL, data);
			if (reply == NULL) {
				SCLogNotice("public %s with data [%s] error.\n", ICS_STUDY_CHANNEL, data);
				ret = TM_ECODE_FAILED;
				goto out;
			}
			break;
		case ICS_WARN_DATA:
			reply = redisCommand(c, "%s %s %s", REDIS_PUBLISH_CMD, ICS_WARN_CHANNEL, data);
			if (reply == NULL) {
				SCLogNotice("public %s with data [%s] error.\n", ICS_WARN_CHANNEL, data);
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

static int create_modbus_audit_data(ics_modbus_t *modbus, char *audit_data, size_t audit_data_len)
{
	int len = 0;

	len += snprintf(audit_data + len, audit_data_len - len, "proto = modbus, ");
	switch(modbus->funcode) {
		case 1:
		case 3:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, address = %x, data = %x\n",
				modbus->funcode,
				modbus->u.addr_data.address,
				modbus->u.addr_data.data);
			break;
		case 8:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, subfunction = %u\n",
				modbus->funcode,
				modbus->u.subfunc.subfunction);
			break;
		case 15:
			{
				size_t value_len = 0;
				char data_value[256] = {0};

				for (int i = 0; i < modbus->u.addr_quan_data.data_len; i++) {
					value_len += snprintf(data_value + value_len, sizeof(data_value) - value_len, "%02x", modbus->u.addr_quan_data.data[i]);
				}

				len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, address = %x, quantity = %x, data_len = %d, data = %s",
					modbus->funcode,
					modbus->u.addr_quan_data.address,
					modbus->u.addr_quan_data.quantity,
					modbus->u.addr_quan_data.data_len,
					data_value);
			}
			break;
		case 16:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 22:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, and_mask = %x, or_mask = %x\n",
				modbus->funcode,
				modbus->u.and_or_mask.and_mask,
				modbus->u.and_or_mask.or_mask);
			break;
		case 23:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u, read_address = %x, read_quantity = %x, write_address = %x, write_quantity = %x\n",
				modbus->funcode,
				modbus->u.rw_addr_quan.read_address,
				modbus->u.rw_addr_quan.read_quantity,
				modbus->u.rw_addr_quan.write_address,
				modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			len += snprintf(audit_data + len, audit_data_len - len, "funcode = %u\n", modbus->funcode);
			break;
	}
	return TM_ECODE_OK;
}

static int create_modbus_study_data(const char *template_name, ics_modbus_t *modbus, char *study_data, size_t study_data_len)
{
	int len = 0;

	len += snprintf(study_data + len, study_data_len - len, "template = %s, proto = modbus, ", template_name);
	switch(modbus->funcode) {
		case 1:
		case 3:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, address = %x, data = %x\n",
				modbus->funcode,
				modbus->u.addr_data.address,
				modbus->u.addr_data.data);
			break;
		case 8:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, subfunction = %u\n",
				modbus->funcode,
				modbus->u.subfunc.subfunction);
			break;
		case 15:
			{
				size_t value_len = 0;
				char data_value[256] = {0};

				for (int i = 0; i < modbus->u.addr_quan_data.data_len; i++) {
					value_len += snprintf(data_value + value_len, sizeof(data_value) - value_len, "%02x", modbus->u.addr_quan_data.data[i]);
				}

				len += snprintf(study_data + len, study_data_len - len, "funcode = %u, address = %x, quantity = %x, data_len = %d, data = %s",
					modbus->funcode,
					modbus->u.addr_quan_data.address,
					modbus->u.addr_quan_data.quantity,
					modbus->u.addr_quan_data.data_len,
					data_value);
			}
			break;
		case 16:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 22:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, and_mask = %x, or_mask = %x\n",
				modbus->funcode,
				modbus->u.and_or_mask.and_mask,
				modbus->u.and_or_mask.or_mask);
			break;
		case 23:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u, read_address = %x, read_quantity = %x, write_address = %x, write_quantity = %x\n",
				modbus->funcode,
				modbus->u.rw_addr_quan.read_address,
				modbus->u.rw_addr_quan.read_quantity,
				modbus->u.rw_addr_quan.write_address,
				modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			len += snprintf(study_data + len, study_data_len - len, "funcode = %u\n", modbus->funcode);
			break;
	}
	return TM_ECODE_OK;
}

static int create_modbus_warning_data(const char *template_name, ics_modbus_t *modbus, char *warning_data, size_t warning_data_len)
{
	int len = 0;

	len += snprintf(warning_data + len, warning_data_len - len, "template = %s, proto = modbus, ", template_name);
	return TM_ECODE_OK;
}

static int create_dnp3_audit_data(ics_dnp3_t *dnp3, char *audit_data, size_t audit_data_len)
{
	int len = 0;

	len += snprintf(audit_data + len, audit_data_len - len, "proto = dnp3, ");
	len += snprintf(audit_data + len, audit_data_len - len, "funcode = 0x%hhx, ", dnp3->function_code);
	for (uint32_t i = 0; i < dnp3->object_count; i++) {
		len += snprintf(audit_data + len, audit_data_len - len, "obj[%u]: group = 0x%hhx, variation = 0x%hhx, ", i, dnp3->objects[i].group, dnp3->objects[i].variation);
		for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
			len += snprintf(audit_data + len, audit_data_len - len, "point[%u]: index = 0x%x, size = 0x%x, ", j, dnp3->objects[i].points[j].index, dnp3->objects[i].points[j].size);
		}
		len -= 2;
		len += snprintf(audit_data + len, audit_data_len - len , "\n");
	}
	return TM_ECODE_OK;
}

static int create_dnp3_study_data(const char *template_name, ics_dnp3_t *dnp3, char *study_data, size_t study_data_len)
{
	int len = 0;

	len += snprintf(study_data + len, study_data_len - len, "template = %s, proto = dnp3, ", template_name);
	len += snprintf(study_data + len, study_data_len - len, "funcode = 0x%hhx, ", dnp3->function_code);
	for (uint32_t i = 0; i < dnp3->object_count; i++) {
		len += snprintf(study_data + len, study_data_len - len, "obj[%u]: group = 0x%hhx, variation = 0x%hhx, ", i, dnp3->objects[i].group, dnp3->objects[i].variation);
		for (uint32_t j = 0; j < dnp3->objects[i].point_count; j++) {
			len += snprintf(study_data + len, study_data_len - len, "point[%u]: index = 0x%x, size = 0x%x, ", j, dnp3->objects[i].points[j].index, dnp3->objects[i].points[j].size);
		}
		len -= 2;
		len += snprintf(study_data + len, study_data_len - len , "\n");
	}
	return TM_ECODE_OK;
}

static int create_dnp3_warning_data(const char *template_name, ics_dnp3_t *dnp3, char *warning_data, size_t warning_data_len)
{
	int len = 0;

	len += snprintf(warning_data + len, warning_data_len - len, "template = %s, proto = dnp3, ", template_name);
	return TM_ECODE_OK;
}

int ICSRadisLogger(ThreadVars *t, void *data, const Packet *p)
{
	redisContext *c = (redisContext *)data;
	ics_adu_t *ics_adu = NULL;
	char audit_data[ICS_AUDIT_DATA_BUF_MAX] = {0};
	char study_data[ICS_STUDY_DATA_BUF_MAX] = {0};
	char warning_data[ICS_WARN_DATA_BUF_MAX] = {0};

	if (p->flow == NULL || p->flow->ics_adu == NULL)
		goto out;

	ics_adu = p->flow->ics_adu;
	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			create_modbus_audit_data(&ics_adu->u.modbus[ICS_ADU_REAL_INDEX], audit_data, sizeof(audit_data));
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					create_modbus_study_data(ics_adu->template_name, &ics_adu->u.modbus[ICS_ADU_REAL_INDEX], study_data, sizeof(study_data));
					ICSSendRedisLog(c, ICS_STUDY_DATA, study_data);
					break;
				case ICS_MODE_WARNING:
					create_modbus_warning_data(ics_adu->template_name, ics_adu->u.modbus, warning_data, sizeof(warning_data));
					ICSSendRedisLog(c, ICS_WARN_DATA, warning_data);
					break;
				default:
					break;
			}
			break;
		case ALPROTO_DNP3:
			create_dnp3_audit_data(&ics_adu->u.dnp3[ICS_ADU_REAL_INDEX], audit_data, sizeof(audit_data));
			switch(ics_adu->work_mode) {
				case ICS_MODE_STUDY:
					create_dnp3_study_data(ics_adu->template_name, &ics_adu->u.dnp3[ICS_ADU_REAL_INDEX], study_data, sizeof(study_data));
					ICSSendRedisLog(c, ICS_STUDY_DATA, study_data);
					break;
				case ICS_MODE_WARNING:
					create_dnp3_warning_data(ics_adu->template_name, ics_adu->u.dnp3, warning_data, sizeof(warning_data));
					ICSSendRedisLog(c, ICS_WARN_DATA, warning_data);
					break;
				default:
					break;
			}
			break;
		default:
			goto out;
	}
	ICSSendRedisLog(c, ICS_AUDIT_DATA, audit_data);
out:
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
