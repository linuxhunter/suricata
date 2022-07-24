#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "util-debug.h"
#include "output.h"
#include "output-redis-ics.h"

#include "app-layer-parser.h"
#include "app-layer-modbus.h"

#include <hiredis/hiredis.h>

#define MODULE_NAME	"ICSRadisLog"
#define REDIS_SERVER_IP	"127.0.0.1"
#define REDIS_SERVER_PORT	6379
#define REDIS_PUBLISH_CMD	"PUBLISH"
#define ICS_AUDIT_CHANNEL	"ChannelICSAudit"
#define ICS_STUDY_CHANNEL	"ChannelICSStudy"
#define ICS_WARN_CHANNEL	"ChannelICSWarn"

typedef enum {
	ICS_AUDIT_DATA,
	ICS_STUDY_DATA,
	ICS_WARN_DATA,
} ics_data_type_t;

#define MODBUS_DATA_LEN_MAX	64
typedef struct {
	uint8_t funcode;
	union {
		struct addr_quan {
			uint16_t address;
			uint16_t quantity;
		} addr_quan;
		struct addr_data {
			uint16_t address;
			uint16_t data;
		} addr_data;
		struct subfunc {
			uint16_t subfunction;
		} subfunc;
		struct addr_quan_data {
			uint16_t address;
			uint16_t quantity;
			uint8_t data_len;
			uint8_t data[MODBUS_DATA_LEN_MAX];
		} addr_quan_data;
		struct and_or_mask {
			uint16_t and_mask;
			uint16_t or_mask;
		} and_or_mask;
		struct rw_addr_quan {
			uint16_t read_address;
			uint16_t read_quantity;
			uint16_t write_address;
			uint16_t write_quantity;
		} rw_addr_quan;
	}u;
} ics_modbus_t;

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

static int get_modbus_adu(Flow *p, ics_modbus_t *ics_modbus)
{
	int ret = TM_ECODE_OK;
	ModbusState *modbus_state = p->alstate;
	ModbusMessage request;
	int tx_counts = 0;
	uint8_t funcode;

	if (modbus_state == NULL) {
		SCLogNotice("Modbus State is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}

	tx_counts = rs_modbus_state_get_tx_count(modbus_state);
	request = rs_modbus_state_get_tx_request(modbus_state, (tx_counts-1));
	if (request._0 == NULL) {
		SCLogNotice("Modbus Request is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}

	funcode = rs_modbus_message_get_function(&request);
	switch(funcode) {
		case 1:
		case 3:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_quan.address = rs_modbus_message_get_read_request_address(&request);
			ics_modbus->u.addr_quan.quantity = rs_modbus_message_get_read_request_quantity(&request);
			break;
		case 5:
		case 6:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_data.address = rs_modbus_message_get_write_address(&request);
			ics_modbus->u.addr_data.data = rs_modbus_message_get_write_data(&request);
			break;
		case 8:
			ics_modbus->funcode = funcode;
			ics_modbus->u.subfunc.subfunction = rs_modbus_message_get_subfunction(&request);
			break;
		case 15:
			{
				size_t data_len;
				const uint8_t *data = rs_modbus_message_get_write_multreq_data(&request, &data_len);
				ics_modbus->funcode = funcode;
				ics_modbus->u.addr_quan_data.address = rs_modbus_message_get_write_multreq_address(&request);
				ics_modbus->u.addr_quan_data.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
				ics_modbus->u.addr_quan_data.data_len = data_len;
				memcpy(&ics_modbus->u.addr_quan_data.data, data, sizeof(ics_modbus->u.addr_quan_data.data));
			}
			break;
		case 16:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_quan.address = rs_modbus_message_get_write_multreq_address(&request);
			ics_modbus->u.addr_quan.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
			break;
		case 22:
			ics_modbus->funcode = funcode;
			ics_modbus->u.and_or_mask.and_mask = rs_modbus_message_get_and_mask(&request);
			ics_modbus->u.and_or_mask.or_mask = rs_modbus_message_get_or_mask(&request);
			break;
		case 23:
			ics_modbus->funcode = funcode;
			ics_modbus->u.rw_addr_quan.read_address = rs_modbus_message_get_rw_multreq_read_address(&request);
			ics_modbus->u.rw_addr_quan.read_quantity = rs_modbus_message_get_rw_multreq_read_quantity(&request);
			ics_modbus->u.rw_addr_quan.write_address = rs_modbus_message_get_rw_multreq_write_address(&request);
			ics_modbus->u.rw_addr_quan.write_quantity = rs_modbus_message_get_rw_multreq_write_quantity(&request);
			break;
		default:
			ics_modbus->funcode = funcode;
			break;
	}
out:
	return ret;
}

static int create_modbus_audit_data(ics_modbus_t *modbus, char *audit_data, size_t audit_data_len)
{
	switch(modbus->funcode) {
		case 1:
		case 3:
			snprintf(audit_data, audit_data_len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 5:
		case 6:
			snprintf(audit_data, audit_data_len, "funcode = %u, address = %x, data = %x\n",
				modbus->funcode,
				modbus->u.addr_data.address,
				modbus->u.addr_data.data);
			break;
		case 8:
			snprintf(audit_data, audit_data_len, "funcode = %u, subfunction = %u\n",
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

				snprintf(audit_data, audit_data_len, "funcode = %u, address = %x, quantity = %x, data_len = %d, data = %s",
					modbus->funcode,
					modbus->u.addr_quan_data.address,
					modbus->u.addr_quan_data.quantity,
					modbus->u.addr_quan_data.data_len,
					data_value);
			}
			break;
		case 16:
			snprintf(audit_data, audit_data_len, "funcode = %u, address = %x, quantity = %x\n",
				modbus->funcode,
				modbus->u.addr_quan.address,
				modbus->u.addr_quan.quantity);
			break;
		case 22:
			snprintf(audit_data, audit_data_len, "funcode = %u, and_mask = %x, or_mask = %x\n",
				modbus->funcode,
				modbus->u.and_or_mask.and_mask,
				modbus->u.and_or_mask.or_mask);
			break;
		case 23:
			snprintf(audit_data, audit_data_len, "funcode = %u, read_address = %x, read_quantity = %x, write_address = %x, write_quantity = %x\n",
				modbus->funcode,
				modbus->u.rw_addr_quan.read_address,
				modbus->u.rw_addr_quan.read_quantity,
				modbus->u.rw_addr_quan.write_address,
				modbus->u.rw_addr_quan.write_quantity);
			break;
		default:
			snprintf(audit_data, audit_data_len, "funcode = %u\n", modbus->funcode);
			break;
	}
	return TM_ECODE_OK;
}

int ICSRadisLogger(ThreadVars *t, void *data, const Packet *p)
{
	redisContext *c = (redisContext *)data;
	char audit_data[256] = {0};
	ics_modbus_t modbus;

	switch(p->flow->alproto) {
		case ALPROTO_MODBUS:
			{
				memset(&modbus, 0x00, sizeof(modbus));
				if (get_modbus_adu(p->flow, &modbus) != TM_ECODE_OK) {
					SCLogNotice("get modbus adu error.\n");
					goto out;
				}
				create_modbus_audit_data(&modbus, audit_data, sizeof(audit_data));
			}
			break;
		default:
			goto out;
	}
	ICSSendRedisLog(c, ICS_AUDIT_DATA, audit_data);
	//ICSSendRedisLog(c, ICS_STUDY_DATA, "ics study data!!!\n");
	//ICSSendRedisLog(c, ICS_WARN_DATA, "ics warn data!!!\n");
out:
	return TM_ECODE_OK;
}

int ICSRadisLogCondition(ThreadVars *t, void *data, const Packet *p)
{
	return (p->flow->alproto == ALPROTO_MODBUS) ? TRUE : FALSE;
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
