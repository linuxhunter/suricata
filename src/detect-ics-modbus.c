#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "decode.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-modbus.h"

#include "detect-ics-modbus.h"

static modbus_ht_item_t* alloc_modbus_ht_item(uint32_t sip, uint32_t dip, uint8_t proto, uint8_t funcode, uint32_t address, uint32_t quantity)
{
	modbus_ht_item_t *modbus_item = NULL;

	if ((modbus_item = SCMalloc(sizeof(modbus_ht_item_t))) == NULL)
		goto out;
	modbus_item->sip = sip;
	modbus_item->dip = dip;
	modbus_item->proto = proto;
	modbus_item->funcode = funcode;
	modbus_item->address = address;
	modbus_item->quantity = quantity;
out:
	return modbus_item;
}

static void free_modbus_ht_item(modbus_ht_item_t *modbus_item)
{
	if (modbus_item != NULL)
		SCFree(modbus_item);
	return;
}

int detect_get_modbus_audit_data(Packet *p, ics_modbus_t *audit_modbus)
{
	int ret = TM_ECODE_OK;
	ModbusState *modbus_state = p->flow->alstate;
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
		case 2:
		case 3:
		case 4:
			audit_modbus->funcode = funcode;
			audit_modbus->u.addr_quan.address = rs_modbus_message_get_read_request_address(&request);
			audit_modbus->u.addr_quan.quantity = rs_modbus_message_get_read_request_quantity(&request);
			break;
		case 5:
		case 6:
			audit_modbus->funcode = funcode;
			audit_modbus->u.addr_data.address = rs_modbus_message_get_write_address(&request);
			audit_modbus->u.addr_data.data = rs_modbus_message_get_write_data(&request);
			break;
		case 8:
			audit_modbus->funcode = funcode;
			audit_modbus->u.subfunc.subfunction = rs_modbus_message_get_subfunction(&request);
			goto out;
		case 15:
			{
				size_t data_len;
				const uint8_t *data = rs_modbus_message_get_write_multreq_data(&request, &data_len);
				audit_modbus->funcode = funcode;
				audit_modbus->u.addr_quan_data.address = rs_modbus_message_get_write_multreq_address(&request);
				audit_modbus->u.addr_quan_data.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
				audit_modbus->u.addr_quan_data.data_len = data_len;
				memcpy(&audit_modbus->u.addr_quan_data.data, data, sizeof(audit_modbus->u.addr_quan_data.data));
			}
			break;
		case 16:
			audit_modbus->funcode = funcode;
			audit_modbus->u.addr_quan.address = rs_modbus_message_get_write_multreq_address(&request);
			audit_modbus->u.addr_quan.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
			break;
		case 22:
			audit_modbus->funcode = funcode;
			audit_modbus->u.and_or_mask.and_mask = rs_modbus_message_get_and_mask(&request);
			audit_modbus->u.and_or_mask.or_mask = rs_modbus_message_get_or_mask(&request);
			goto out;
		case 23:
			audit_modbus->funcode = funcode;
			audit_modbus->u.rw_addr_quan.read_address = rs_modbus_message_get_rw_multreq_read_address(&request);
			audit_modbus->u.rw_addr_quan.read_quantity = rs_modbus_message_get_rw_multreq_read_quantity(&request);
			audit_modbus->u.rw_addr_quan.write_address = rs_modbus_message_get_rw_multreq_write_address(&request);
			audit_modbus->u.rw_addr_quan.write_quantity = rs_modbus_message_get_rw_multreq_write_quantity(&request);
			break;
		default:
			audit_modbus->funcode = funcode;
			goto out;
	}
out:
	return ret;
}

int detect_get_modbus_study_data(Packet *p, ics_modbus_t *audit_modbus, modbus_ht_item_t *study_modbus)
{
	int ret = 0;

	study_modbus->sip = GET_IPV4_SRC_ADDR_U32(p);
	study_modbus->dip = GET_IPV4_DST_ADDR_U32(p);
	study_modbus->proto = IP_GET_IPPROTO(p);
	study_modbus->funcode = audit_modbus->funcode;
	switch(audit_modbus->funcode) {
		case 1:
		case 2:
		case 3:
		case 4:
			study_modbus->address = audit_modbus->u.addr_quan.address;
			study_modbus->quantity = audit_modbus->u.addr_quan.quantity;
			break;
		case 5:
		case 6:
			study_modbus->address = audit_modbus->u.addr_data.address;
			study_modbus->quantity = 1;
			break;
		case 15:
			study_modbus->address = audit_modbus->u.addr_quan_data.address;
			study_modbus->quantity = audit_modbus->u.addr_quan_data.quantity;
			break;
		case 16:
			study_modbus->address = audit_modbus->u.addr_quan.address;
			study_modbus->quantity = audit_modbus->u.addr_quan.quantity;
			break;
		case 23:
			study_modbus->address = (audit_modbus->u.rw_addr_quan.write_address << 16) + audit_modbus->u.rw_addr_quan.read_address;
			study_modbus->quantity = (audit_modbus->u.rw_addr_quan.write_quantity << 16) + audit_modbus->u.rw_addr_quan.read_quantity;
			break;
		default:
			ret = -1;
			goto out;
	}
out:
	return ret;
}

static uint32_t ics_modbus_hashfunc(HashTable *ht, void *data, uint16_t datalen)
{
	return HashTableGenericHash(ht, data, datalen);
}

static char ics_modbus_hash_comparefunc(void *data1, uint16_t datalen1,
							  void *data2, uint16_t datalen2)
{
	char ret = 0;
	modbus_ht_item_t *item1 = (modbus_ht_item_t *)data1;
	modbus_ht_item_t *item2 = (modbus_ht_item_t *)data2;

	if (item1 == NULL || item2 == NULL)
		goto out;
	if (item1->sip == item2->sip &&
		item1->dip == item2->dip &&
		item1->proto == item2->proto &&
		item1->funcode == item2->funcode &&
		item1->address == item2->address &&
		item1->quantity == item2->quantity) {
		ret = 1;
		goto out;
	}
out:
	return ret;
}

static void ics_modbus_hashfree(void *data)
{
	free_modbus_ht_item(data);
}

static int add_modbus_ht_item(HashTable *ht, modbus_ht_item_t *modbus_item)
{
	int ret = TM_ECODE_OK;
	modbus_ht_item_t *modbus_lookup = NULL;

	modbus_lookup = HashTableLookup(ht, modbus_item, 0);
	if (modbus_lookup == NULL) {
		if (HashTableAdd(ht, modbus_item, 0) < 0) {
			SCLogNotice("add modbus hashtable item error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
	} else {
		SCLogNotice("Duplicate modbus hashtable item.\n");
		free_modbus_ht_item(modbus_item);
	}
out:
	return ret;
}

int init_modbus_hashtable(HashTable **ht, uint32_t size)
{
	*ht = HashTableInit(size, ics_modbus_hashfunc, ics_modbus_hash_comparefunc, ics_modbus_hashfree);
	if (*ht != NULL)
		return TM_ECODE_OK;
	else
		return TM_ECODE_FAILED;
}

int create_modbus_hashtable(HashTable *ht, intmax_t template_id)
{
	int status = 0, len;
    modbus_ht_item_t *modbus_item = NULL;
    sql_handle handle = NULL;
    char query[SQL_QUERY_SIZE] = {0};
	MYSQL_RES *results=NULL;
	MYSQL_ROW record;
	uint32_t sip, dip;
	uint8_t proto, funcode;
	uint32_t address, quantity;

    if ((handle = sql_db_connect(DB_NAME)) == NULL) {
        SCLogNotice("connect database study_modbus_table error.\n");
        goto out;
    }
    len = snprintf(query, sizeof(query), "select src_ip,dst_ip,proto,funcode,address,quantity from study_modbus_table where template_id='%ld';", template_id);

	status = sql_real_query(handle, query, len);
	if (status != 0) {
		SCLogNotice("query modbus whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	results = mysql_use_result(handle);
	if (results == NULL) {
		SCLogNotice("get modbus whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	while((record = mysql_fetch_row(results))) {
		sip = strtoul(record[0], NULL, 10);
		dip = strtoul(record[1], NULL, 10);
		proto = strtoul(record[2], NULL, 10);
		funcode = strtoul(record[3], NULL, 10);
		address = strtoul(record[4], NULL, 10);
		quantity = strtoul(record[5], NULL, 10);
		if ((modbus_item = alloc_modbus_ht_item(sip, dip, proto, funcode, address, quantity)) == NULL) {
            SCLogNotice("Alloc Modbus Item error.\n");
            goto out;
		}
		if (add_modbus_ht_item(ht, modbus_item) != TM_ECODE_OK) {
            SCLogNotice("Insert Modbus Item to HashTable error.\n");
            goto out;
		}
	}
out:
    if (handle)
        sql_db_disconnect(handle);
    return 0;
}

int detect_get_modbus_warning_data(HashTable *ht, Packet *p, ics_modbus_t *audit_modbus, modbus_ht_item_t *warning_modbus)
{
       int matched = 0;
       uint32_t sip, dip;
       uint8_t proto, funcode;
       uint32_t address = 0, quantity = 0;
       modbus_ht_item_t *modbus_item = NULL;

	   sip = GET_IPV4_SRC_ADDR_U32(p);
	   dip = GET_IPV4_DST_ADDR_U32(p);
	   proto = IP_GET_IPPROTO(p);
	   funcode = audit_modbus->funcode;
	   switch(funcode) {
		   case 1:
		   case 2:
		   case 3:
		   case 4:
			   address = audit_modbus->u.addr_quan.address;
			   quantity = audit_modbus->u.addr_quan.quantity;
			   break;
		   case 5:
		   case 6:
			   address = audit_modbus->u.addr_data.address;
			   quantity = 1;
			   break;
		   case 15:
			   address = audit_modbus->u.addr_quan_data.address;
			   quantity = audit_modbus->u.addr_quan_data.quantity;
			   break;
		   case 16:
			   address = audit_modbus->u.addr_quan.address;
			   quantity = audit_modbus->u.addr_quan.quantity;
			   break;
		   case 23:
			   address = (audit_modbus->u.rw_addr_quan.write_address << 16) + audit_modbus->u.rw_addr_quan.read_address;
			   quantity = (audit_modbus->u.rw_addr_quan.write_quantity << 16) + audit_modbus->u.rw_addr_quan.read_quantity;
			   break;
		   default:
			   matched = 1;
			   goto out;
	   }
	   if ((modbus_item = alloc_modbus_ht_item(sip, dip, proto, funcode, address, quantity)) == NULL) {
		   matched = 1;
		   goto out;
	   }

	   if (HashTableLookup(ht, modbus_item, 0) == NULL) {
		   memcpy(warning_modbus, modbus_item, sizeof(modbus_ht_item_t));
	   } else {
		   matched = 1;
	   }
out:
	   if (modbus_item)
		   SCFree(modbus_item);
	   return matched;
}

