#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-enip-common.h"
#include "app-layer-enip.h"

#include "detect-ics-enip.h"

static void *ENIPGetTx(void *alstate, uint64_t tx_id)
{
	ENIPState         *enip = (ENIPState *) alstate;
	ENIPTransaction   *tx = NULL;

	if (enip->curr && enip->curr->tx_num == tx_id + 1)
		return enip->curr;

	TAILQ_FOREACH(tx, &enip->tx_list, next) {
		if (tx->tx_num != (tx_id+1))
			continue;

		SCLogDebug("returning tx %p", tx);
		return tx;
	}

	return NULL;
}

static uint64_t ENIPGetTxCnt(void *alstate)
{
	return ((ENIPState *)alstate)->transaction_max;
}

static enip_ht_item_t* alloc_enip_ht_item(uint32_t sip, uint32_t dip ,uint8_t proto,
	uint16_t command, uint32_t session, uint32_t conn_id, uint8_t service, uint8_t class)
{
	enip_ht_item_t *enip_item = NULL;

	if ((enip_item = SCMalloc(sizeof(enip_ht_item_t))) == NULL) {
		goto out;
	}
	enip_item->sip = sip;
	enip_item->dip = dip;
	enip_item->proto = proto;
	enip_item->command = command;
	enip_item->session = session;
	enip_item->conn_id = conn_id;
	enip_item->service = service;
	enip_item->class = class;
out:
	return enip_item;
}

static void free_enip_ht_item(enip_ht_item_t *enip_item)
{
	if (enip_item)
		SCFree(enip_item);
	return;
}

static uint32_t ics_enip_hashfunc(HashTable *ht, void *data, uint16_t datalen)
{
	return HashTableGenericHash(ht, data, datalen);
}

static char ics_enip_hash_comparefunc(void *data1, uint16_t data1_len,
	void *data2, uint16_t data2_len)
{
	char ret = 0;
	enip_ht_item_t *item1 = (enip_ht_item_t *)data1;
	enip_ht_item_t *item2 = (enip_ht_item_t *)data2;

	if (item1 == NULL || item2 == NULL)
		goto out;
	if (item1->sip == item2->sip &&
		item1->dip == item2->dip &&
		item1->proto == item2->proto &&
		item1->command == item2->command &&
		item1->session == item2->session &&
		item1->conn_id == item2->conn_id &&
		item1->service == item2->service &&
		item1->class == item2->class) {
		ret = 1;
		goto out;
	}
out:
	return ret;
}

static void ics_enip_hashfree(void *data)
{
	free_enip_ht_item(data);
}

static int add_enip_ht_item(HashTable *ht, enip_ht_item_t *enip_item)
{
    int ret = TM_ECODE_OK;

    if (HashTableLookup(ht, enip_item, 0) == NULL) {
        if (HashTableAdd(ht, enip_item, 0) < 0) {
            SCLogNotice("add ENIP hashtable item error.\n");
            ret = TM_ECODE_FAILED;
            goto out;
        }
    } else {
        SCLogNotice("Duplicate ENIP hashtable item.\n");
        free_enip_ht_item(enip_item);
    }
out:
    return ret;
}

int init_enip_hashtable(HashTable **ht, uint32_t size)
{
    *ht = HashTableInit(size, ics_enip_hashfunc, ics_enip_hash_comparefunc, ics_enip_hashfree);
    if (*ht != NULL)
        return TM_ECODE_OK;
    else
        return TM_ECODE_FAILED;
}

int create_enip_hashtable(HashTable *ht, intmax_t template_id)
{
	int status = 0, len;
	enip_ht_item_t *enip_item = NULL;
	sql_handle handle = NULL;
	char query[SQL_QUERY_SIZE] = {0};
	MYSQL_RES *results=NULL;
	MYSQL_ROW record;
	uint32_t sip, dip, session, conn_id;
	uint8_t proto, service, class;
	uint16_t command;

	if ((handle = sql_db_connect(DB_NAME)) == NULL) {
		SCLogNotice("connect database study_modbus_table error.\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "select src_ip,dst_ip,proto,command,session,conn_id,service,class from study_enip_table where template_id='%ld';", template_id);

	status = sql_real_query(handle, query, len);
	if (status != 0) {
		SCLogNotice("query enip whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	results = mysql_use_result(handle);
	if (results == NULL) {
		SCLogNotice("get enip whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	while((record = mysql_fetch_row(results))) {
		sip = strtoul(record[0], NULL, 10);
		dip = strtoul(record[1], NULL, 10);
		proto = strtoul(record[2], NULL, 10);
		command = strtoul(record[3], NULL, 10);
		session = strtoul(record[4], NULL, 10);
		conn_id = strtoul(record[5], NULL, 10);
		service = strtoul(record[6], NULL, 10);
		class = strtoul(record[7], NULL, 10);

		if ((enip_item = alloc_enip_ht_item(sip, dip, proto, command, session, conn_id, service, class)) == NULL) {
			SCLogNotice("Alloc ENIP Item error.\n");
			goto out;
		}
		if (add_enip_ht_item(ht, enip_item) != TM_ECODE_OK) {
			SCLogNotice("Insert ENIP Item to HashTable error.\n");
			goto out;
		}
		SCLogNotice("sip = %u, dip = %u, proto = %u, command = %u, session = %u, conn_id = %u, service = %u, class = %u\n",
			sip, dip, proto, command, session, conn_id, service, class);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return 0;
}

int detect_get_enip_audit_data(Packet *p, ics_enip_t *ics_enip)
{
	int ret = TM_ECODE_OK;
	uint64_t tx_count = 0;
	ENIPState *enip_state = p->flow->alstate;
	ENIPTransaction *tx = NULL;
	
	if (enip_state == NULL) {
		SCLogNotice("ENIP State is NULL");
		ret = TM_ECODE_FAILED;
		goto out;
	}

	tx_count = ENIPGetTxCnt((void *)enip_state);
	if (tx_count > 0) {
		uint16_t index = 0;
		uint8_t service_count = 0;
		CIPServiceEntry *svc = NULL;
		SegmentEntry *seg = NULL;

		for (uint64_t curr_tx = 0; curr_tx < tx_count; curr_tx++) {
			tx = ENIPGetTx(enip_state, curr_tx);
			if (tx == NULL) {
				continue;
			}
			ics_enip->enip_services[index].command = tx->header.command;
			ics_enip->enip_services[index].session = tx->header.session;
			ics_enip->enip_services[index].conn_id = tx->encap_addr_item.conn_id;
			service_count = 0;
			TAILQ_FOREACH(svc, &tx->service_list, next)
			{
				ics_enip->enip_services[index].cip_services[service_count].service = svc->service;
				TAILQ_FOREACH(seg, &svc->segment_list, next) {
					if (seg->segment == PATH_CLASS_8BIT ||
						seg->segment == PATH_ATTR_8BIT ||
						seg->segment == PATH_CLASS_16BIT)
						ics_enip->enip_services[index].cip_services[service_count].class = seg->value;
					else
						ics_enip->enip_services[index].cip_services[service_count].instance = seg->value;
				}
				service_count++;
    		}
			ics_enip->enip_services[index].cip_service_count = service_count;
			index++;
		}
		ics_enip->enip_service_count = index;
	}
out:
	return ret;
}

int detect_get_enip_study_data(Packet *p, ics_enip_t *audit_enip, enip_ht_items_t *study_enip)
{
	int ret = 0;
	uint32_t sip, dip, total_count = 0, study_enip_index = 0;
	uint8_t proto;
	uint16_t enip_index;
	uint8_t cip_index;

	sip = GET_IPV4_SRC_ADDR_U32(p);
	dip = GET_IPV4_DST_ADDR_U32(p);
	proto = IP_GET_IPPROTO(p);

	for (enip_index = 0; enip_index < audit_enip->enip_service_count; enip_index++) {
		if (audit_enip->enip_services[enip_index].cip_service_count > 0) {
			for (cip_index = 0; cip_index < audit_enip->enip_services[enip_index].cip_service_count; cip_index++) {
				total_count++;
			}
		} else {
			total_count++;
		}
	}
	study_enip->enip_ht_count = total_count;
	if ((study_enip->items = SCMalloc(sizeof(enip_ht_item_t)*total_count)) == NULL) {
		ret = -1;
		goto out;
	}
	memset(study_enip->items, 0x00, sizeof(enip_ht_item_t)*total_count);
	for (enip_index = 0; enip_index < audit_enip->enip_service_count; enip_index++) {
		if (audit_enip->enip_services[enip_index].cip_service_count > 0) {
			for (cip_index = 0; cip_index < audit_enip->enip_services[enip_index].cip_service_count; cip_index++) {
				study_enip->items[study_enip_index].sip = sip;
				study_enip->items[study_enip_index].dip = dip;
				study_enip->items[study_enip_index].proto = proto;
				study_enip->items[study_enip_index].command = audit_enip->enip_services[enip_index].command;
				study_enip->items[study_enip_index].session = audit_enip->enip_services[enip_index].session;
				study_enip->items[study_enip_index].conn_id = audit_enip->enip_services[enip_index].conn_id;
				study_enip->items[study_enip_index].service = audit_enip->enip_services[enip_index].cip_services[cip_index].service;
				study_enip->items[study_enip_index].class = audit_enip->enip_services[enip_index].cip_services[cip_index].class;
				study_enip_index++;
			}
		} else {
			study_enip->items[study_enip_index].sip = sip;
			study_enip->items[study_enip_index].dip = dip;
			study_enip->items[study_enip_index].proto = proto;
			study_enip->items[study_enip_index].command = audit_enip->enip_services[enip_index].command;
			study_enip->items[study_enip_index].session = audit_enip->enip_services[enip_index].session;
			study_enip->items[study_enip_index].conn_id = audit_enip->enip_services[enip_index].conn_id;
			study_enip->items[study_enip_index].service = 0;
			study_enip->items[study_enip_index].class = 0;
			study_enip_index++;
		}
	}
out:
	return ret;
}

static int __match_enip_ht_item(HashTable *ht, enip_ht_item_t *enip_item)
{
    int matched = 0;

    if (HashTableLookup(ht, enip_item, 0) == NULL) {
        matched = 0;
    } else {
        matched = 1;
    }
    return matched;
}

int detect_get_enip_warning_data(HashTable *ht, Packet *p, ics_enip_t *audit_enip, enip_ht_item_t *warning_enip)
{
	int matched = 0;
	uint32_t sip, dip, session, conn_id;
	uint8_t proto, service, class;
	uint16_t command;
	enip_ht_item_t *enip_item = NULL;

	sip = GET_IPV4_SRC_ADDR_U32(p);
	dip = GET_IPV4_DST_ADDR_U32(p);
	proto = IP_GET_IPPROTO(p);
	for (uint32_t i = 0; i < audit_enip->enip_service_count; i++) {
		command = audit_enip->enip_services[i].command;
		session = audit_enip->enip_services[i].session;
		conn_id = audit_enip->enip_services[i].conn_id;
		if (audit_enip->enip_services[i].cip_service_count > 0) {
			for (uint8_t j = 0; j < audit_enip->enip_services[i].cip_service_count; j++) {
				service = audit_enip->enip_services[i].cip_services[j].service;
				class = audit_enip->enip_services[i].cip_services[j].class;
				if ((enip_item = alloc_enip_ht_item(sip, dip, proto, command, session, conn_id, service, class)) == NULL) {
					matched = 1;
					goto out;
				}
				if (__match_enip_ht_item(ht, enip_item) == 0) {
					memcpy(warning_enip, enip_item, sizeof(enip_ht_item_t));
					goto out;
				}
			}
		} else {
			service = 0;
			class = 0;
			if ((enip_item = alloc_enip_ht_item(sip, dip, proto, command, session, conn_id, service, class)) == NULL) {
				matched = 1;
				goto out;
			}
			if (__match_enip_ht_item(ht, enip_item) == 0) {
				memcpy(warning_enip, enip_item, sizeof(enip_ht_item_t));
				goto out;
			}
		}
	}
	matched = 1;
out:
	if (enip_item) {
		free_enip_ht_item(enip_item);
	}
	return matched;
}

void display_enip_audit_data(ics_enip_t *ics_enip)
{
	for (uint16_t i = 0; i < ics_enip->enip_service_count; i++) {
		SCLogNotice("---------------------------------------------");
		SCLogNotice("command = 0x%x", ics_enip->enip_services[i].command);
		SCLogNotice("session = 0x%x", ics_enip->enip_services[i].session);
		SCLogNotice("conn_id = 0x%x", ics_enip->enip_services[i].conn_id);
		for (uint8_t j = 0; j < ics_enip->enip_services[i].cip_service_count; j++) {
			SCLogNotice("service = 0x%x", ics_enip->enip_services[i].cip_services[j].service);
			SCLogNotice("class = 0x%x", ics_enip->enip_services[i].cip_services[j].class);
			SCLogNotice("instance = 0x%x", ics_enip->enip_services[i].cip_services[j].instance);
		}
		SCLogNotice("---------------------------------------------");
	}
}

void display_enip_study_data(enip_ht_items_t *study_enip)
{
	char buffer[4096] = {0};

	for (uint32_t i = 0; i < study_enip->enip_ht_count; i++) {
		snprintf(buffer, sizeof(buffer), "sip = %x, dip = %x, proto = %x, command = %u, session = %u, conn_id = %u, service = %u, class = %u\n",
			study_enip->items[i].sip,
			study_enip->items[i].dip,
			study_enip->items[i].proto,
			study_enip->items[i].command,
			study_enip->items[i].session,
			study_enip->items[i].conn_id,
			study_enip->items[i].service,
			study_enip->items[i].class);
		SCLogNotice("[%u]: %s", i, buffer);
	}
	return;
}

