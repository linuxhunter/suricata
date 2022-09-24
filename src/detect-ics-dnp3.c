#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"

#include "detect-ics-dnp3.h"

static dnp3_ht_item_t* alloc_dnp3_ht_item(uint32_t sip, uint32_t dip ,uint8_t proto,
	uint8_t funcode, uint8_t group, uint8_t variation, uint32_t index, uint32_t size)
{
	dnp3_ht_item_t *dnp3_item = NULL;

	if ((dnp3_item = malloc(sizeof(*dnp3_item))) == NULL) {
		goto out;
	}
	dnp3_item->sip = sip;
	dnp3_item->dip = dip;
	dnp3_item->proto = proto;
	dnp3_item->funcode = funcode;
	dnp3_item->group = group;
	dnp3_item->variation = variation;
	dnp3_item->index = index;
	dnp3_item->size = size;
out:
	return dnp3_item;
}

static void free_dnp3_ht_item(dnp3_ht_item_t *dnp3_item)
{
	if (dnp3_item)
		SCFree(dnp3_item);
	return;
}

static void* get_dnp3_tx(void *al_state, uint64_t tx_id)
{
	DNP3State *dnp3_state = (DNP3State *)al_state;
	DNP3Transaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	if (dnp3_state->curr && dnp3_state->curr->tx_num == (tx_num))
		return (void *)dnp3_state->curr;

	TAILQ_FOREACH(tx, &dnp3_state->tx_list, next) {
		if (tx_num != tx->tx_num)
			continue;
		return (void *)tx;
	}
	return NULL;
}

static uint64_t get_dnp3_tx_count(void *state)
{
	uint64_t count = ((uint64_t)((DNP3State *)state)->transaction_max);
	return count;
}

int detect_get_dnp3_audit_data(Packet *p, ics_dnp3_t *ics_dnp3)
{
	int ret = TM_ECODE_OK;
	DNP3State *dnp3_state = p->flow->alstate;
	DNP3Transaction *tx = NULL;
	uint64_t tx_count = 0;
	DNP3Object *object = NULL;
	DNP3Point *point = NULL;
	uint32_t point_index = 0;
	void *rptr = NULL;

	if (dnp3_state == NULL) {
		SCLogNotice("DNP3 State is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	tx_count = get_dnp3_tx_count((void *)dnp3_state);
	tx = get_dnp3_tx((void *)dnp3_state, (tx_count - 1));
	if (tx == NULL) {
		SCLogNotice("DNP3 Transaction is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	ics_dnp3->function_code = tx->request_ah.function_code;
	TAILQ_FOREACH(object, &tx->request_objects, next) {
		rptr = SCRealloc(ics_dnp3->objects, sizeof(dnp3_object_t)*(ics_dnp3->object_count+1));
		if (rptr == NULL) {
			SCLogNotice("Out of Memory for DNP3 Objects\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
		ics_dnp3->objects = rptr;
		ics_dnp3->objects[ics_dnp3->object_count].group = object->group;
		ics_dnp3->objects[ics_dnp3->object_count].variation = object->variation;
		ics_dnp3->objects[ics_dnp3->object_count].point_count = object->count;
		ics_dnp3->objects[ics_dnp3->object_count].points = SCMalloc(sizeof(dnp3_point_t)*object->count);
		if (unlikely(ics_dnp3->objects[ics_dnp3->object_count].points == NULL)) {
			SCLogNotice("Out of Memory for dnp3 points\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
		TAILQ_FOREACH(point, object->points, next) {
			if (point_index >= ics_dnp3->objects[ics_dnp3->object_count].point_count)
				break;
			ics_dnp3->objects[ics_dnp3->object_count].points[point_index].index = point->index;
			ics_dnp3->objects[ics_dnp3->object_count].points[point_index].size = point->size;
		}
		ics_dnp3->object_count += 1;
	}
out:
	return ret;
}


int detect_get_dnp3_study_data(Packet *p, ics_dnp3_t *audit_dnp3, dnp3_ht_items_t *study_dnp3)
{
	int ret = 0;
    uint32_t sip, dip, index, size, total_count = 0, study_data_index = 0;
    uint8_t proto, funcode, group, variation;

    sip = GET_IPV4_SRC_ADDR_U32(p);
    dip = GET_IPV4_DST_ADDR_U32(p);
    proto = IP_GET_IPPROTO(p);
	funcode = audit_dnp3->function_code;

	for (uint32_t i = 0; i < audit_dnp3->object_count; i++) {
		if (audit_dnp3->objects[i].point_count > 0) {
			for (uint32_t j = 0; j < audit_dnp3->objects[i].point_count; j++)
				total_count++;
		} else {
			total_count++;
		}
	}
	study_dnp3->dnp3_ht_count = total_count;
	if ((study_dnp3->items = SCMalloc(sizeof(dnp3_ht_item_t)*total_count)) == NULL) {
		ret = -1;
		goto out;
	}
	memset(study_dnp3->items, 0x00, sizeof(dnp3_ht_item_t)*total_count);
	for (uint32_t i = 0; i < audit_dnp3->object_count; i++) {
		group = audit_dnp3->objects[i].group;
		variation = audit_dnp3->objects[i].variation;
		if (audit_dnp3->objects[i].point_count > 0) {
			for (uint32_t j = 0; j < audit_dnp3->objects[i].point_count; j++) {
				index = audit_dnp3->objects[i].points[j].index;
				size = audit_dnp3->objects[i].points[j].size;
				study_dnp3->items[study_data_index].sip = sip;
				study_dnp3->items[study_data_index].dip = dip;
				study_dnp3->items[study_data_index].proto = proto;
				study_dnp3->items[study_data_index].funcode = funcode;
				study_dnp3->items[study_data_index].group = group;
				study_dnp3->items[study_data_index].variation = variation;
				study_dnp3->items[study_data_index].index = index;
				study_dnp3->items[study_data_index].size = size;
				study_data_index++;
			}
		} else {
			study_dnp3->items[study_data_index].sip = sip;
			study_dnp3->items[study_data_index].dip = dip;
			study_dnp3->items[study_data_index].proto = proto;
			study_dnp3->items[study_data_index].funcode = funcode;
			study_dnp3->items[study_data_index].group = group;
			study_dnp3->items[study_data_index].variation = variation;
			study_dnp3->items[study_data_index].index = 0;
			study_dnp3->items[study_data_index].size = 0;
			study_data_index++;
		}
	}
out:
	return ret;
}

static uint32_t ics_dnp3_hashfunc(HashTable *ht, void *data, uint16_t datalen)
{
	return HashTableGenericHash(ht, data, datalen);
}

static char ics_dnp3_hash_comparefunc(void *data1, uint16_t datalen1,
							  void *data2, uint16_t datalen2)
{
	char ret = 0;
	dnp3_ht_item_t *item1 = (dnp3_ht_item_t *)data1;
	dnp3_ht_item_t *item2 = (dnp3_ht_item_t *)data2;

	if (item1 == NULL || item2 == NULL)
		goto out;
	if (item1->sip == item2->sip &&
		item1->dip == item2->dip &&
		item1->proto == item2->proto &&
		item1->funcode == item2->funcode &&
		item1->group == item2->group &&
		item1->variation == item2->variation &&
		item1->index == item2->index &&
		item1->size == item2->size) {
		ret = 1;
		goto out;
	}
out:
	return ret;
}

static void ics_dnp3_hashfree(void *data)
{
	free_dnp3_ht_item(data);
}

static int add_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *dnp3_item)
{
	int ret = TM_ECODE_OK;

	if (HashTableLookup(ht, dnp3_item, 0) == NULL) {
		if (HashTableAdd(ht, dnp3_item, 0) < 0) {
			SCLogNotice("add DNP3 hashtable item error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
	} else {
		SCLogNotice("Duplicate DNP3 hashtable item.\n");
		free_dnp3_ht_item(dnp3_item);
	}
out:
	return ret;
}

int init_dnp3_hashtable(HashTable **ht, uint32_t size)
{
    *ht = HashTableInit(size, ics_dnp3_hashfunc, ics_dnp3_hash_comparefunc, ics_dnp3_hashfree);
    if (*ht != NULL)
        return TM_ECODE_OK;
    else
        return TM_ECODE_FAILED;
}

int create_dnp3_hashtable(HashTable *ht, intmax_t template_id)
{
	int status = 0, len;
	dnp3_ht_item_t *dnp3_item = NULL;
	sql_handle handle = NULL;
	char query[SQL_QUERY_SIZE] = {0};
	MYSQL_RES *results=NULL;
	MYSQL_ROW record;
	uint32_t sip, dip, index, size;
	uint8_t proto, funcode, group, variation;

	if ((handle = sql_db_connect(DB_NAME)) == NULL) {
		SCLogNotice("connect database study_modbus_table error.\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "select src_ip,dst_ip,proto,funcode,groups,variation,indexes,size from study_dnp3_table where template_id='%ld';", template_id);

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
		group = strtoul(record[4], NULL, 10);
		variation = strtoul(record[5], NULL, 10);
		index = strtoul(record[6], NULL, 10);
		size = strtoul(record[7], NULL, 10);
		if ((dnp3_item = alloc_dnp3_ht_item(sip, dip, proto, funcode, group, variation, index, size)) == NULL) {
			SCLogNotice("Alloc DNP3 Item error.\n");
			goto out;
		}
		if (add_dnp3_ht_item(ht, dnp3_item) != TM_ECODE_OK) {
			SCLogNotice("Insert DNP3 Item to HashTable error.\n");
			goto out;
		}
		SCLogNotice("sip = %u, dip = %u, proto = %u, funcode = %u, group = %u, variation = %u, index = %u, size = %u\n",
			sip, dip, proto, funcode, group, variation, index, size);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return 0;
}

static int __match_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *dnp3_item)
{
	int matched = 0;

	if (HashTableLookup(ht, dnp3_item, 0) == NULL) {
		matched = 0;
	} else {
		matched = 1;
	}
	return matched;
}

int detect_get_dnp3_warning_data(HashTable *ht, Packet *p, ics_dnp3_t *audit_dnp3, dnp3_ht_item_t *warning_dnp3)
{
	int matched = 0;
	uint32_t sip, dip, index, size;
	uint8_t proto, funcode, group, variation;
	dnp3_ht_item_t *dnp3_item = NULL;

	sip = GET_IPV4_SRC_ADDR_U32(p);
	dip = GET_IPV4_DST_ADDR_U32(p);
	proto = IP_GET_IPPROTO(p);
	funcode = audit_dnp3->function_code;
	for (uint32_t i = 0; i < audit_dnp3->object_count; i++) {
		group = audit_dnp3->objects[i].group;
		variation = audit_dnp3->objects[i].variation;
		if (audit_dnp3->objects[i].point_count > 0) {
			for (uint32_t j = 0; j < audit_dnp3->objects[i].point_count; j++) {
				index = audit_dnp3->objects[i].points[j].index;
				size = audit_dnp3->objects[i].points[j].size;
				if ((dnp3_item = alloc_dnp3_ht_item(sip, dip, proto, funcode, group, variation, index, size)) == NULL) {
					matched = 1;
					goto out;
				}
				if (__match_dnp3_ht_item(ht, dnp3_item) == 0) {
					memcpy(warning_dnp3, dnp3_item, sizeof(dnp3_ht_item_t));
					goto out;
				}
			}
		} else {
			index = 0;
			size = 0;
			if ((dnp3_item = alloc_dnp3_ht_item(sip, dip, proto, funcode, group, variation, index, size)) == NULL) {
				matched = 1;
				goto out;
			}
			if (__match_dnp3_ht_item(ht, dnp3_item) == 0) {
				memcpy(warning_dnp3, dnp3_item, sizeof(dnp3_ht_item_t));
				goto out;
			}
		}
	}
	matched = 1;
out:
	if (dnp3_item) {
		free_dnp3_ht_item(dnp3_item);
	}
	return matched;
}

