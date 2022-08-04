#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"

#include "detect-ics-dnp3.h"

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

int detect_get_dnp3_adu(Flow *p, ics_dnp3_t *ics_dnp3)
{
	int ret = TM_ECODE_OK;
	DNP3State *dnp3_state = p->alstate;
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


int init_dnp3_hashtable(HashTable **ht, uint32_t size)
{
    *ht = HashTableInit(size, ics_dnp3_hashfunc, ics_dnp3_hash_comparefunc, ics_dnp3_hashfree);
    if (*ht != NULL)
        return TM_ECODE_OK;
    else
        return TM_ECODE_FAILED;
}

dnp3_ht_item_t* alloc_dnp3_ht_item(uint32_t sip, uint32_t dip ,uint8_t proto,
	uint8_t funcode, uint8_t group, uint8_t variation, uint32_t index, uint32_t size)
{
	dnp3_ht_item_t *dnp3_item = NULL;

	if ((dnp3_item = SCMalloc(sizeof(dnp3_ht_item_t))) == NULL) {
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

void free_dnp3_ht_item(dnp3_ht_item_t *dnp3_item)
{
	if (dnp3_item)
		SCFree(dnp3_item);
	return;
}

int add_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *dnp3_item)
{
	return 0;
}

int match_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *dnp3_item)
{
	return 0;
}

int create_dnp3_hashtable(HashTable *ht, intmax_t template_id)
{
	return 0;
}

