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
