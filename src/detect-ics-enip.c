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

