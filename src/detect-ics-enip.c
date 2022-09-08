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

