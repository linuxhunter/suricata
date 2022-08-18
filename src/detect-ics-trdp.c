#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-trdp.h"

#include "detect-ics-trdp.h"

static void* get_trdp_tx(void *al_state, uint64_t tx_id)
{
    TRDPState *trdp_state = (TRDPState *)al_state;
    TRDPTransaction *tx = NULL;
    uint64_t tx_num = tx_id + 1;

    if (trdp_state->curr && trdp_state->curr->tx_num == (tx_num))
        return (void *)trdp_state->curr;

    TAILQ_FOREACH(tx, &trdp_state->tx_list, next) {
        if (tx_num != tx->tx_num)
            continue;
        return (void *)tx;
    }
    return NULL;
}

static uint64_t get_trdp_tx_count(void *state)
{
    uint64_t count = ((uint64_t)((TRDPState *)state)->transaction_max);
    return count;
}

#if 0
static void debug_output_trdp(ics_trdp_t *ics_trdp)
{
	SCLogNotice("packet type: %s\n", (ics_trdp->packet_type == PD_PDU) ? "PD" : "MD");
	SCLogNotice("sequence_counter: %u\n", ics_trdp->u.pd.header.sequence_counter);
	SCLogNotice("protocol_version: %u\n", ics_trdp->u.pd.header.protocol_version);
	SCLogNotice("msg_type: 0x%x\n", ics_trdp->u.pd.header.msg_type);
	SCLogNotice("com_id: %u\n", ics_trdp->u.pd.header.com_id);
	SCLogNotice("ebt_topo_cnt: %u\n", ics_trdp->u.pd.header.ebt_topo_cnt);
	SCLogNotice("op_trn_topo_cnt: %u\n", ics_trdp->u.pd.header.op_trn_topo_cnt);
	SCLogNotice("dataset_length: %u\n", ics_trdp->u.pd.header.dataset_length);
	SCLogNotice("reserved: %u\n", ics_trdp->u.pd.header.reserved);
	SCLogNotice("reply_com_id: %u\n", ics_trdp->u.pd.header.reply_com_id);
	SCLogNotice("reply_ip_address: %u\n", ics_trdp->u.pd.header.reply_ip_address);
	SCLogNotice("frame_checksum: 0x%x\n", ics_trdp->u.pd.header.frame_checksum);
	return;
}
#endif

int detect_get_trdp_adu(Flow *p, ics_trdp_t *ics_trdp)
{
	int ret = TM_ECODE_OK;
	TRDPState *trdp_state = p->alstate;
	TRDPTransaction *tx = NULL;
	uint64_t tx_count = 0;

	if (trdp_state == NULL) {
		SCLogNotice("TRDP State is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	tx_count = get_trdp_tx_count((void *)trdp_state);
	tx = get_trdp_tx((void *)trdp_state, (tx_count - 1));
	if (tx == NULL) {
		SCLogNotice("DNP3 Transaction is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}
	memcpy(ics_trdp, &tx->packet, sizeof(ics_trdp_t));
out:
	return ret;
}

