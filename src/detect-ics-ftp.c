#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-ftp.h"
#include "detect-ics-ftp.h"

static void *FTPGetTx(void *state, uint64_t tx_id)
{
	FtpState *ftp_state = (FtpState *)state;
	if (ftp_state) {
		FTPTransaction *tx = NULL;

		if (ftp_state->curr_tx == NULL)
			return NULL;
		if (ftp_state->curr_tx->tx_id == tx_id)
			return ftp_state->curr_tx;

		TAILQ_FOREACH(tx, &ftp_state->tx_list, next) {
			if (tx->tx_id == tx_id)
				return tx;
		}
	}
	return NULL;
}

static uint64_t FTPGetTxCnt(void *state)
{
	uint64_t cnt = 0;
	FtpState *ftp_state = state;
	if (ftp_state) {
		cnt = ftp_state->tx_cnt;
	}
	SCLogDebug("returning state %p %"PRIu64, state, cnt);
	return cnt;
}

int detect_get_ftp_audit_data(Packet *p, ics_ftp_t *ics_ftp)
{
	int ret = TM_ECODE_OK;
	uint64_t tx_count;

	tx_count = FTPGetTxCnt(p->flow->alstate);
	FTPTransaction *tx = FTPGetTx(p->flow->alstate, tx_count-1);
	if (tx != NULL) {
		if (tx->command_descriptor == NULL) {
			ret = TM_ECODE_FAILED;
			goto out;
		}
		if ((ics_ftp->command = SCMalloc(tx->command_descriptor->command_length+1)) == NULL) {
			ret = TM_ECODE_FAILED;
			goto out;
		}
		memset(ics_ftp->command, 0x00, tx->command_descriptor->command_length+1);
		memcpy(ics_ftp->command, tx->command_descriptor->command_name, tx->command_descriptor->command_length);
		ics_ftp->command_length = tx->command_descriptor->command_length;
	}
out:
	return ret;
}
