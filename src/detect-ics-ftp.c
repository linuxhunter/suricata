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

static void *FTPDataGetTx(void *state, uint64_t tx_id)
{
	FtpDataState *ftp_state = (FtpDataState *)state;
	return ftp_state;
}

static uint64_t FTPDataGetTxCnt(void *state)
{
	/* ftp-data is single tx */
	return 1;
}

int detect_get_ftp_audit_data(Packet *p, ics_ftp_t *ics_ftp)
{
	int ret = TM_ECODE_OK;
	uint64_t tx_count;

	if (p->flow->alproto == ALPROTO_FTP) {
		FtpState *ftp_state = p->flow->alstate;
		tx_count = FTPGetTxCnt(ftp_state);
		FTPTransaction *tx = FTPGetTx(ftp_state, tx_count-1);
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
			if (tx->command_descriptor->command == FTP_COMMAND_USER) {
				if (ftp_state->login_info.username != NULL) {
					if ((ics_ftp->params = SCMalloc(ftp_state->login_info.username_length+1)) == NULL) {
						ret = TM_ECODE_FAILED;
						goto out;
					}
					ics_ftp->params_length = ftp_state->login_info.username_length;
					memset(ics_ftp->params, 0x00, ics_ftp->params_length+1);
					memcpy(ics_ftp->params, ftp_state->login_info.username, ics_ftp->params_length);
				}
			} else if (tx->command_descriptor->command == FTP_COMMAND_PASS) {
				if ((ics_ftp->params = SCMalloc(ftp_state->login_info.password_length+1)) == NULL) {
					ret = TM_ECODE_FAILED;
					goto out;
				}
				ics_ftp->params_length = ftp_state->login_info.password_length;
				memset(ics_ftp->params, 0x00, ics_ftp->params_length+1);
				memcpy(ics_ftp->params, ftp_state->login_info.password, ics_ftp->params_length);
			}
		}
	} else if (p->flow->alproto == ALPROTO_FTPDATA) {
		tx_count = FTPDataGetTxCnt(p->flow->alstate);
		FtpDataState *ftp_state = FTPDataGetTx(p->flow->alstate, tx_count-1);
		if (ftp_state != NULL) {
			if (ftp_state->command <= FTP_COMMAND_UNKNOWN || ftp_state->command >= FTP_COMMAND_MAX) {
				ret = TM_ECODE_FAILED;
				goto out;
			}
			uint8_t command_length;
			command_length = FtpCommands[ftp_state->command].command_length;
			if ((ics_ftp->command = SCMalloc(command_length+1)) == NULL) {
				ret = TM_ECODE_FAILED;
				goto out;
			}
			memset(ics_ftp->command, 0x00, command_length+1);
			memcpy(ics_ftp->command, FtpCommands[ftp_state->command].command_name, command_length);
			ics_ftp->command_length = command_length;
		}
	}
out:
	return ret;
}
