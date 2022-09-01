#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "detect-ics-http1.h"

static uint64_t HTPStateGetTxCnt(void *alstate)
{
	HtpState *http_state = (HtpState *)alstate;

	if (http_state != NULL && http_state->conn != NULL) {
		const int64_t size = (int64_t)htp_list_size(http_state->conn->transactions);
		if (size < 0)
			return 0ULL;
		SCLogDebug("size %"PRIu64, size);
		return (uint64_t)size;
	} else {
		return 0ULL;
	}
}

static void *HTPStateGetTx(void *alstate, uint64_t tx_id)
{
	HtpState *http_state = (HtpState *)alstate;

	if (http_state != NULL && http_state->conn != NULL)
		return htp_list_get(http_state->conn->transactions, tx_id);
	else
		return NULL;
}

int detect_get_http1_audit_data(Packet *p, ics_http1_t *ics_http1)
{
	int ret = TM_ECODE_OK;
	static uint64_t global_http_tx_count = 0;
	uint64_t tx_count = 0;

	tx_count = HTPStateGetTxCnt(p->flow->alstate);
	if (global_http_tx_count == tx_count)
		goto out;
	global_http_tx_count = tx_count;
	htp_tx_t *tx = HTPStateGetTx(p->flow->alstate, tx_count-1);
	if (tx != NULL) {
		if (bstr_ptr(tx->request_line) == NULL) {
			ret = TM_ECODE_FAILED;
			goto out;
		}
		if (ics_http1->http_uri == NULL) {
			ics_http1->http_uri = SCMalloc(bstr_len(tx->request_line)+1);
			if (ics_http1->http_uri == NULL) {
				ret = TM_ECODE_FAILED;
				goto out;
			}
			memset(ics_http1->http_uri, 0x00, bstr_len(tx->request_line)+1);
			memcpy(ics_http1->http_uri, bstr_ptr(tx->request_line), bstr_len(tx->request_line));
			ics_http1->http_uri_len = bstr_len(tx->request_line);
		}
	}
out:
	return ret;
}

