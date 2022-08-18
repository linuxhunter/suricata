#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "util-byte.h"
#include "util-hashlist.h"
#include "util-print.h"
#include "util-enum.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "app-layer-trdp.h"

static TRDPTransaction *TRDPTxAlloc(TRDPState *trdp)
{
	TRDPTransaction *tx = SCCalloc(1, sizeof(TRDPTransaction));
	if (unlikely(tx == NULL))
		return NULL;
	trdp->transaction_max++;
	trdp->curr = tx;
	tx->trdp = trdp;
	tx->tx_num = trdp->transaction_max;
	TAILQ_INSERT_TAIL(&trdp->tx_list, tx, next);
	return tx;
}

static void TRDPTxFree(TRDPTransaction *tx)
{
	SCEnter();
	SCFree(tx);
	SCReturn;
}

static uint16_t TRDPProbingParser(Flow *f, uint8_t direction, const uint8_t *input, uint32_t len, uint8_t *rdir)
{
	SCEnter();
	uint32_t offset = 0;
	uint16_t protocol, msg_type;

	offset += sizeof(uint32_t);
	protocol = ntohs(*((uint16_t *)&input[offset]));
	offset += sizeof(uint16_t);
	msg_type = ntohs(*((uint16_t *)&input[offset]));
	if (protocol == TRDP_PROTO_VERSION &&
		(msg_type == TRDP_PD_MSG_TYPE ||
		 msg_type == TRDP_PR_MSG_TYPE)) {
		return ALPROTO_TRDP;
	}
	return ALPROTO_UNKNOWN;
}

static AppLayerResult TRDPParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	SCEnter();
	TRDPState *trdp = (TRDPState *)state;
	const uint8_t *input = StreamSliceGetData(&stream_slice);
	uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
	TRDPTransaction *tx;
	uint32_t offset = 0;

	if (input_len == 0)
		SCReturnStruct(APP_LAYER_ERROR);
	if ((tx = TRDPTxAlloc(trdp)) == NULL)
		SCReturnStruct(APP_LAYER_ERROR);
	if (input_len < sizeof(TRDP_PD_Header_t))
		SCReturnStruct(APP_LAYER_ERROR);

	tx->packet.packet_type = PD_PDU;
	tx->packet.u.pd.header.sequence_counter = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.protocol_version = ntohs(*((uint16_t *)&input[offset]));
	offset += sizeof(uint16_t);
	tx->packet.u.pd.header.msg_type = ntohs(*((uint16_t *)&input[offset]));
	offset += sizeof(uint16_t);
	tx->packet.u.pd.header.com_id = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.ebt_topo_cnt = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.op_trn_topo_cnt = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.dataset_length = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.reserved = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.reply_com_id = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.reply_ip_address = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	tx->packet.u.pd.header.frame_checksum = ntohl(*((uint32_t *)&input[offset]));
	offset += sizeof(uint32_t);
	memcpy(tx->packet.u.pd.data, &input[offset], TRDP_MAX_PD_DATA_SIZE);
	SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult TRDPParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	SCEnter();
	SCReturnStruct(APP_LAYER_ERROR);
}

static void *TRDPStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	TRDPState *trdp;

	trdp = (TRDPState *)SCCalloc(1, sizeof(TRDPState));
	if (unlikely(trdp == NULL))
		return NULL;
	TAILQ_INIT(&trdp->tx_list);
	SCReturnPtr(trdp, "void");
}

static void TRDPStateFree(void *state)
{
	SCEnter();
	TRDPState *trdp = state;
	TRDPTransaction *tx;

	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&trdp->tx_list)) != NULL) {
			TAILQ_REMOVE(&trdp->tx_list, tx, next);
			TRDPTxFree(tx);
		}
	}
	SCFree(trdp);
	SCReturn;
}

static void *TRDPGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	TRDPState *trdp = (TRDPState *)alstate;
	TRDPTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	if (trdp->curr && trdp->curr->tx_num == (tx_num)) {
		SCReturnPtr(trdp->curr, "void");
	}

	TAILQ_FOREACH(tx, &trdp->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

static uint64_t TRDPGetTxCnt(void *state)
{
    SCEnter();
    uint64_t count = ((uint64_t)((TRDPState *)state)->transaction_max);
    SCReturnUInt(count);
}

static void TRDPStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	TRDPState *trdp = state;
	TRDPTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &trdp->tx_list, next, ttx) {
		if (tx->tx_num != tx_num) {
			continue;
		}

		if (tx == trdp->curr) {
			trdp->curr = NULL;
		}

		TAILQ_REMOVE(&trdp->tx_list, tx, next);
		TRDPTxFree(tx);
		break;
	}

	SCReturn;
}

static int TRDPGetAlstateProgress(void *tx, uint8_t direction)
{
	return 1;
}

static AppLayerTxData *TRDPGetTxData(void *vtx)
{
	TRDPTransaction *tx = (TRDPTransaction *)vtx;
	return &tx->tx_data;
}

void RegisterTRDPParsers(void)
{
	SCEnter();

	const char *proto_name = "trdp";

	if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("udp", proto_name, false)) {
		AppLayerProtoDetectRegisterProtocol(ALPROTO_TRDP, proto_name);
		if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
				proto_name, ALPROTO_TRDP, 0, sizeof(TRDP_MD_Header_t),
				TRDPProbingParser, TRDPProbingParser)) {
			return;
		}
	} else {
		SCLogConfig("Protocol detection and parser disabled for TRDP.");
		SCReturn;
	}

	if (AppLayerParserConfParserEnabled("udp", proto_name)) {
		SCLogConfig("Registering TRDP/udp parsers.");

		AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TRDP, STREAM_TOSERVER,
			TRDPParseRequest);
		AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TRDP, STREAM_TOCLIENT,
			TRDPParseResponse);

		AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_TRDP, TRDPStateAlloc, TRDPStateFree);

		AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_TRDP, TRDPGetTx);
		AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_TRDP, TRDPGetTxCnt);
		AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_TRDP, TRDPStateTxFree);

		AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_TRDP, TRDPGetAlstateProgress);
		AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_TRDP, 1, 1);

		AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_TRDP, NULL);
		AppLayerParserRegisterGetEventInfoById(IPPROTO_UDP, ALPROTO_TRDP, NULL);

		AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_TRDP, TRDPGetTxData);
	}
	else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);
	}
	SCReturn;
}
