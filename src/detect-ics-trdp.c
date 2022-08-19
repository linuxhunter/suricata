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

static trdp_ht_item_t* alloc_trdp_ht_item(uint32_t sip, uint32_t dip ,uint8_t proto,
	TRDP_Packet_Type_t packet_type, uint16_t protocol_version, uint16_t msg_type, uint32_t com_id)
{
	trdp_ht_item_t *trdp_item = NULL;

	if ((trdp_item = SCMalloc(sizeof(trdp_ht_item_t))) == NULL) {
		goto out;
	}
	trdp_item->sip = sip;
	trdp_item->dip = dip;
	trdp_item->proto = proto;
	trdp_item->packet_type = packet_type;
	trdp_item->protocol_version = protocol_version;
	trdp_item->msg_type = msg_type;
	trdp_item->com_id = com_id;
out:
	return trdp_item;
}

static void free_trdp_ht_item(trdp_ht_item_t *trdp_item)
{
	if (trdp_item)
		SCFree(trdp_item);
	return;
}

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

int detect_get_trdp_audit_data(Packet *p, ics_trdp_t *ics_trdp)
{
	int ret = TM_ECODE_OK;
	TRDPState *trdp_state = p->flow->alstate;
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

int detect_get_trdp_study_data(Packet *p, ics_trdp_t *audit_trdp, trdp_ht_item_t *study_trdp)
{
	study_trdp->sip = GET_IPV4_SRC_ADDR_U32(p);
	study_trdp->dip = GET_IPV4_DST_ADDR_U32(p);
	study_trdp->proto = IP_GET_IPPROTO(p);
	study_trdp->packet_type = audit_trdp->packet_type;
	study_trdp->protocol_version = audit_trdp->u.pd.header.protocol_version;
	study_trdp->msg_type = audit_trdp->u.pd.header.msg_type;
	study_trdp->com_id = audit_trdp->u.pd.header.com_id;
	return 0;
}

static uint32_t ics_trdp_hashfunc(HashTable *ht, void *data, uint16_t datalen)
{
	return HashTableGenericHash(ht, data, datalen);
}

static char ics_trdp_hash_comparefunc(void *data1, uint16_t data1_len,
	void *data2, uint16_t data2_len)
{
	char ret = 0;
	trdp_ht_item_t *item1 = (trdp_ht_item_t *)data1;
	trdp_ht_item_t *item2 = (trdp_ht_item_t *)data2;

	if (item1 == NULL || item2 == NULL)
		goto out;
	if (item1->sip == item2->sip &&
		item1->dip == item2->dip &&
		item1->proto == item2->proto &&
		item1->packet_type == item2->packet_type &&
		item1->protocol_version == item2->protocol_version &&
		item1->msg_type == item2->msg_type &&
		item1->com_id == item2->com_id) {
		ret = 1;
		goto out;
	}
out:
	return ret;
}

static void ics_trdp_hashfree(void *data)
{
	free_trdp_ht_item(data);
}

static int add_trdp_ht_item(HashTable *ht, trdp_ht_item_t *trdp_item)
{
	int ret = TM_ECODE_OK;

	if (HashTableLookup(ht, trdp_item, 0) == NULL) {
		if (HashTableAdd(ht, trdp_item, 0) < 0) {
			SCLogNotice("add TRDP hashtable item error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
	} else {
		SCLogNotice("Duplicate TRDP hashtable item.\n");
		free_trdp_ht_item(trdp_item);
	}
out:
	return ret;
}

int init_trdp_hashtable(HashTable **ht, uint32_t size)
{
	*ht = HashTableInit(size, ics_trdp_hashfunc, ics_trdp_hash_comparefunc, ics_trdp_hashfree);
	if (*ht != NULL)
		return TM_ECODE_OK;
	else
		return TM_ECODE_FAILED;
}

int create_trdp_hashtable(HashTable *ht, intmax_t template_id)
{
	int status = 0, len;
    trdp_ht_item_t *trdp_item = NULL;
	sql_handle handle = NULL;
	char query[SQL_QUERY_SIZE] = {0};
	MYSQL_RES *results=NULL;
	MYSQL_ROW record;
	uint32_t sip, dip;
	uint8_t proto;
	TRDP_Packet_Type_t packet_type;
	uint16_t protocol_version, msg_type;
	uint32_t com_id;

	if ((handle = sql_db_connect(DB_NAME)) == NULL) {
		SCLogNotice("connect database study_modbus_table error.\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "select src_ip,dst_ip,proto,packet_type,protocol_version,msg_type,com_id from study_trdp_table where template_id='%ld';", template_id);

	status = sql_real_query(handle, query, len);
	if (status != 0) {
		SCLogNotice("query trdp whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	results = mysql_use_result(handle);
	if (results == NULL) {
		SCLogNotice("get trdp whitelist with template_id %ld error.\n", template_id);
		goto out;
	}
	while((record = mysql_fetch_row(results))) {
		sip = strtoul(record[0], NULL, 10);
		dip = strtoul(record[1], NULL, 10);
		proto = strtoul(record[2], NULL, 10);
		packet_type = strtoul(record[3], NULL, 10);
		protocol_version = strtoul(record[4], NULL, 10);
		msg_type = strtoul(record[5], NULL, 10);
		com_id = strtoul(record[6], NULL, 10);
		if ((trdp_item = alloc_trdp_ht_item(sip, dip, proto, packet_type, protocol_version, msg_type, com_id)) == NULL) {
			SCLogNotice("Alloc TRDP Item error.\n");
			goto out;
		}
		if (add_trdp_ht_item(ht, trdp_item) != TM_ECODE_OK) {
			SCLogNotice("Insert TRDP Item to HashTable error.\n");
			goto out;
		}
		SCLogNotice("sip = %u, dip = %u, proto = %u, packet_type = %u, protocol_version = %u, msg_type = %u, com_id = %u\n",
			sip, dip, proto, packet_type, protocol_version, msg_type, com_id);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return 0;
}

static int __match_trdp_ht_item(HashTable *ht, trdp_ht_item_t *trdp_item)
{
	int matched = 0;

	if (HashTableLookup(ht, trdp_item, 0) == NULL) {
		matched = 0;
	} else {
		matched = 1;
	}
	return matched;
}

int detect_get_trdp_warning_data(HashTable *ht, Packet *p, ics_trdp_t *audit_trdp, trdp_ht_item_t *warning_trdp)
{
	int matched = 0;
	uint32_t sip, dip, com_id;
	uint8_t proto;
	uint16_t protocol_version, msg_type;
	TRDP_Packet_Type_t packet_type;
	trdp_ht_item_t *trdp_item = NULL;

	sip = GET_IPV4_SRC_ADDR_U32(p);
	dip = GET_IPV4_DST_ADDR_U32(p);
	proto = IP_GET_IPPROTO(p);
	packet_type = audit_trdp->packet_type;
	protocol_version = audit_trdp->u.pd.header.protocol_version;
	msg_type = audit_trdp->u.pd.header.msg_type;
	com_id = audit_trdp->u.pd.header.com_id;
	if ((trdp_item = alloc_trdp_ht_item(sip, dip, proto, packet_type, protocol_version, msg_type, com_id)) == NULL) {
		matched = 1;
		goto out;
	}
	if (__match_trdp_ht_item(ht, trdp_item) == 0) {
		memcpy(warning_trdp, trdp_item, sizeof(trdp_ht_item_t));
		goto out;
	}
	matched = 1;
out:
	if (trdp_item) {
		free_trdp_ht_item(trdp_item);
	}
	return matched;
}

