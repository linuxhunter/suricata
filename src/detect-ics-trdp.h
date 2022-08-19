#ifndef __DETECT_ICS_TRDP_H__
#define __DETECT_ICS_TRDP_H__
#include "app-layer-trdp.h"

typedef TRDP_PACKET_t ics_trdp_t;

typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
	TRDP_Packet_Type_t packet_type;
	uint16_t protocol_version;
	uint16_t msg_type;
	uint32_t com_id;
} trdp_ht_item_t;

int detect_get_trdp_adu(Flow *p, ics_trdp_t *ics_trdp);
int init_trdp_hashtable(HashTable **ht, uint32_t size);
int create_trdp_hashtable(HashTable *ht, intmax_t template_id);
int match_trdp_ht_item(HashTable *ht, Packet *p, ics_trdp_t *trdp, trdp_ht_item_t *warning_data);
#endif
