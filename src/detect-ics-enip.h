#ifndef __DETECT_ICS_ENIP_H__
#define __DETECT_ICS_ENIP_H__
#include "app-layer-enip.h"

#define ENIP_SERVICE_MAX	128
#define CIP_SERVICE_MAX		32
typedef struct {
	uint8_t service;
	uint8_t class;
	uint8_t instance;
	uint8_t reserved;
} cip_service_t;

typedef struct {
	uint16_t command;
	uint32_t session;
	uint32_t conn_id;
	uint8_t cip_service_count;
	cip_service_t cip_services[CIP_SERVICE_MAX];
} enip_service_t;

typedef struct {
	uint16_t enip_service_count;
	enip_service_t enip_services[ENIP_SERVICE_MAX];
} ics_enip_t;

typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
	uint16_t command;
	uint32_t session;
	uint32_t conn_id;
	uint8_t service;
	uint8_t class;
} enip_ht_item_t;

typedef struct {
	uint32_t enip_ht_count;
	enip_ht_item_t *items;
} enip_ht_items_t;

int detect_get_enip_audit_data(Packet *p, ics_enip_t *audit_enip);
int detect_get_enip_study_data(Packet *p, ics_enip_t *audit_enip, enip_ht_items_t *study_enip);
int detect_get_enip_warning_data(HashTable *ht, Packet *p, ics_enip_t *audit_enip, enip_ht_item_t *warning_enip);
int init_enip_hashtable(HashTable **ht, uint32_t size);
int create_enip_hashtable(HashTable *ht, intmax_t template_id);
void display_enip_audit_data(ics_enip_t *audit_enip);
void display_enip_study_data(enip_ht_items_t *study_enip);
#endif
