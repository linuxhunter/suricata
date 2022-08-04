#ifndef __DETECT_ICS_DNP3_H
#define __DETECT_ICS_DNP3_H

typedef struct {
    uint32_t index;
    uint32_t size;
} dnp3_point_t;

typedef struct {
    uint8_t group;
    uint8_t variation;
    uint32_t point_count;
    dnp3_point_t *points;
} dnp3_object_t;

typedef struct {
    uint8_t function_code;
    uint32_t object_count;
    dnp3_object_t *objects;
} ics_dnp3_t;

typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
	uint8_t funcode;
	uint8_t group;
	uint8_t variation;
	uint32_t index;
	uint32_t size;
} dnp3_ht_item_t;

int detect_get_dnp3_adu(Flow *p, ics_dnp3_t *ics_dnp3);
int init_dnp3_hashtable(HashTable **ht, uint32_t size);
int create_dnp3_hashtable(HashTable *ht, intmax_t template_id);
dnp3_ht_item_t* alloc_dnp3_ht_item(uint32_t sip, uint32_t dip ,uint8_t proto, uint8_t funcode, uint8_t group, uint8_t variation, uint32_t index, uint32_t size);
void free_dnp3_ht_item(dnp3_ht_item_t *dnp3_item);
int add_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *dnp3_item);
int match_dnp3_ht_item(HashTable *ht, dnp3_ht_item_t *modbus_item);

#endif
