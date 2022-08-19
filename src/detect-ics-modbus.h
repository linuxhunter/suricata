#ifndef __DETECT_ICS_MODBUS_H
#define __DETECT_ICS_MODBUS_H

#define MODBUS_DATA_LEN_MAX 64
typedef struct {
    uint8_t funcode;
    union {
        struct addr_quan {
            uint16_t address;
            uint16_t quantity;
        } addr_quan;
        struct addr_data {
            uint16_t address;
            uint16_t data;
        } addr_data;
        struct subfunc {
            uint16_t subfunction;
        } subfunc;
        struct addr_quan_data {
            uint16_t address;
            uint16_t quantity;
            uint8_t data_len;
            uint8_t data[MODBUS_DATA_LEN_MAX];
        } addr_quan_data;
        struct and_or_mask {
            uint16_t and_mask;
            uint16_t or_mask;
        } and_or_mask;
        struct rw_addr_quan {
            uint16_t read_address;
            uint16_t read_quantity;
            uint16_t write_address;
            uint16_t write_quantity;
        } rw_addr_quan;
    }u;
} ics_modbus_t;

typedef struct {
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
	uint8_t funcode;
	uint32_t address;
	uint32_t quantity;
} modbus_ht_item_t;

int detect_get_modbus_audit_data(Packet *p, ics_modbus_t *audit_modbus);
int detect_get_modbus_study_data(Packet *p, ics_modbus_t *audit_modbus, modbus_ht_item_t *study_modbus);
int detect_get_modbus_warning_data(HashTable *ht, Packet *p, ics_modbus_t *audit_modbus, modbus_ht_item_t *warning_modbus);
int init_modbus_hashtable(HashTable **ht, uint32_t size);
int create_modbus_hashtable(HashTable *ht, intmax_t template_id);

#endif
