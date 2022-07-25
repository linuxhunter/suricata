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

int detect_get_modbus_adu(Flow *p, ics_modbus_t *ics_modbus);
#endif
