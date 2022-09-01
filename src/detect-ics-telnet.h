#ifndef __DETECT_ICS_TELNET_H__
#define __DETECT_ICS_TELNET_H__
#include "rust.h"

typedef enum {
	TELNET_USERNAME,
	TELNET_PASSWORD,
	TELNET_CMD,
	TELNET_NONE,
} ics_telnet_audit_data_type_t;

typedef struct {
	ics_telnet_audit_data_type_t data_type;
	char *data;
	int data_length;
} ics_telnet_t;

int detect_get_telnet_audit_data(Packet *p, ics_telnet_t *ics_telnet);
#endif
