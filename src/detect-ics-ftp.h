#ifndef __DETECT_ICS_FTP_H__
#define __DETECT_ICS_FTP_H__
#include "app-layer-ftp.h"

typedef struct {
	char *command;
	uint8_t command_length;
	char *params;
	uint32_t params_length;
} ics_ftp_t;

int detect_get_ftp_audit_data(Packet *p, ics_ftp_t *ics_ftp);
#endif
