#ifndef __DETECT_ICS_HTTP1_H__
#define __DETECT_ICS_HTTP1_H__
#include "app-layer-htp.h"

typedef struct {
	char *http_uri;
	size_t http_uri_len;
} ics_http1_t;

int detect_get_http1_audit_data(Packet *p, ics_http1_t *ics_http1);
#endif
