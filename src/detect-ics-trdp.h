#ifndef __DETECT_ICS_TRDP_H__
#define __DETECT_ICS_TRDP_H__
#include "app-layer-trdp.h"

typedef TRDP_PACKET_t ics_trdp_t;

int detect_get_trdp_adu(Flow *p, ics_trdp_t *ics_trdp);
#endif
