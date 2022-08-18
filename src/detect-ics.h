#ifndef __DETECT_ICS_H
#define __DETECT_ICS_H

#include "app-layer-protos.h"
#include "detect-ics-modbus.h"
#include "detect-ics-dnp3.h"
#include "detect-ics-trdp.h"

typedef enum {
	ICS_MODE_MIN = 0,
	ICS_MODE_STUDY,
	ICS_MODE_NORMAL,
	ICS_MODE_WARNING,
	ICS_MODE_MAX,
} ics_mode_t;

typedef enum {
	MODBUS = 0,
	DNP3,
	TRDP,
	ICS_PROTO_MAX,
} ics_proto_t;

#define ICS_ADU_WARNING_INVALID_FLAG	0x01
typedef struct {
	ics_mode_t work_mode;
	enum AppProtoEnum proto;
	uint32_t template_id;
	uint32_t flags;
	union {
		ics_modbus_t *modbus;
		ics_dnp3_t *dnp3;
		ics_trdp_t *trdp;
	}u;
	union {
		modbus_ht_item_t *modbus;
		dnp3_ht_item_t *dnp3;
	}warning;
} ics_adu_t;

#define ICS_HASHTABLE_SIZE	8192
typedef struct {
	SCMutex mutex;
	HashTable *hashtable;
} ics_hashtable_t;

void* detect_create_ics_adu(ics_mode_t work_mode, Flow *f, intmax_t template_id);
void detect_free_ics_adu(Flow *p, enum AppProtoEnum proto);
int detect_get_ics_adu(Packet *p, ics_adu_t *ics_adu);
TmEcode detect_ics_adu(ThreadVars *tv, Packet *p);
int ParseICSControllerSettings(void);
#endif
