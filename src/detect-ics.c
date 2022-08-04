#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-hash.h"

#include "detect-ics.h"
#include "util-ics.h"

ics_mode_t global_ics_work_mode;
intmax_t global_ics_template_id;
ics_hashtable_t global_ics_hashtables[ICS_PROTO_MAX];

static int init_ics_hashtables(void)
{
	int ret = TM_ECODE_OK;

	for (int i = 0; i < ICS_PROTO_MAX; i++) {
		SCMutexInit(&global_ics_hashtables[i].mutex, NULL);
		switch(i) {
			case MODBUS:
				ret = init_modbus_hashtable(&global_ics_hashtables[i].hashtable, ICS_HASHTABLE_SIZE);
				break;
			case DNP3:
				ret = init_dnp3_hashtable(&global_ics_hashtables[i].hashtable, ICS_HASHTABLE_SIZE);
				break;
			default:
				continue;
		}
		if (global_ics_hashtables[i].hashtable == NULL) {
			ret = TM_ECODE_FAILED;
			goto out;
		}
	}
out:
	return ret;
}

static int create_ics_hashtables(intmax_t template_id)
{
	for (int i = 0; i < ICS_PROTO_MAX; i++) {
		switch(i) {
			case MODBUS:
				SCMutexLock(&global_ics_hashtables[MODBUS].mutex);
				create_modbus_hashtable(global_ics_hashtables[MODBUS].hashtable, template_id);
				SCMutexUnlock(&global_ics_hashtables[MODBUS].mutex);
				break;
			case DNP3:
				SCMutexLock(&global_ics_hashtables[DNP3].mutex);
				create_dnp3_hashtable(global_ics_hashtables[DNP3].hashtable, template_id);
				SCMutexUnlock(&global_ics_hashtables[DNP3].mutex);
				break;
			default:
				break;
		}
	}
	return 0;
}

static void free_ics_hashtables(void)
{
	for (int i = 0; i < ICS_PROTO_MAX; i++) {
		SCMutexLock(&global_ics_hashtables[i].mutex);
		if (global_ics_hashtables[i].hashtable != NULL) {
			HashTableFree(global_ics_hashtables[i].hashtable);
			global_ics_hashtables[i].hashtable = NULL;
		}
		SCMutexUnlock(&global_ics_hashtables[i].mutex);
	}
}

void* detect_create_ics_adu(ics_mode_t work_mode, enum AppProtoEnum proto, intmax_t template_id)
{
	ics_adu_t *ics_adu = SCMalloc(sizeof(ics_adu_t));

	if (ics_adu == NULL)
		goto error;

	memset(ics_adu, 0x00, sizeof(ics_adu_t));
	if (work_mode <= ICS_MODE_MIN || work_mode >= ICS_MODE_MAX)
		goto error;
	if (proto != ALPROTO_MODBUS &&
		proto != ALPROTO_DNP3)
		goto error;
	ics_adu->work_mode = work_mode;
	ics_adu->proto = proto;
	ics_adu->template_id = template_id;
	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			{
				ics_adu->u.modbus = SCMalloc(sizeof(ics_modbus_t)*ICS_ADU_INDEX_MAX);
				if (ics_adu->u.modbus == NULL)
					goto error;
				memset(ics_adu->u.modbus, 0x00, sizeof(ics_modbus_t)*ICS_ADU_INDEX_MAX);
			}
			break;
		case ALPROTO_DNP3:
			{
				ics_adu->u.dnp3 = SCMalloc(sizeof(ics_dnp3_t)*ICS_ADU_INDEX_MAX);
				if (ics_adu->u.dnp3 == NULL)
					goto error;
				memset(ics_adu->u.dnp3, 0x00, sizeof(ics_dnp3_t)*ICS_ADU_INDEX_MAX);
			}
			break;
		default:
			break;
	}
	return ics_adu;
error:
	if (ics_adu) {
		SCFree(ics_adu);
		ics_adu = NULL;
	}
	return NULL;
}

void detect_free_ics_adu(ics_adu_t *ics_adu, enum AppProtoEnum proto)
{
	if (ics_adu == NULL)
		goto out;
	switch(proto) {
		case ALPROTO_MODBUS:
			if (ics_adu->u.modbus != NULL)
				SCFree(ics_adu->u.modbus);
			break;
		case ALPROTO_DNP3:
			if (ics_adu->u.dnp3 != NULL)
				SCFree(ics_adu->u.dnp3);
			break;
		default:
			break;
	}
out:
	return;
}

int detect_get_ics_adu(Packet *p, ics_adu_t *ics_adu)
{
	int ret = TM_ECODE_OK;

	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			ret = detect_get_modbus_adu(p->flow, &ics_adu->u.modbus[ICS_ADU_REAL_INDEX]);
			if (ret != TM_ECODE_OK)
				goto out;
			if (global_ics_work_mode == ICS_MODE_WARNING) {
				if (match_modbus_ht_item(global_ics_hashtables[MODBUS].hashtable, p, &ics_adu->u.modbus[ICS_ADU_REAL_INDEX]) == 0)
					ics_adu->invalid = 1;
			}
			break;
		case ALPROTO_DNP3:
			ret = detect_get_dnp3_adu(p->flow, &ics_adu->u.dnp3[ICS_ADU_REAL_INDEX]);
			if (ret != TM_ECODE_OK)
				goto out;
			break;
		default:
			ret = TM_ECODE_FAILED;
			goto out;
	}
out:
	return ret;
}

TmEcode detect_ics_adu(ThreadVars *tv, Packet *p)
{
	ics_adu_t *ics_adu = NULL;

	if (p->flow) {
		p->flow->ics_adu = NULL;
		if (p->flow->alproto == ALPROTO_MODBUS ||
			p->flow->alproto == ALPROTO_DNP3) {
			if (p->flowflags & FLOW_PKT_TOSERVER) {
				ics_adu = detect_create_ics_adu(global_ics_work_mode, p->flow->alproto, global_ics_template_id);
				if (ics_adu == NULL) {
					SCLogNotice("create modbus adu error.\n");
					goto error;
				}
				if (detect_get_ics_adu(p, ics_adu) != TM_ECODE_OK) {
					SCLogNotice("get modbus adu error.\n");
					goto error;
				}
				p->flow->ics_adu = (void *)ics_adu;
			}
		}
	}
	return TM_ECODE_OK;
error:
	p->flow->ics_adu = NULL;
	if (ics_adu)
		detect_free_ics_adu(ics_adu, p->flow->alproto);
	return TM_ECODE_FAILED;
}

int ParseICSControllerSettings(void)
{
	int ret = TM_ECODE_OK;
	const char *conf_val;
	intmax_t template_id = 0;

	if ((ConfGet("ics-control.work-mode", &conf_val)) == 1) {
		if (!strncmp(conf_val, "study", strlen("study")))
			global_ics_work_mode = ICS_MODE_STUDY;
		else if (!strncmp(conf_val, "warning", strlen("warning")))
			global_ics_work_mode = ICS_MODE_WARNING;
		else
			global_ics_work_mode = ICS_MODE_NORMAL;
	} else {
		global_ics_work_mode = ICS_MODE_NORMAL;
	}
	if (global_ics_work_mode == ICS_MODE_STUDY ||
		global_ics_work_mode == ICS_MODE_WARNING) {
		if ((ConfGetInt("ics-control.template-id", &template_id)) == 1) {
			global_ics_template_id = template_id;
		} else {
			global_ics_template_id = 0;
			ret = TM_ECODE_FAILED;
			goto out;
		}
	}
	if (global_ics_work_mode == ICS_MODE_WARNING) {
		if (init_ics_hashtables() != TM_ECODE_OK) {
			SCLogNotice("init ics hashtables error.\n");
			ret = TM_ECODE_FAILED;
			goto out;
		}
		create_ics_hashtables(template_id);
	}
out:
	return ret;
}
