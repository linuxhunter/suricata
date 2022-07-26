#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"

#include "detect-ics.h"

ics_mode_t global_ics_work_mode;
const char *global_ics_template_name;

void* detect_create_ics_adu(ics_mode_t work_mode, enum AppProtoEnum proto, const char *template_name)
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
	if (template_name)
		ics_adu->template_name = strdup(template_name);
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
			SCFree(ics_adu->u.modbus);
			break;
		case ALPROTO_DNP3:
			SCFree(ics_adu->u.dnp3);
			break;
		default:
			break;
	}
	free(ics_adu->template_name);
out:
	return;
}

int detect_get_ics_adu(Flow *p, ics_adu_t *ics_adu)
{
	int ret = TM_ECODE_OK;

	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			ret = detect_get_modbus_adu(p, &ics_adu->u.modbus[ICS_ADU_REAL_INDEX]);
			break;
		case ALPROTO_DNP3:
			ret = detect_get_dnp3_adu(p, &ics_adu->u.dnp3[ICS_ADU_REAL_INDEX]);
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
		if (p->flow->alproto == ALPROTO_MODBUS ||
			p->flow->alproto == ALPROTO_DNP3) {
			ics_adu = detect_create_ics_adu(global_ics_work_mode, p->flow->alproto, global_ics_template_name);
			if (ics_adu == NULL) {
				SCLogNotice("create modbus adu error.\n");
				goto error;
			}
			if (detect_get_ics_adu(p->flow, ics_adu) != TM_ECODE_OK) {
				SCLogNotice("get modbus adu error.\n");
				goto error;
			}
			p->flow->ics_adu = (void *)ics_adu;
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
		if ((ConfGet("ics-control.template-name", &conf_val)) == 1) {
			global_ics_template_name = conf_val;
		} else {
			global_ics_template_name = NULL;
			ret = TM_ECODE_FAILED;
			goto out;
		}
	}
out:
	return ret;
}
