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
			case TRDP:
				ret = init_trdp_hashtable(&global_ics_hashtables[i].hashtable, ICS_HASHTABLE_SIZE);
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
			case TRDP:
				SCMutexLock(&global_ics_hashtables[TRDP].mutex);
				create_trdp_hashtable(global_ics_hashtables[TRDP].hashtable, template_id);
				SCMutexUnlock(&global_ics_hashtables[TRDP].mutex);
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

void* detect_create_ics_adu(ics_mode_t work_mode, Flow *f, intmax_t template_id)
{
	ics_adu_t *ics_adu = SCMalloc(sizeof(ics_adu_t));

	if (ics_adu == NULL)
		goto error;

	f->ics_adu = ics_adu;
	memset(ics_adu, 0x00, sizeof(ics_adu_t));
	if (work_mode <= ICS_MODE_MIN || work_mode >= ICS_MODE_MAX)
		goto error;
	if (f->alproto != ALPROTO_MODBUS &&
		f->alproto != ALPROTO_DNP3 &&
		f->alproto != ALPROTO_TRDP &&
		f->alproto != ALPROTO_HTTP1 &&
		f->alproto != ALPROTO_FTP &&
		f->alproto != ALPROTO_FTPDATA &&
		f->alproto != ALPROTO_TELNET)
		goto error;
	ics_adu->work_mode = work_mode;
	ics_adu->proto = f->alproto;
	ics_adu->template_id = template_id;
	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			{
				ics_adu->audit.modbus = SCMalloc(sizeof(ics_modbus_t));
				if (ics_adu->audit.modbus == NULL)
					goto error;
				memset(ics_adu->audit.modbus, 0x00, sizeof(ics_modbus_t));
				if (work_mode == ICS_MODE_STUDY) {
					ics_adu->study.modbus = SCMalloc(sizeof(modbus_ht_item_t));
					if (ics_adu->study.modbus == NULL)
						goto error;
					memset(ics_adu->study.modbus, 0x00, sizeof(modbus_ht_item_t));
				} else if (work_mode == ICS_MODE_WARNING) {
					ics_adu->warning.modbus = SCMalloc(sizeof(modbus_ht_item_t));
					if (ics_adu->warning.modbus == NULL)
						goto error;
					memset(ics_adu->warning.modbus, 0x00, sizeof(modbus_ht_item_t));
				}
			}
			break;
		case ALPROTO_DNP3:
			{
				ics_adu->audit.dnp3 = SCMalloc(sizeof(ics_dnp3_t));
				if (ics_adu->audit.dnp3 == NULL)
					goto error;
				memset(ics_adu->audit.dnp3, 0x00, sizeof(ics_dnp3_t));
				if (work_mode == ICS_MODE_STUDY) {
					ics_adu->study.dnp3 = SCMalloc(sizeof(dnp3_ht_items_t));
					if (ics_adu->study.dnp3 == NULL)
						goto error;
					memset(ics_adu->study.dnp3, 0x00, sizeof(dnp3_ht_items_t));
				} else if (work_mode == ICS_MODE_WARNING) {
					ics_adu->warning.dnp3 = SCMalloc(sizeof(dnp3_ht_item_t));
					if (ics_adu->warning.dnp3 == NULL)
						goto error;
					memset(ics_adu->warning.dnp3, 0x00, sizeof(dnp3_ht_item_t));
				}
			}
			break;
		case ALPROTO_TRDP:
			{
				ics_adu->audit.trdp = SCMalloc(sizeof(ics_trdp_t));
				if (ics_adu->audit.trdp == NULL)
					goto error;
				memset(ics_adu->audit.trdp, 0x00, sizeof(ics_trdp_t));
				if (work_mode == ICS_MODE_STUDY) {
					ics_adu->study.trdp = SCMalloc(sizeof(trdp_ht_item_t));
					if (ics_adu->study.trdp == NULL)
						goto error;
					memset(ics_adu->study.trdp, 0x00, sizeof(trdp_ht_item_t));
				} else if (work_mode == ICS_MODE_WARNING) {
					ics_adu->warning.trdp = SCMalloc(sizeof(trdp_ht_item_t));
					if (ics_adu->warning.trdp == NULL)
						goto error;
					memset(ics_adu->warning.trdp, 0x00, sizeof(trdp_ht_item_t));
				}
			}
			break;
		case ALPROTO_HTTP1:
			{
				ics_adu->audit.http1 = SCMalloc(sizeof(ics_http1_t));
				if (ics_adu->audit.http1 == NULL)
					goto error;
				memset(ics_adu->audit.http1, 0x00, sizeof(ics_http1_t));
			}
			break;
		case ALPROTO_FTP:
		case ALPROTO_FTPDATA:
			{
				ics_adu->audit.ftp = SCMalloc(sizeof(ics_ftp_t));
				if (ics_adu->audit.ftp == NULL)
					goto error;
				memset(ics_adu->audit.ftp, 0x00, sizeof(ics_ftp_t));
			}
			break;
		case ALPROTO_TELNET:
			ics_adu->audit.telnet = SCMalloc(sizeof(ics_telnet_t));
			if (ics_adu->audit.telnet == NULL)
				goto error;
			memset(ics_adu->audit.telnet, 0x00, sizeof(ics_telnet_t));
			break;
		default:
			break;
	}
	return ics_adu;
error:
	if (ics_adu) {
		detect_free_ics_adu(f, f->alproto);
		ics_adu = NULL;
	}
	return NULL;
}

void detect_free_ics_adu(Flow *f, enum AppProtoEnum proto)
{
	ics_adu_t *ics_adu = (ics_adu_t *)f->ics_adu;
	if (ics_adu == NULL)
		goto out;
	switch(proto) {
		case ALPROTO_MODBUS:
			if (ics_adu->audit.modbus != NULL) {
				SCFree(ics_adu->audit.modbus);
				ics_adu->audit.modbus = NULL;
			}
			if (global_ics_work_mode == ICS_MODE_STUDY) {
				if (ics_adu->study.modbus != NULL) {
					SCFree(ics_adu->study.modbus);
					ics_adu->study.modbus = NULL;
				}
			} else if (global_ics_work_mode == ICS_MODE_WARNING) {
				if (ics_adu->warning.modbus != NULL) {
					SCFree(ics_adu->warning.modbus);
					ics_adu->warning.modbus = NULL;
				}
			}
			break;
		case ALPROTO_DNP3:
			if (ics_adu->audit.dnp3 != NULL) {
				SCFree(ics_adu->audit.dnp3);
				ics_adu->audit.dnp3 = NULL;
			}
			if (global_ics_work_mode == ICS_MODE_STUDY) {
				if (ics_adu->study.dnp3 != NULL) {
					if (ics_adu->study.dnp3->items != NULL) {
						SCFree(ics_adu->study.dnp3->items);
						ics_adu->study.dnp3->items = NULL;
					}
					SCFree(ics_adu->study.dnp3);
					ics_adu->study.dnp3 = NULL;
				}
			} else if (global_ics_work_mode == ICS_MODE_WARNING) {
				if (ics_adu->warning.dnp3 != NULL) {
					SCFree(ics_adu->warning.dnp3);
					ics_adu->warning.dnp3 = NULL;
				}
			}
			break;
		case ALPROTO_TRDP:
			if (ics_adu->audit.trdp != NULL) {
				SCFree(ics_adu->audit.trdp);
				ics_adu->audit.trdp = NULL;
			}
			if (global_ics_work_mode == ICS_MODE_STUDY) {
				if (ics_adu->study.trdp != NULL) {
					SCFree(ics_adu->study.trdp);
					ics_adu->study.trdp = NULL;
				}
			} else if (global_ics_work_mode == ICS_MODE_WARNING) {
				if (ics_adu->warning.trdp != NULL) {
					SCFree(ics_adu->warning.trdp);
					ics_adu->warning.trdp = NULL;
				}
			}
			break;
		case ALPROTO_HTTP1:
			if (ics_adu->audit.http1 != NULL) {
				if (ics_adu->audit.http1->http_uri != NULL) {
					SCFree(ics_adu->audit.http1->http_uri);
					ics_adu->audit.http1->http_uri = NULL;
				}
				SCFree(ics_adu->audit.http1);
				ics_adu->audit.http1 = NULL;
			}
			break;
		case ALPROTO_FTP:
			if (ics_adu->audit.ftp != NULL) {
				if (ics_adu->audit.ftp->command != NULL) {
					SCFree(ics_adu->audit.ftp->command);
					ics_adu->audit.ftp->command = NULL;
				}
				if (ics_adu->audit.ftp->params != NULL) {
					SCFree(ics_adu->audit.ftp->params);
					ics_adu->audit.ftp->params = NULL;
				}
				SCFree(ics_adu->audit.ftp);
				ics_adu->audit.ftp = NULL;
			}
			break;
		case ALPROTO_TELNET:
			if (ics_adu->audit.telnet != NULL) {
				if (ics_adu->audit.telnet->data != NULL) {
					SCFree(ics_adu->audit.telnet->data);
					ics_adu->audit.telnet->data = NULL;
				}
				SCFree(ics_adu->audit.telnet);
				ics_adu->audit.telnet = NULL;
			}
			break;
		default:
			break;
	}
	SCFree(f->ics_adu);
	f->ics_adu = NULL;
out:
	return;
}

int detect_get_ics_adu(Packet *p, ics_adu_t *ics_adu)
{
	int ret = TM_ECODE_OK;

	switch(ics_adu->proto) {
		case ALPROTO_MODBUS:
			ret = detect_get_modbus_audit_data(p, ics_adu->audit.modbus);
			if (ret != TM_ECODE_OK)
				goto out;
			if (ics_adu->work_mode == ICS_MODE_STUDY) {
				ret = detect_get_modbus_study_data(p, ics_adu->audit.modbus, ics_adu->study.modbus);
				if (ret != TM_ECODE_OK)
					goto out;
			} else if (ics_adu->work_mode == ICS_MODE_WARNING) {
				if (detect_get_modbus_warning_data(global_ics_hashtables[MODBUS].hashtable, p, ics_adu->audit.modbus, ics_adu->warning.modbus) == 0)
					ics_adu->flags |= ICS_ADU_WARNING_INVALID_FLAG;
			}
			break;
		case ALPROTO_DNP3:
			ret = detect_get_dnp3_audit_data(p, ics_adu->audit.dnp3);
			if (ret != TM_ECODE_OK)
				goto out;
			if (ics_adu->work_mode == ICS_MODE_STUDY) {
				ret = detect_get_dnp3_study_data(p, ics_adu->audit.dnp3, ics_adu->study.dnp3);
				if (ret != TM_ECODE_OK)
					goto out;
			} else if (ics_adu->work_mode == ICS_MODE_WARNING) {
				if (detect_get_dnp3_warning_data(global_ics_hashtables[DNP3].hashtable, p, ics_adu->audit.dnp3, ics_adu->warning.dnp3) == 0)
					ics_adu->flags |= ICS_ADU_WARNING_INVALID_FLAG;
			}
			break;
		case ALPROTO_TRDP:
			ret = detect_get_trdp_audit_data(p, ics_adu->audit.trdp);
			if (ret != TM_ECODE_OK)
				goto out;
			if (ics_adu->work_mode == ICS_MODE_STUDY) {
				ret = detect_get_trdp_study_data(p, ics_adu->audit.trdp, ics_adu->study.trdp);
				if (ret != TM_ECODE_OK)
					goto out;
			} else if (ics_adu->work_mode == ICS_MODE_WARNING) {
				if (detect_get_trdp_warning_data(global_ics_hashtables[TRDP].hashtable, p, ics_adu->audit.trdp, ics_adu->warning.trdp) == 0)
					ics_adu->flags |= ICS_ADU_WARNING_INVALID_FLAG;
			}
			break;
		case ALPROTO_HTTP1:
			ret = detect_get_http1_audit_data(p, ics_adu->audit.http1);
			if (ret != TM_ECODE_OK)
				goto out;
			break;
		case ALPROTO_FTP:
		case ALPROTO_FTPDATA:
			ret = detect_get_ftp_audit_data(p, ics_adu->audit.ftp);
			if (ret != TM_ECODE_OK)
				goto out;
			break;
		case ALPROTO_TELNET:
			ret = detect_get_telnet_audit_data(p, ics_adu->audit.telnet);
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

	if (p->flow && (p->flowflags & FLOW_PKT_TOSERVER)) {
		if (p->flow->alproto == ALPROTO_MODBUS ||
			p->flow->alproto == ALPROTO_DNP3 ||
			p->flow->alproto == ALPROTO_TRDP ||
			p->flow->alproto == ALPROTO_HTTP1 ||
			p->flow->alproto == ALPROTO_FTP ||
			p->flow->alproto == ALPROTO_FTPDATA ||
			p->flow->alproto == ALPROTO_TELNET) {
			ics_adu = detect_create_ics_adu(global_ics_work_mode, p->flow, global_ics_template_id);
			if (ics_adu == NULL) {
				SCLogNotice("create ics adu error.\n");
				goto error;
			}
			if (detect_get_ics_adu(p, ics_adu) != TM_ECODE_OK) {
				SCLogNotice("get ics adu error.\n");
				goto error;
			}
			p->flow->ics_adu = (void *)ics_adu;
		}
	}
	return TM_ECODE_OK;
error:
	if (ics_adu)
		detect_free_ics_adu(p->flow, p->flow->alproto);
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
