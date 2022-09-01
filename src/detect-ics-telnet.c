#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "util-ics.h"
#include "app-layer-parser.h"
#include "detect-ics-telnet.h"

#define TELNET_DATA_CONTENT_MAX		4096
int detect_get_telnet_audit_data(Packet *p, ics_telnet_t *ics_telnet)
{
	int ret = TM_ECODE_OK;
	char data_type;
	char data_content[TELNET_DATA_CONTENT_MAX] = {0};
	int data_length = 0;

	rs_telnet_state_get_frame_data(p->flow->alstate, &data_type, data_content, &data_length);
	if (data_length > 0) {
		if (data_type == 1)
			ics_telnet->data_type = TELNET_USERNAME;
		else if (data_type == 2)
			ics_telnet->data_type = TELNET_PASSWORD;
		else
			ics_telnet->data_type = TELNET_CMD;
		ics_telnet->data_length = data_length;
		if ((ics_telnet->data = SCMalloc(data_length+1)) == NULL) {
			ret = TM_ECODE_FAILED;
			goto out;
		}
		memset(ics_telnet->data, 0x00, data_length + 1);
		memcpy(ics_telnet->data, data_content, data_length);
	}
out:
	return ret;
}


