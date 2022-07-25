#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "debug.h"
#include "util-debug.h"
#include "app-layer-parser.h"
#include "app-layer-modbus.h"

#include "detect-ics-modbus.h"

int detect_get_modbus_adu(Flow *p, ics_modbus_t *ics_modbus)
{
	int ret = TM_ECODE_OK;
	ModbusState *modbus_state = p->alstate;
	ModbusMessage request;
	int tx_counts = 0;
	uint8_t funcode;

	if (modbus_state == NULL) {
		SCLogNotice("Modbus State is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}

	tx_counts = rs_modbus_state_get_tx_count(modbus_state);
	request = rs_modbus_state_get_tx_request(modbus_state, (tx_counts-1));
	if (request._0 == NULL) {
		SCLogNotice("Modbus Request is NULL\n");
		ret = TM_ECODE_FAILED;
		goto out;
	}

	funcode = rs_modbus_message_get_function(&request);
	switch(funcode) {
		case 1:
		case 3:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_quan.address = rs_modbus_message_get_read_request_address(&request);
			ics_modbus->u.addr_quan.quantity = rs_modbus_message_get_read_request_quantity(&request);
			break;
		case 5:
		case 6:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_data.address = rs_modbus_message_get_write_address(&request);
			ics_modbus->u.addr_data.data = rs_modbus_message_get_write_data(&request);
			break;
		case 8:
			ics_modbus->funcode = funcode;
			ics_modbus->u.subfunc.subfunction = rs_modbus_message_get_subfunction(&request);
			break;
		case 15:
			{
				size_t data_len;
				const uint8_t *data = rs_modbus_message_get_write_multreq_data(&request, &data_len);
				ics_modbus->funcode = funcode;
				ics_modbus->u.addr_quan_data.address = rs_modbus_message_get_write_multreq_address(&request);
				ics_modbus->u.addr_quan_data.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
				ics_modbus->u.addr_quan_data.data_len = data_len;
				memcpy(&ics_modbus->u.addr_quan_data.data, data, sizeof(ics_modbus->u.addr_quan_data.data));
			}
			break;
		case 16:
			ics_modbus->funcode = funcode;
			ics_modbus->u.addr_quan.address = rs_modbus_message_get_write_multreq_address(&request);
			ics_modbus->u.addr_quan.quantity = rs_modbus_message_get_write_multreq_quantity(&request);
			break;
		case 22:
			ics_modbus->funcode = funcode;
			ics_modbus->u.and_or_mask.and_mask = rs_modbus_message_get_and_mask(&request);
			ics_modbus->u.and_or_mask.or_mask = rs_modbus_message_get_or_mask(&request);
			break;
		case 23:
			ics_modbus->funcode = funcode;
			ics_modbus->u.rw_addr_quan.read_address = rs_modbus_message_get_rw_multreq_read_address(&request);
			ics_modbus->u.rw_addr_quan.read_quantity = rs_modbus_message_get_rw_multreq_read_quantity(&request);
			ics_modbus->u.rw_addr_quan.write_address = rs_modbus_message_get_rw_multreq_write_address(&request);
			ics_modbus->u.rw_addr_quan.write_quantity = rs_modbus_message_get_rw_multreq_write_quantity(&request);
			break;
		default:
			ics_modbus->funcode = funcode;
			break;
	}
out:
	return ret;
}


