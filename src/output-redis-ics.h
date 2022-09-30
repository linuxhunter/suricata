#ifndef __OUTPUT_REDIS_ICS_H
#define __OUTPUT_REDIS_ICS_H
#include "detect-ics.h"

#define MODULE_NAME	"ICSRadisLog"
#define REDIS_SERVER_IP	"127.0.0.1"
#define REDIS_SERVER_PORT	6379

typedef enum {
	BEGIN = 1,
	TEMPLATE_ID,
	SRC_MAC,
	DST_MAC,
	SRC_IPv4,
	DST_IPv4,
	SRC_PORT,
	DST_PORT,
	PROTO,
	FLOW_HASH,
	PKTLEN,
	PAYLOAD_LEN,
	APP_PROTO,
	MODBUS_AUDIT_DATA,
	MODBUS_STUDY_DATA,
	MODBUS_WARNING_DATA,
	DNP3_AUDIT_DATA,
	DNP3_STUDY_DATA,
	DNP3_WARNING_DATA,
	TRDP_AUDIT_DATA,
	TRDP_STUDY_DATA,
	TRDP_WARNING_DATA,
	ENIP_AUDIT_DATA,
	ENIP_STUDY_DATA,
	ENIP_WARNING_DATA,
	HTTP1_AUDIT_DATA,
	FTP_AUDIT_DATA,
	TELNET_AUDIT_DATA,
	BASELINE_WARNING_DATA,
	END,
} ics_tlv_type_t;

typedef enum {
	FTP_COMMAND_LENGTH = 0x1000,
	FTP_COMMAND,
	FTP_PARAMS_LENGTH,
	FTP_PARAMS,
} ics_ftp_tlv_type_t;

typedef enum {
	TELNET_DATA_LENGTH = 0x2000,
	TELNET_DATA,
} ics_telnet_tlv_type_t;

#define ICS_BASELINE_DEFAULT_TIMEOUT	10*1000
#define ICS_BASELINE_DEFAULT_PACK_FREQ	1024
#define ICS_BASELINE_DEFAULT_BPS_MIN	1024
#define ICS_BASELINE_DEFAULT_BPS_MAX	1024*1024
#define ICS_BASELINE_DEFAULT_PPS_MIN	16
#define ICS_BASELINE_DEFAULT_PPS_MAX	1024

typedef enum {
	BASELINE_PACKET_FREQ,
	BASELINE_PPS,
	BASELINE_BPS,
} ics_baseline_warning_type_t;

typedef struct {
	ics_baseline_warning_type_t type;
	uint32_t std_min;
	uint32_t std_max;
	uint32_t real_value;
} ics_baseline_warning_data_t;

typedef struct {
	uint32_t timeout;
	uint32_t packet_frequency;
	uint32_t bps_min;
	uint32_t bps_max;
	uint32_t pps_min;
	uint32_t pps_max;
} ics_baseline_info_t;

typedef struct {
	uint32_t packets;
	uint32_t bytes;
} baseline_stat_t;

typedef struct {
	pthread_mutex_t mutex;
	baseline_stat_t stats[ICS_PROTO_MAX];
} ics_baseline_stat_t;

void ICSRedisLogRegister(void);
#endif
