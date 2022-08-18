#ifndef __APP_LAYER_TRDP_H__
#define __APP_LAYER_TRDP_H__

#include "rust.h"

#define TRDP_MIN_PD_HEADER_SIZE	sizeof(TRDP_PD_Header_t)	/**< PD header size with FCS                */
#define TRDP_MAX_PD_DATA_SIZE	1432u		/**< PD data                                */
#define TRDP_MAX_PD_PACKET_SIZE	(TRDP_MAX_PD_DATA_SIZE + TRDP_MIN_PD_HEADER_SIZE)
#define TRDP_MAX_MD_DATA_SIZE	65388u		/**< MD payload size                        */
#define TRDP_MAX_MD_PACKET_SIZE	(TRDP_MAX_MD_DATA_SIZE + sizeof(MD_HEADER_T))

#define TRDP_PROTO_VERSION		0x0100
#define TRDP_PD_MSG_TYPE		0x5064
#define TRDP_PR_MSG_TYPE		0x5072

typedef enum TRDP_Packet_Type_ {
	PD_PDU = 0,
	MD_PDU = 1,
} TRDP_Packet_Type_t;

typedef struct TRDP_PD_Header_ {
	uint32_t sequence_counter;				/**< Unique counter (autom incremented)                     */
	uint16_t protocol_version;				/**< fix value for compatibility (set by the API)           */
	uint16_t msg_type;						/**< of datagram: PD Request (0x5072) or PD_MSG (0x5064)    */
	uint32_t com_id;						/**< set by user: unique id                                 */
	uint32_t ebt_topo_cnt;					/**< set by user: ETB to use, '0' for consist local traffic */
	uint32_t op_trn_topo_cnt;				/**< set by user: direction/side critical, '0' if ignored   */
	uint32_t dataset_length;				/**< length of the data to transmit 0...1432                */
	uint32_t reserved;						/**< reserved for ServiceID/InstanceID support              */
	uint32_t reply_com_id;					/**< used in PD request                                     */
	uint32_t reply_ip_address;				/**< used for PD request                                    */
	uint32_t frame_checksum;				/**< CRC32 of header                                        */
} TRDP_PD_Header_t;

typedef struct TRDP_MD_Header_ {
	uint32_t sequence_counter;				/**< Unique counter (autom incremented)                     */
	uint16_t protocol_version;				/**< fix value for compatibility (set by the API)           */
	uint16_t msg_type;						/**< of datagram: PD Request (0x5072) or PD_MSG (0x5064)    */
	uint32_t com_id;						/**< set by user: unique id                                 */
	uint32_t ebt_topo_cnt;					/**< set by user: ETB to use, '0' for consist local traffic */
	uint32_t op_trn_topo_cnt;				/**< set by user: direction/side critical, '0' if ignored   */
	uint32_t dataset_length;				/**< length of the data to transmit 0...1432                */
	int32_t reply_status;					/**< 0 = OK                                                 */
	uint8_t session_id[16u];				/**< UUID as a byte stream                                  */
	uint32_t reply_timeout;					/**< in us                                                  */
	uint8_t source_uri[32u];				/**< User part of URI                                       */
	uint8_t destination_uri[32u];			/**< User part of URI                                       */
	uint32_t frame_checksum;				/**< CRC32 of header                                        */
} TRDP_MD_Header_t;

typedef struct TRDP_PD_PACKET_ {
	TRDP_PD_Header_t header;
	uint8_t data[TRDP_MAX_PD_DATA_SIZE];
} TRDP_PD_PACKET_t;

typedef struct TRDP_MD_PACKET_ {
	TRDP_MD_Header_t header;
	uint8_t data[TRDP_MAX_MD_DATA_SIZE];
} TRDP_MD_PACKET_t;

typedef struct TRDP_PACKET_ {
	TRDP_Packet_Type_t packet_type;;
	union {
		TRDP_PD_PACKET_t pd;
		TRDP_MD_PACKET_t md;
	}u;
} TRDP_PACKET_t;

typedef struct TRDPTransaction_ {
	AppLayerTxData	tx_data;
	uint64_t tx_num;						/**< Internal transaction ID. 								*/
	struct TRDPState_ *trdp;
	TRDP_PACKET_t packet;
	TAILQ_ENTRY(TRDPTransaction_) next;
} TRDPTransaction;

typedef struct TRDPState_ {
	TAILQ_HEAD(, TRDPTransaction_) tx_list;
	TRDPTransaction *curr;
	uint64_t transaction_max;
} TRDPState;

void RegisterTRDPParsers(void);
#endif
