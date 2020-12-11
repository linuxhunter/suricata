#ifndef __ACL_DPDK_H
#define __ACL_DPDK_H

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_acl.h>

#define PREFETCH_OFFSET 3
#define DEFAULT_MAX_CATEGORIES  1
#define MAX_PKT_BURST 32
#define MAX_ACL_RULE_NUM    100000
#define DEFAULT_MAX_CATEGORIES  1
#define L3FWD_ACL_IPV4_NAME "l3fwd-acl-ipv4"
#define L3FWD_ACL_IPV6_NAME "l3fwd-acl-ipv6"
#define ACL_LEAD_CHAR       ('@')
#define ROUTE_LEAD_CHAR     ('R')
#define COMMENT_LEAD_CHAR   ('#')
#define OPTION_CONFIG       "config"
#define OPTION_NONUMA       "no-numa"
#define OPTION_ENBJMO       "enable-jumbo"
#define OPTION_RULE_IPV4    "rule_ipv4"
#define OPTION_RULE_IPV6    "rule_ipv6"
#define OPTION_ALG      "alg"
#define OPTION_ETH_DEST     "eth-dest"
#define ACL_DENY_SIGNATURE  0xf0000000
#define RTE_LOGTYPE_L3FWDACL    RTE_LOGTYPE_USER3
#define acl_log(format, ...)    RTE_LOG(ERR, L3FWDACL, format, ##__VA_ARGS__)
#define uint32_t_to_char(ip, a, b, c, d) do {\
	*a = (unsigned char)(ip >> 24 & 0xff);\
	*b = (unsigned char)(ip >> 16 & 0xff);\
	*c = (unsigned char)(ip >> 8 & 0xff);\
	*d = (unsigned char)(ip & 0xff);\
} while (0)

#define OFF_ETHHEAD (sizeof(struct rte_ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct rte_ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct rte_ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m) \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m) \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

/*
 * Rule and trace formats definitions.
 */
enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4VLAN classifications:
 *  - proto *  - VLAN (TAG and DOMAIN)
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS *  - PORTS (SRC and DST)
 */
enum {
	RTE_ACL_IPV4VLAN_PROTO,
	RTE_ACL_IPV4VLAN_VLAN,
	RTE_ACL_IPV4VLAN_SRC,
	RTE_ACL_IPV4VLAN_DST,
	RTE_ACL_IPV4VLAN_PORTS,
	RTE_ACL_IPV4VLAN_NUM
};

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	CB_FLD_USERDATA,
	CB_FLD_NUM,
};

typedef struct __attribute__((__packed__))
{
	uint32_t acl4_rules;
	uint32_t ipv4AclCount;
	struct rte_acl_ctx *ipv4AclCtx;
} DpdkAclConfig_t;

struct acl_search_t {
	const uint8_t *data_ipv4[MAX_PKT_BURST];
	struct rte_mbuf *m_ipv4[MAX_PKT_BURST];
	uint32_t res_ipv4[MAX_PKT_BURST];
	int num_ipv4;
};

int CreateDpdkAcl(void);
int DpdkAclClassify(struct rte_mbuf **pkts_in, struct acl_search_t *acl, int nb_rx);
#endif
