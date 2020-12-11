#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-dpdk.h"
#include "output.h"

#include "detect-engine.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"

#include "runmode-dpdk.h"
#include "acl-dpdk.h"

#define ACL_RULE_PATH	"/etc/suricata/acl_ipv4.db"

#define GET_CB_FIELD(in, fd, base, lim, dlm)    do {            \
	unsigned long val;                                      \
	char *end;                                              \
	errno = 0;                                              \
	val = strtoul((in), &end, (base));                      \
	if (errno != 0 || end[0] != (dlm) || val > (lim))       \
	return -EINVAL;                               \
	(fd) = (typeof(fd))val;                                 \
	(in) = end + 1;                                         \
} while (0)

const char cb_port_delim[] = ":";
struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_SRC,
		.offset = offsetof(struct rte_ipv4_hdr, src_addr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_DST,
		.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct rte_ipv4_hdr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct rte_ipv4_hdr) -
			offsetof(struct rte_ipv4_hdr, next_proto_id) +
			sizeof(uint16_t),
	},
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));
DpdkAclConfig_t dpdk_acl_config;

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_ipv4_net(const char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint8_t a, b, c, d, m;

	GET_CB_FIELD(in, a, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, d, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);

	addr[0] = RTE_IPV4(a, b, c, d);
	mask_len[0] = m;

	return 0;
}

/* Bypass comment and empty lines */
static inline int
is_bypass_line(char *buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

static struct rte_acl_ctx* setup_acl(struct rte_acl_rule *acl_base, unsigned int acl_num, int socketid)
{
	char name[PATH_MAX];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx *context;
	int dim = RTE_DIM(ipv4_defs);

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "%s%d", L3FWD_ACL_IPV4_NAME, socketid);

	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	if ((context = rte_acl_create(&acl_param)) == NULL)
		goto error;

	if (rte_acl_set_ctx_classify(context, RTE_ACL_CLASSIFY_DEFAULT) != 0)
		goto error;

	if (rte_acl_add_rules(context, acl_base, acl_num) < 0)
		goto error;

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));

	if (rte_acl_build(context, &acl_build_param) != 0)
		goto error;

	return context;
error:
	return NULL;
}

static int add_acl_rules(const char *rule_path, struct rte_acl_rule **acl_base, unsigned int *acl_base_num, uint32_t rule_size, int (*parser)(char *, struct rte_acl_rule *, int))
{
	int ret = 0;
	uint8_t *acl_rules;
	struct rte_acl_rule *next;
	unsigned int acl_num = 0, total_num = 0;
	unsigned int acl_cnt = 0;
	char buff[LINE_MAX];
	FILE *fh = NULL;
	unsigned int i = 0;
	int val;

	fh = fopen(rule_path, "rb");
	if (fh == NULL) {
		SCLogInfo(" Open file %s error!", rule_path);
		ret = -1;
		goto out;
	}
	while ((fgets(buff, LINE_MAX, fh) != NULL)) {
		if (buff[0] == ACL_LEAD_CHAR)
			acl_num++;
	}
	val = fseek(fh, 0, SEEK_SET);
	if (val < 0) {
		SCLogInfo(" reset file pointer error.");
		ret = -2;
		goto out;
	}
	acl_rules = calloc(acl_num, rule_size);
	if (NULL == acl_rules) {
		SCLogInfo(" calloc memory error.");
		ret = -3;
		goto out;
	}
	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;
		if (is_bypass_line(buff))
			continue;
		char s = buff[0];
		if (s != ACL_LEAD_CHAR)
			continue;
		/* ACL entry */
		next = (struct rte_acl_rule *)(acl_rules + acl_cnt * rule_size);
		if (parser(buff + 1, next, 0) != 0) {
			SCLogInfo(" parse ACL rule error.");
			ret = -4;
			goto out;
		}
		next->data.userdata = ACL_DENY_SIGNATURE + acl_cnt;
		acl_cnt++;
		next->data.priority = RTE_ACL_MAX_PRIORITY - total_num;
		next->data.category_mask = -1;
		total_num++;
	}

	fclose(fh);
	*acl_base = (struct rte_acl_rule *)acl_rules;
	*acl_base_num = acl_num;
out:
	return ret;
}

static int parse_ipv4_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;
	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL) {
			SCLogInfo(" invalid ACL rule line.");
			return -EINVAL;
		}
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
		&v->field[SRC_FIELD_IPV4].value.u32,
		&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		SCLogInfo("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
		&v->field[DST_FIELD_IPV4].value.u32,
		&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		SCLogInfo("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		v->field[SRCP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		v->field[SRCP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0) {
		SCLogInfo("failed to read port delim");
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		v->field[DSTP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		v->field[DSTP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0) {
		SCLogInfo("failed to read port delim 2");
		return -EINVAL;
	}

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
		< v->field[SRCP_FIELD_IPV4].value.u16
		|| v->field[DSTP_FIELD_IPV4].mask_range.u16
		< v->field[DSTP_FIELD_IPV4].value.u16) {
		SCLogInfo("source port or dest port range error.");
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
		0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
		0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0,
			UINT32_MAX, 0);

	return 0;
}

static inline void
print_one_ipv4_rule(struct acl4_rule *rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32,
		&a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
		rule->field[SRC_FIELD_IPV4].mask_range.u32);
	uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32,
		&a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
		rule->field[DST_FIELD_IPV4].mask_range.u32);
	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV4].value.u16,
		rule->field[SRCP_FIELD_IPV4].mask_range.u16,
		rule->field[DSTP_FIELD_IPV4].value.u16,
		rule->field[DSTP_FIELD_IPV4].mask_range.u16,
		rule->field[PROTO_FIELD_IPV4].value.u8,
		rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
			rule->data.category_mask,
			rule->data.priority,
			rule->data.userdata);
}

static void dump_ipv4_rules(struct acl4_rule *rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv4_rule(rule, extra);
		printf("\n");
	}
}

int CreateDpdkAcl(void)
{
	int ret = 0;
	SCEnter();

#ifndef HAVE_DPDK
	SCLogInfo(" Not configured for DPDK");
#else
	if (GetPreAcl()) {
		struct rte_acl_rule *acl_base_ipv4;
		unsigned int acl_num_ipv4 = 0;

		if (add_acl_rules(ACL_RULE_PATH, &acl_base_ipv4, &acl_num_ipv4, sizeof(struct acl4_rule), &parse_ipv4_rule) < 0) {
			SCLogInfo(" Failed to add acl rules!");
			ret = -1;
			goto out;
		}
		dump_ipv4_rules((struct acl4_rule *)acl_base_ipv4, acl_num_ipv4, 1);
		dpdk_acl_config.ipv4AclCtx = setup_acl(acl_base_ipv4, acl_num_ipv4, 0);
		dpdk_acl_config.ipv4AclCount = acl_num_ipv4;
		free(acl_base_ipv4);
	}
out:
#endif
	return ret;
}

static inline void
prepare_one_packet(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
	int index)
{
	struct rte_mbuf *pkt = pkts_in[index];

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else {
		/* Unknown type, drop the packet */
		rte_pktmbuf_free(pkt);
	}
}

static void
prepare_acl_parameter(struct rte_mbuf **pkts_in, struct acl_search_t *acl, int nb_rx)
{
	int i;

	acl->num_ipv4 = 0;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(
				pkts_in[i], void *));
	}

	for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_in[
				i + PREFETCH_OFFSET], void *));
		prepare_one_packet(pkts_in, acl, i);
	}

	/* Process left packets */
	for (; i < nb_rx; i++)
		prepare_one_packet(pkts_in, acl, i);
}

int DpdkAclClassify(struct rte_mbuf **pkts_in, struct acl_search_t *acl, int nb_rx)
{
	int ret = 0;

	if (GetPreAcl()) {
		prepare_acl_parameter(pkts_in, acl, nb_rx);
		if (acl->num_ipv4) {
			rte_acl_classify(
				dpdk_acl_config.ipv4AclCtx,
				acl->data_ipv4,
				acl->res_ipv4,
				acl->num_ipv4,
				DEFAULT_MAX_CATEGORIES);
			ret = 1;
		}
	}
	return ret;
}
