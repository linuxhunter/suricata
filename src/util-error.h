/* Copyright (C) 2007-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __ERROR_H__
#define __ERROR_H__


/* different error types */
typedef enum {
    SC_OK,
    SC_ERR_MEM_ALLOC,
    SC_ERR_PCRE_MATCH,
    SC_ERR_ACTION_ORDER,
    SC_ERR_PCRE_GET_SUBSTRING,
    SC_ERR_PCRE_COMPILE,
    SC_ERR_PCRE_STUDY,
    SC_ERR_PCRE_PARSE,
    SC_ERR_LOG_MODULE_NOT_INIT,
    SC_ERR_LOG_FG_FILTER_MATCH,
    SC_ERR_COUNTER_EXCEEDED,
    SC_ERR_INVALID_CHECKSUM,
    SC_ERR_SPRINTF,
    SC_ERR_INVALID_ARGUMENT,
    SC_ERR_SPINLOCK,
    SC_ERR_INVALID_ENUM_MAP,
    SC_ERR_INVALID_IP_NETBLOCK,
    SC_ERR_INVALID_IPV4_ADDR,
    SC_ERR_INVALID_IPV6_ADDR,
    SC_ERR_INVALID_RUNMODE,
    SC_ERR_PCAP_DISPATCH,
    SC_ERR_PCAP_CREATE,
    SC_ERR_PCAP_SET_SNAPLEN,
    SC_ERR_PCAP_SET_PROMISC,
    SC_ERR_PCAP_SET_TIMEOUT,
    SC_ERR_PCAP_OPEN_LIVE,
    SC_ERR_PCAP_OPEN_OFFLINE,
    SC_ERR_PCAP_ACTIVATE_HANDLE,
    SC_ERR_PCAP_SET_BUFF_SIZE,
    SC_ERR_NO_PCAP_SET_BUFFER_SIZE,
    SC_ERR_NO_PF_RING,
    SC_ERR_PF_RING_RECV,
    SC_ERR_PF_RING_GET_CLUSTERID_FAILED,
    SC_ERR_PF_RING_GET_INTERFACE_FAILED,
    SC_ERR_PF_RING_OPEN,
    SC_ERR_GET_CLUSTER_TYPE_FAILED,
    SC_ERR_INVALID_CLUSTER_TYPE,
    SC_ERR_PF_RING_SET_CLUSTER_FAILED,
    SC_ERR_DATALINK_UNIMPLEMENTED,
    SC_ERR_INVALID_SIGNATURE,
    SC_ERR_OPENING_FILE,
    SC_ERR_OPENING_RULE_FILE,
    SC_ERR_NO_RULES,
    SC_ERR_NO_RULES_LOADED,
    SC_ERR_FOPEN,
    SC_ERR_INITIALIZATION,
    SC_ERR_THREAD_SPAWN,
    SC_ERR_THREAD_NICE_PRIO,
    SC_ERR_THREAD_CREATE,
    SC_ERR_THREAD_INIT, /**< thread's initialization function failed */
    SC_ERR_SYSCALL,
    SC_ERR_SYSCONF,
    SC_ERR_INVALID_ARGUMENTS,
    SC_ERR_STATS_NOT_INIT,
    SC_ERR_COMPLETE_PORT_SPACE_NEGATED,
    SC_ERR_NO_PORTS_LEFT_AFTER_MERGE,
    SC_ERR_NEGATED_VALUE_IN_PORT_RANGE,
    SC_ERR_PORT_PARSE_INSERT_STRING,
    SC_ERR_UNREACHABLE_CODE_REACHED,
    SC_ERR_ALPARSER,
    SC_ERR_INVALID_NUMERIC_VALUE,
    SC_ERR_NUMERIC_VALUE_ERANGE,
    SC_ERR_INVALID_NUM_BYTES,
    SC_ERR_ARG_LEN_LONG,
    SC_ERR_POOL_EMPTY,
    SC_ERR_REASSEMBLY,
    SC_ERR_POOL_INIT,
    SC_ERR_NFQ_NOSUPPORT,
    SC_ERR_NFQ_OPEN,
    SC_ERR_NFQ_BIND,
    SC_ERR_NFQ_UNBIND,
    SC_ERR_NFQ_MAXLEN,
    SC_ERR_NFQ_CREATE_QUEUE,
    SC_ERR_NFQ_SET_MODE,
    SC_ERR_NFQ_SETSOCKOPT,
    SC_ERR_NFQ_RECV,
    SC_ERR_NFQ_HANDLE_PKT,
    SC_ERR_NFQ_SET_VERDICT,
    SC_ERR_NFQ_THREAD_INIT,
    SC_ERR_IPFW_NOSUPPORT,
    SC_ERR_IPFW_BIND,
    SC_ERR_IPFW_SOCK,
    SC_ERR_IPFW_NOPORT,
    SC_WARN_IPFW_RECV,
    SC_WARN_IPFW_XMIT,
    SC_WARN_IPFW_SETSOCKOPT,
    SC_WARN_IPFW_UNBIND,
    SC_ERR_DAEMON,
    SC_ERR_UNIMPLEMENTED,
    SC_ERR_ADDRESS_ENGINE_GENERIC,
    SC_ERR_PORT_ENGINE_GENERIC,
    SC_ERR_IPONLY_RADIX,
    SC_ERR_FAST_LOG_GENERIC,
    SC_ERR_DEBUG_LOG_GENERIC,
    SC_ERR_UNIFIED_LOG_GENERIC,
    SC_ERR_HTTP_LOG_GENERIC,
    SC_ERR_TLS_LOG_GENERIC,
    SC_ERR_UNIFIED_ALERT_GENERIC,
    SC_ERR_UNIFIED2_ALERT_GENERIC,
    SC_ERR_FWRITE,
    SC_ERR_THRESHOLD_HASH_ADD,
    SC_ERR_UNDEFINED_VAR,
    SC_ERR_RULE_KEYWORD_UNKNOWN,
    SC_ERR_FLAGS_MODIFIER,
    SC_ERR_DISTANCE_MISSING_CONTENT,
    SC_ERR_WITHIN_MISSING_CONTENT,
    SC_ERR_WITHIN_INVALID,
    SC_ERR_OFFSET_MISSING_CONTENT,
    SC_ERR_DEPTH_MISSING_CONTENT,
    SC_ERR_BYTETEST_MISSING_CONTENT,
    SC_ERR_BYTEJUMP_MISSING_CONTENT,
    SC_ERR_NOCASE_MISSING_PATTERN,
    SC_ERR_RAWBYTES_MISSING_CONTENT,
    SC_ERR_NO_URICONTENT_NEGATION,
    SC_ERR_HASH_TABLE_INIT,
    SC_ERR_STAT,
    SC_ERR_LOGDIR_CONFIG,
    SC_ERR_LOGDIR_CMDLINE,
    SC_ERR_MISSING_CONFIG_PARAM,
    SC_ERR_RADIX_TREE_GENERIC,
    SC_ERR_MISSING_QUOTE,
    SC_ERR_MUTEX,
    SC_ERR_REPUTATION_INVALID_OPERATION,
    SC_ERR_REPUTATION_INVALID_TYPE,
    SC_ERR_UNKNOWN_PROTOCOL, /**< signature contains invalid protocol */
    SC_ERR_UNKNOWN_RUN_MODE,
    SC_ERR_MULTIPLE_RUN_MODE,
    SC_ERR_BPF,
    SC_ERR_BYTE_EXTRACT_FAILED,
    SC_ERR_UNKNOWN_VALUE,
    SC_ERR_INVALID_VALUE,
    SC_ERR_UNKNOWN_REGEX_MOD,
    SC_ERR_INVALID_OPERATOR,
    SC_ERR_PCAP_RECV_INIT,
    SC_ERR_CUDA_ERROR,
    SC_ERR_CUDA_HANDLER_ERROR,
    SC_ERR_TM_THREADS_ERROR,
    SC_ERR_TM_MODULES_ERROR,
    SC_ERR_AC_CUDA_ERROR,
    SC_ERR_INVALID_YAML_CONF_ENTRY,
    SC_ERR_TMQ_ALREADY_REGISTERED,
    SC_ERR_CONFLICTING_RULE_KEYWORDS,
    SC_ERR_INVALID_ACTION,
    SC_ERR_LIBNET_REQUIRED_FOR_ACTION,
    SC_ERR_LIBNET_INIT,
    SC_ERR_LIBNET_INVALID_DIR,
    SC_ERR_LIBNET_BUILD_FAILED,
    SC_ERR_LIBNET_WRITE_FAILED,
    SC_ERR_LIBNET_NOT_ENABLED,
    SC_ERR_UNIFIED_LOG_FILE_HEADER, /**< Error to indicate the unified file
                                         header writing function has been
                                         failed */
    SC_ERR_REFERENCE_UNKNOWN,       /**< unknown reference key (cve, url, etc) */
    SC_ERR_PIDFILE_SNPRINTF,
    SC_ERR_PIDFILE_OPEN,
    SC_ERR_PIDFILE_WRITE,
    SC_ERR_PIDFILE_DAEMON,
    SC_ERR_UID_FAILED,
    SC_ERR_GID_FAILED,
    SC_ERR_CHANGING_CAPS_FAILED,
    SC_ERR_LIBCAP_NG_REQUIRED,
    SC_ERR_LIBNET11_INCOMPATIBLE_WITH_LIBCAP_NG,
    SC_WARN_FLOW_EMERGENCY,
    SC_WARN_COMPATIBILITY,
    SC_ERR_SVC,
    SC_ERR_ERF_DAG_OPEN_FAILED,
    SC_ERR_ERF_DAG_STREAM_OPEN_FAILED,
    SC_ERR_ERF_DAG_STREAM_START_FAILED,
    SC_ERR_ERF_DAG_STREAM_SET_FAILED,
    SC_ERR_ERF_DAG_STREAM_READ_FAILED,
    SC_WARN_ERF_DAG_REC_LEN_CHANGED,
    SC_ERR_DAG_REQUIRED,
    SC_ERR_DAG_NOSUPPORT, /**< no ERF/DAG support compiled in */
    SC_ERR_FATAL,
    SC_ERR_DCERPC,
    SC_ERR_DETECT_PREPARE, /**< preparing the detection engine failed */
    SC_ERR_AHO_CORASICK,
    SC_ERR_REFERENCE_CONFIG,
    SC_ERR_DUPLICATE_SIG, /**< Error to indicate that signature is duplicate */
    SC_WARN_PCAP_MULTI_DEV_EXPERIMENTAL,
    SC_ERR_PCAP_MULTI_DEV_NO_SUPPORT,
    SC_ERR_HTTP_METHOD_NEEDS_PRECEEDING_CONTENT,
    SC_ERR_HTTP_METHOD_INCOMPATIBLE_WITH_RAWBYTES,
    SC_ERR_HTTP_METHOD_RELATIVE_MISSING,
    SC_ERR_HTTP_COOKIE_NEEDS_PRECEEDING_CONTENT,
    SC_ERR_HTTP_COOKIE_INCOMPATIBLE_WITH_RAWBYTES,
    SC_ERR_HTTP_COOKIE_RELATIVE_MISSING,
    SC_ERR_LOGPCAP_SGUIL_BASE_DIR_MISSING,
    SC_ERR_UNKNOWN_DECODE_EVENT,
    SC_ERR_RUNMODE,
    SC_ERR_SHUTDOWN,
    SC_ERR_INVALID_DIRECTION,
    SC_ERR_AFP_CREATE,
    SC_ERR_AFP_READ,
    SC_ERR_AFP_DISPATCH,
    SC_ERR_NO_AF_PACKET,
    SC_ERR_PCAP_FILE_DELETE_FAILED,
    SC_ERR_CMD_LINE,
    SC_ERR_MAGIC_OPEN,
    SC_ERR_MAGIC_LOAD,
    SC_ERR_SIZE_PARSE,
    SC_ERR_RAWBYTES_BUFFER,
    SC_ERR_SOCKET,
    SC_ERR_PCAP_TRANSLATE, /* failed to translate ip to dev */
    SC_WARN_OUTDATED_LIBHTP,
    SC_WARN_DEPRECATED,
    SC_WARN_PROFILE,
    SC_ERR_FLOW_INIT,
    SC_ERR_HOST_INIT,
    SC_ERR_MEM_BUFFER_API,
    SC_ERR_INVALID_MD5,
    SC_ERR_NO_MD5_SUPPORT,
    SC_ERR_EVENT_ENGINE,
    SC_ERR_NO_LUA_SUPPORT,
    SC_ERR_LUA_ERROR,
    SC_ERR_DEFRAG_INIT,
    SC_ERR_NAPATECH_OPEN_FAILED,
    SC_ERR_NAPATECH_STREAM_NEXT_FAILED,
    SC_ERR_NAPATECH_NOSUPPORT,
    SC_ERR_NAPATECH_REQUIRED,
    SC_ERR_NAPATECH_TIMESTAMP_TYPE_NOT_SUPPORTED,
    SC_ERR_NAPATECH_INIT_FAILED,
    SC_ERR_NAPATECH_CONFIG_STREAM,
    SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
    SC_ERR_NAPATECH_STAT_DROPS_FAILED,
    SC_ERR_NAPATECH_PARSE_CONFIG,
    SC_ERR_NO_REPUTATION,
    SC_ERR_NOT_SUPPORTED,
    SC_ERR_IPFW_SETSOCKOPT,
    SC_ERR_NO_GEOIP_SUPPORT,
    SC_ERR_GEOIP_ERROR,
    SC_ERR_LIVE_RULE_SWAP,
    SC_WARN_UNCOMMON,
    SC_ERR_CUDA_BUFFER_ERROR,
    SC_ERR_DNS_LOG_GENERIC,
    SC_WARN_OPTION_OBSOLETE,
    SC_WARN_NO_UNITTESTS,
    SC_ERR_THREAD_QUEUE,
    SC_WARN_XFF_INVALID_MODE,
    SC_WARN_XFF_INVALID_HEADER,
    SC_WARN_XFF_INVALID_DEPLOYMENT,
    SC_ERR_THRESHOLD_SETUP,
    SC_ERR_DNS_CONFIG,
    SC_ERR_MODBUS_CONFIG,
    SC_ERR_CONF_YAML_ERROR,
    SC_ERR_CONF_NAME_TOO_LONG,
    SC_ERR_APP_LAYER_PROTOCOL_DETECTION,
    SC_ERR_PCIE_INIT_FAILED,
    SC_ERR_NFLOG_NOSUPPORT,
    SC_ERR_NFLOG_OPEN,
    SC_ERR_NFLOG_BIND,
    SC_ERR_NFLOG_UNBIND,
    SC_ERR_NFLOG_MAX_BUFSIZ,
    SC_ERR_NFLOG_SET_MODE,
    SC_ERR_NFLOG_HANDLE_PKT,
    SC_ERR_NFLOG_GROUP,
    SC_ERR_NFLOG_FD,
    SC_WARN_NFLOG_RECV,
    SC_WARN_NFLOG_LOSING_EVENTS,
    SC_WARN_NFLOG_MAXBUFSIZ_REACHED,
    SC_WARN_NFLOG_SETSOCKOPT,
    SC_WARN_LUA_SCRIPT,
    SC_ERR_LUA_SCRIPT,
    SC_WARN_NO_STATS_LOGGERS,
    SC_ERR_NO_NETMAP,
    SC_ERR_NETMAP_CREATE,
    SC_ERR_NETMAP_READ,
    SC_ERR_THREAD_DEINIT, /**< thread's deinit function failed */
    SC_ERR_IPPAIR_INIT,
    SC_ERR_MT_NO_SELECTOR,
    SC_ERR_MT_DUPLICATE_TENANT,
    SC_ERR_NO_JSON_SUPPORT,
    SC_ERR_INVALID_RULE_ARGUMENT, /**< Generic error code for invalid
                                   * rule argument. */
    SC_ERR_MT_NO_MAPPING,
    SC_ERR_STATS_LOG_NEGATED,      /**< When totals and threads are both NO in yaml **/
    SC_ERR_JSON_STATS_LOG_NEGATED, /**< When totals and threads are both NO in yaml **/
    SC_ERR_DEPRECATED_CONF,        /**< Deprecated configuration parameter. */
    SC_WARN_FASTER_CAPTURE_AVAILABLE,
    SC_WARN_POOR_RULE,
    SC_ERR_ALERT_PAYLOAD_BUFFER,
    SC_ERR_STATS_LOG_GENERIC,
    SC_ERR_TCPDATA_LOG_GENERIC,
    SC_ERR_FLOW_LOG_GENERIC,
    SC_ERR_NETFLOW_LOG_GENERIC,
    SC_ERR_SMTP_LOG_GENERIC,
    SC_ERR_SSH_LOG_GENERIC,
    SC_ERR_NIC_OFFLOADING,
    SC_ERR_NO_FILES_FOR_PROTOCOL,
    SC_ERR_INVALID_HASH,
    SC_ERR_NO_SHA1_SUPPORT,
    SC_ERR_NO_SHA256_SUPPORT,
    SC_ERR_ENIP_CONFIG,
    SC_ERR_DNP3_CONFIG,
    SC_ERR_DIR_OPEN,
    SC_WARN_REMOVE_FILE,
    SC_ERR_NO_MAGIC_SUPPORT,
    SC_ERR_REDIS,
    SC_ERR_VAR_LIMIT,
    SC_WARN_DUPLICATE_OUTPUT,
    SC_WARN_CHMOD,
    SC_WARN_LOG_CF_TOO_MANY_NODES,
    SC_WARN_EVENT_DROPPED,
    SC_ERR_NO_REDIS_ASYNC,
    SC_ERR_REDIS_CONFIG,
    SC_ERR_BYPASS_NOT_SUPPORTED,
    SC_WARN_RENAMING_FILE,
    SC_ERR_PF_RING_VLAN,
    SC_ERR_CREATE_DIRECTORY,
    SC_WARN_FLOWBIT,
    SC_ERR_SMB_CONFIG,
    SC_WARN_NO_JA3_SUPPORT,
    SC_WARN_JA3_DISABLED,
    SC_ERR_PCAP_LOG_COMPRESS,
    SC_ERR_FSEEK,
    SC_ERR_WINDIVERT_GENERIC,
    SC_ERR_WINDIVERT_NOSUPPORT,
    SC_ERR_WINDIVERT_INVALID_FILTER,
    SC_ERR_WINDIVERT_TOOLONG_FILTER,
    SC_WARN_RUST_NOT_AVAILABLE,
    SC_WARN_DEFAULT_WILL_CHANGE,
    SC_WARN_EVE_MISSING_EVENTS,
    SC_ERR_PLEDGE_FAILED,
    SC_ERR_FTP_LOG_GENERIC,
    SC_ERR_THASH_INIT,
    SC_ERR_DATASET,
    SC_WARN_ANOMALY_CONFIG,
    SC_WARN_ALERT_CONFIG,
    SC_ERR_PCRE_COPY_SUBSTRING,
    SC_WARN_PCRE_JITSTACK,
    SC_WARN_REGISTRATION_FAILED,
    SC_ERR_ERF_BAD_RLEN,
    SC_WARN_ERSPAN_CONFIG,
    SC_WARN_HASSH_DISABLED,
    SC_WARN_FILESTORE_CONFIG,
    SC_WARN_PATH_READ_ERROR,
    SC_ERR_HTTP2_LOG_GENERIC,
    SC_ERR_PLUGIN,
    SC_ERR_LOG_OUTPUT,
    SC_ERR_RULE_INVALID_UTF8,
	SC_ERR_DPDK_CONFIG,
	SC_ERR_DPDK_MEM,

    SC_ERR_MAX
} SCError;

const char *SCErrorToString(SCError);


#endif /* __ERROR_H__ */
