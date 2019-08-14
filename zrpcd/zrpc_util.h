/* Zrpc utilities
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */
#ifndef _QUAGGA_ZRPC_UTIL_H
#define _QUAGGA_ZRPC_UTIL_H

#include <arpa/inet.h>
#include <stdint.h>

#ifdef __GNUC__
#  ifdef __LP64__               /* is m64, 8 byte align */
#    define PREFIX_GCC_ALIGN_ATTRIBUTES __attribute__ ((aligned (8)))
#  else                         /* must be m32, 4 byte align */
#    define PREFIX_GCC_ALIGN_ATTRIBUTES __attribute__ ((aligned (4)))
#  endif
#else                           /* not GCC, no alignment attributes */
#  define PREFIX_GCC_ALIGN_ATTRIBUTES
#endif

#define RDRT_TYPE_AS  0x00
#define RDRT_TYPE_IP  0x01
#define RDRT_TYPE_AS4 0x02

/* Low-order octet of the Extended Communities type field.  */
#define ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET 0x02
#define ZRPC_UTIL_RDRT_TYPE_OTHER        0x00

/* Extended Communities value is eight octet long.  */
#define ZRPC_UTIL_RDRT_SIZE                  8
#define ZRPC_UTIL_RDRT_LEN                  28
#define ZRPC_UTIL_IPV4_PREFIX_LEN_MAX       32
#define ZRPC_UTIL_IPV4_LEN_MAX              20
#define ZRPC_UTIL_IPV6_LEN_MAX              51
#define ZRPC_UTIL_IPV6_PREFIX_LEN_MAX      128

/* Max bit/byte length of IPv6 address. */
#define ZRPC_UTIL_IPV6_MAX_BYTELEN    16
#define ZRPC_UTIL_IPV6_MAX_BITLEN    128

/* for handling BGP pid */
#define ZRPC_UTIL_PIDFILE_MASK 0644

/* Address family numbers from RFC1700. */
typedef enum {
  ADDRESS_FAMILY_IP  = 1,
  ADDRESS_FAMILY_IPV6  = 2,
  ADDRESS_FAMILY_L2VPN = 4,
  ADDRESS_FAMILY_MAX  = 5,
} address_family_t;

#define SUBSEQUENT_ADDRESS_FAMILY_LABELED_UNICAST      6
#define SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN             3
#define SUBSEQUENT_ADDRESS_FAMILY_EVPN                 5
#define SUBSEQUENT_ADDRESS_FAMILY_MAX                  7
typedef u_int8_t subsequent_address_family_t;

/* value of first byte of ESI */
#define ZRPC_ESI_TYPE_ARBITRARY 0 /* */
#define ZRPC_ESI_TYPE_LACP      1 /* <> */
#define ZRPC_ESI_TYPE_BRIDGE    2 /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ZRPC_ESI_TYPE_MAC       3 /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ZRPC_ESI_TYPE_ROUTER    4 /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ZRPC_ESI_TYPE_AS        5 /* <AS-4B>:<Local Discriminator Value-4B> */
#define ZRPC_MAX_ESI {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}
#define ZRPC_ESI_LEN 10

#define ZRPC_MAC_LEN 6

/* reuse AF_L2VPN define */
#define AF_L2VPN 44

struct zrpc_ethaddr {
    u_char octet[ZRPC_MAC_LEN];
} __attribute__ ((packed));


struct zrpc_eth_segment_id
{
  u_char val[ZRPC_ESI_LEN];
};

/* Extended Communities attribute.  */
struct zrpc_rdrt
{
  /* Reference counter.  */
  unsigned long refcnt;

  /* Size of Extended Communities attribute.  */
  int size;

  /* Extended Communities value.  */
  u_int8_t *val;
};

struct zrpc_rd_prefix
{
  u_char family;
  u_char prefixlen;
  u_char val[8] PREFIX_GCC_ALIGN_ATTRIBUTES;
};

struct zrpc_ipv4_prefix
{
  u_char family;
  u_char prefixlen;
  struct in_addr prefix PREFIX_GCC_ALIGN_ATTRIBUTES;
};

struct zrpc_ipv6_prefix
{
  u_char family;
  u_char prefixlen;
  struct in6_addr prefix PREFIX_GCC_ALIGN_ATTRIBUTES;
};

struct zrpc_macipaddr {
  u_int32_t eth_tag_id;
  u_int8_t mac_len;
  struct zrpc_ethaddr mac;
  u_int8_t ip_len;
  union
  {
    struct in_addr in4;             /* AF_INET */
    struct in6_addr in6;            /* AF_INET6 */
  } ip __attribute__ ((packed));
}__attribute__ ((packed));

struct zrpc_imet_tag {
  u_int32_t eth_tag_id;
  u_int8_t ip_len;
  union
  {
    struct in_addr in4;             /* AF_INET */
    struct in6_addr in6;            /* AF_INET6 */
  } ip __attribute__ ((packed));
} __attribute__ ((packed));

struct zrpc_evpn_addr {
  uint8_t route_type;
/* EVPN route types as per RFC7432 and
 * as per draft-ietf-bess-evpn-prefix-advertisement-02
 */
#define EVPN_ETHERNET_AUTO_DISCOVERY 1
#define EVPN_MACIP_ADVERTISEMENT 2
#define EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG 3
#define EVPN_ETHERNET_SEGMENT 4
#define EVPN_IP_PREFIX 5
  union {
    struct zrpc_macipaddr prefix_macip;      /* AF_L2VPN */
    struct zrpc_macipaddr prefix_ipvrf;      /* AF_L2VPN */
    struct zrpc_imet_tag prefix_imethtag;    /* AF_L2VPN */
  } u;
};

struct zrpc_prefix
{
  u_char family;
  u_char prefixlen;
  union 
  {
    u_char prefix;
    struct in_addr prefix4;
    struct in6_addr prefix6;
    struct zrpc_evpn_addr prefix_evpn; /* AF_L2VPN */
  } u __attribute__ ((aligned (8)));
};
#define ZRPC_L2VPN_PREFIX_HAS_IPV4(p)  ((p)->u.prefix_evpn.u.prefix_macip.ip_len == ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
#define ZRPC_L2VPN_PREFIX_HAS_IPV6(p)  ((p)->u.prefix_evpn.u.prefix_macip.ip_len == ZRPC_UTIL_IPV6_PREFIX_LEN_MAX)
#define ZRPC_L2VPN_PREFIX_HAS_NOIP(p)  ((p)->u.prefix_evpn.u.prefix_macip.ip_len == 0)

/* for EVPN route type 2 */
#define ZRPC_L2VPN_NOIP_PREFIX_LEN ((ZRPC_MAC_LEN + 4 /*ethtag*/+ 2 /*mac len + ip len*/ + 1 /* route type */) * 8)
#define ZRPC_L2VPN_IPV4_PREFIX_LEN ((ZRPC_MAC_LEN + 4 /*ethtag*/+ 4 /*IP address*/ + 2 /*mac len + ip len*/ + 1 /* route type */) * 8)
#define ZRPC_L2VPN_IPV6_PREFIX_LEN ((ZRPC_MAC_LEN + 4 /*ethtag*/+ 16 /*IP address*/ + 2 /*mac len + ip len*/ + 1 /* route type */) * 8)

#define ZRPC_L2VPN_PREFIX_ETHTAGLEN (8 * sizeof(u_int32_t))
#define ZRPC_L2VPN_PREFIX_AD (8 * sizeof (struct zrpc_eth_segment_id) + ZRPC_L2VPN_PREFIX_ETHTAGLEN)

/* for EVPN route type 3 */
#define ZRPC_L2VPN_MCAST_PREFIX_LEN (( 4 /* ethtag */ + 1 /* IP length */ \
                                       + 16 /* IP Address */ + 1 /* route type */) * 8)

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
  ((((a)->in6_u.u6_addr16[0]) == 0) && \
  (((a)->in6_u.u6_addr16[1]) == 0) && \
  (((a)->in6_u.u6_addr16[2]) == 0) && \
  (((a)->in6_u.u6_addr16[3]) == 0) && \
  (((a)->in6_u.u6_addr16[4]) == 0) && \
   (((a)->in6_u.u6_addr16[5]) == 0xFFFF))
#endif

extern struct zrpc_rdrt *zrpc_util_append_rdrt_to_list (u_char *, struct zrpc_rdrt *); 
extern int zrpc_util_str2rd_prefix (char *buf, struct zrpc_rd_prefix *rd_p);
extern int zrpc_util_str2ipv4_prefix (const char *buf, struct zrpc_ipv4_prefix *ipv4_p);
extern int zrpc_util_str2ipv6_prefix (const char *buf, struct zrpc_ipv6_prefix *ipv6_p);
extern int zrpc_util_str2_prefix (const char *buf, struct zrpc_prefix *prefix_p);
extern void zrpc_util_copy_prefix (struct zrpc_prefix *dst, struct zrpc_prefix *src);
extern int zrpc_util_prefix_2str (struct zrpc_prefix *pfx, char *buf, socklen_t len);

extern int zrpc_util_str2rdrt (char *buf, u_char *rd_rt, int type);
extern void zrpc_util_rdrt_free (struct zrpc_rdrt *rdrt);
extern char *zrpc_util_rd_prefix2str (struct zrpc_rd_prefix *rd_p, 
                                        char *buf, int size);
extern int zrpc_util_rd_prefix_cmp (struct zrpc_rd_prefix *rd_p_1,
                                        struct zrpc_rd_prefix *rd_p_2);
struct zrpc_rdrt *zrpc_util_rdrt_import (u_char *vals, int listsize);

#if 0
extern int zrpc_cmd_get_path_prefix_dir(char *path, unsigned int size);
#endif
extern uint32_t zrpc_util_get_pid_output (const char *path);
extern void zrpc_kill_child(const char *, const char *);
extern uint32_t zrpc_util_proc_find(const char* name);
extern void zrpc_clean_tmp_files_for_bgpd_bfdd(void);

extern int zrpc_util_str2esi (const char *str, struct zrpc_eth_segment_id *id);
extern int zrpc_util_str2mac (const char *str, char *mac);
extern char *zrpc_util_esi2str (struct zrpc_eth_segment_id *id);
extern char *zrpc_util_mac2str (char *mac);
extern char *zrpc_util_ecom_mac2str(char *ecom_mac);
extern int zrpc_util_convert_ipv4toipv6mapped (struct zrpc_prefix *pfx);
extern int zrpc_util_convert_ipv6mappedtoipv4 (struct zrpc_prefix *pfx);

#endif /* _QUAGGA_ZRPC_UTIL_H */
