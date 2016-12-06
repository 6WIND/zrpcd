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
#define ZRPC_UTIL_IPV6_LEN_MAX              51

/* for handling BGP pid */
#define ZRPC_UTIL_PIDFILE_MASK 0644

/* Address family numbers from RFC1700. */
typedef enum {
  ADDRESS_FAMILY_IP  = 1,
  ADDRESS_FAMILY_L2VPN = 4,
  ADDRESS_FAMILY_MAX  = 5,
} address_family_t;

#define SUBSEQUENT_ADDRESS_FAMILY_MPLS_VPN             4
#define SUBSEQUENT_ADDRESS_FAMILY_EVPN                 5
#define SUBSEQUENT_ADDRESS_FAMILY_MAX                  6
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

struct zrpc_eth_segment_id
{
  u_char val[ZRPC_ESI_LEN];
};

#define ZRPC_MAC_LEN 6

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


extern struct zrpc_rdrt *zrpc_util_append_rdrt_to_list (u_char *, struct zrpc_rdrt *); 
extern int zrpc_util_str2rd_prefix (char *buf, struct zrpc_rd_prefix *rd_p);
extern int zrpc_util_str2ipv4_prefix (const char *buf, struct zrpc_ipv4_prefix *ipv4_p);
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

extern int zrpc_util_str2esi (const char *str, struct zrpc_eth_segment_id *id);
extern int zrpc_util_str2mac (const char *str, char *mac);
extern char *zrpc_util_esi2str (struct zrpc_eth_segment_id *id);
extern char *zrpc_util_mac2str (char *mac);
extern char *zrpc_util_ecom_mac2str(char *ecom_mac);

#endif /* _QUAGGA_ZRPC_UTIL_H */
