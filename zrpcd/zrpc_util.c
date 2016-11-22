/* 
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "zrpcd/zrpc_memory.h"
#include "zrpcd/zrpc_util.h"
#include "zrpcd/zrpc_debug.h"

struct zrpc_rdrt *zrpc_util_append_rdrt_to_list (u_char *incoming_rdrt, struct zrpc_rdrt *rdrt)
{
  u_char *tmp_target;
  
  if (!rdrt)
    return NULL; 
  rdrt->size++;
  if (rdrt->val == NULL)
    {
      rdrt->val = ZRPC_CALLOC (ZRPC_UTIL_RDRT_SIZE);
      tmp_target = rdrt->val;
    }
  else
    {
      tmp_target = ZRPC_CALLOC (ZRPC_UTIL_RDRT_SIZE*rdrt->size);
      memcpy (tmp_target, rdrt->val, ZRPC_UTIL_RDRT_SIZE*(rdrt->size-1));
      ZRPC_FREE (rdrt->val);
      rdrt->val = tmp_target;
      tmp_target += ZRPC_UTIL_RDRT_SIZE*(rdrt->size-1);
    }
  memcpy (tmp_target, incoming_rdrt, 8);
  return rdrt;
}

/* from string <AS>:<VRF>, build internal uint64_t structure 
 * this function assumes RD and RT are the same
 * return 1 if successfull translation, 0 otherwise
 */
int
zrpc_util_str2rdrt (char *buf, u_char *rd_rt, int type)
{
  char *ptr, *ptr_init;
  unsigned int cnt, dot_presence = 0, remaining_length;
  unsigned long as_val = 0;
  uint64_t vrf_val = 0;
  char buf_local[ZRPC_UTIL_RDRT_LEN];

  /* bad length */
  if(strlen(buf) > ZRPC_UTIL_RDRT_LEN)
    return 0;
  ptr = buf;
  cnt = 0;
  /* search : separator */
  while(*ptr != ':' && cnt < strlen(buf))
    {
      if(*ptr == '.')
        dot_presence = 1;
      ptr++;
      cnt++;
    }
  if(dot_presence)
    return 0;
  /* extract as number */
  if(*ptr == ':')
    {
      strncpy(buf_local, buf, cnt);
      buf_local[cnt]='\0';
      as_val = atol(buf_local);
    }
  /* search for vrf val */
  remaining_length = strlen(buf) - cnt;
  ptr++;
  ptr_init = ptr;
  cnt = 0;
  while(*ptr != '\0' && cnt < remaining_length)
    {
      ptr++;
      cnt++;
    }
  /* extract vrf_number */
  if(*ptr == '\0')
    {
      strncpy(buf_local, ptr_init, cnt);
      buf_local[cnt]='\0';
      vrf_val = atoll(buf_local);
    }
  if(as_val > 0xffff)
    {
      /* RDRT_TYPE_AS4 */
      if (type == ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET)
        {
          rd_rt[0]=2;
          rd_rt[1]=0;
        }
      else
        {
          rd_rt[0]=0;
          rd_rt[1]=2;
        }
      /* AS number */
      rd_rt[2]= (as_val & 0xff000000) >> 24;
      rd_rt[3]= (as_val & 0x00ff0000) >> 16;
      rd_rt[4]= (as_val & 0x0000ff00) >> 8;
      rd_rt[5]= as_val & 0x000000ff;
      /* vrf */
      rd_rt[6]= (vrf_val & 0xff00) >> 8;
      rd_rt[7]= vrf_val & 0xff;
    }
  else
    {
      /* RDRT_TYPE_AS */
      rd_rt[0]=0;
      rd_rt[1]=0;
      /* AS number */
      rd_rt[2]= (as_val & 0x0000ff00) >> 8;
      rd_rt[3]= as_val & 0x000000ff;
      /* vrf */
      rd_rt[4]= (vrf_val & 0xff000000) >> 24;
      rd_rt[5]= (vrf_val & 0xff0000) >> 16;
      rd_rt[6]= (vrf_val & 0xff00) >> 8;
      rd_rt[7]= vrf_val & 0xff;

    }
  if (type == ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET)
    rd_rt[1] = ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET;
  return 1;
}

struct zrpc_rdrt *zrpc_util_rdrt_import (u_char *vals, int listsize)
{
  struct zrpc_rdrt *rdrt;

  rdrt = ZRPC_CALLOC (sizeof (struct zrpc_rdrt));
  rdrt->size = listsize;
  rdrt->val = ZRPC_CALLOC (ZRPC_UTIL_RDRT_SIZE*rdrt->size);
  memcpy (rdrt->val, vals, ZRPC_UTIL_RDRT_SIZE*listsize);
  return rdrt;
}
void zrpc_util_rdrt_free (struct zrpc_rdrt *rdrt)
{
  if (!rdrt)
    return;
  if (rdrt->val)
    ZRPC_FREE (rdrt->val);
  rdrt->val = NULL;
  ZRPC_FREE (rdrt);
  return;
}

int zrpc_util_str2rd_prefix (char *buf, struct zrpc_rd_prefix *rd_p)
{
  int ret;
  ret = zrpc_util_str2rdrt (buf, rd_p->val, ZRPC_UTIL_RDRT_TYPE_OTHER);

  /* family AF_INET */
  rd_p->family = AF_INET;
  rd_p->prefixlen = 0;
  return ret;
}

/* assuming input buffer is on format A.B.C.D/xx 
 * return 0 if error */
int zrpc_util_str2ipv4_prefix (const char *buf, struct zrpc_ipv4_prefix *ipv4_p)
{
  char *pnt, *cp;
  int ret;

  /* Find slash inside string. */
  pnt = strchr (buf, '/');
  if (pnt == NULL) 
    {
      return 0;
    }
  cp = ZRPC_MALLOC ((pnt - buf) + 1);
  strncpy (cp, buf, pnt - buf);
  *(cp + (pnt - buf)) = '\0';
  ret = inet_aton (cp, &ipv4_p->prefix);
  ZRPC_FREE (cp);
  
  /* Get prefix length. */
  ipv4_p->prefixlen = (u_char) atoi (++pnt);
  if (ipv4_p->prefixlen > ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
    return 0;

  ipv4_p->family = AF_INET;
  return  ret;
}

extern char *zrpc_util_rd_prefix2str (struct zrpc_rd_prefix *rd_p, 
                                      char *buf, int size)
{
  u_char *pnt;
  u_int16_t type;

  if (size < ZRPC_UTIL_RDRT_LEN)
    {
      buf[0]='\0';
      return buf;
    }
  pnt = rd_p->val;

  type = (u_int16_t)(pnt[0] << 8) + (u_int16_t) pnt[1];
  pnt+=2;

  if (type == RDRT_TYPE_AS)
    {
      uint16_t rd_as;
      uint32_t rd_val;
      rd_as = (u_int16_t) *pnt++ << 8;
      rd_as |= (u_int16_t) *pnt++;
      rd_val = ((u_int32_t) *pnt++ << 24);
      rd_val |= ((u_int32_t) *pnt++ << 16);
      rd_val |= ((u_int32_t) *pnt++ << 8);
      rd_val |= (u_int32_t) *pnt;
      snprintf (buf, size, "%u:%d", rd_as, rd_val);
      return buf;
    }
  else if (type == RDRT_TYPE_AS4)
    {
      uint16_t rd_val;
      uint32_t rd_as;
  
      rd_as  = (u_int32_t) *pnt++ << 24;
      rd_as |= (u_int32_t) *pnt++ << 16;
      rd_as |= (u_int32_t) *pnt++ << 8;
      rd_as |= (u_int32_t) *pnt++;

      rd_val  = ((u_int16_t) *pnt++ << 8);
      rd_val |= (u_int16_t) *pnt;

      snprintf (buf, size, "%u:%d", rd_as, rd_val);
      return buf;
    }
  buf[0]='\0';
  return buf;
}

int zrpc_util_rd_prefix_cmp (struct zrpc_rd_prefix *rd_p_1,
                                struct zrpc_rd_prefix *rd_p_2)
{
  if(rd_p_1->family != rd_p_2->family)
    return 1;
  if(rd_p_1->prefixlen != rd_p_2->prefixlen)
    return 1;
  if(memcmp((char *)rd_p_1->val, (char *)rd_p_2->val, 8))
    return 1;
  return 0;
}

#if 0
/*
 * retrieve installation path where daemon
 * will be put. Default is /. 0 is returned.
 * if prefix_dir is mentioned, path is /<prefixdir>
 * function returns value > 0 on success, 0 otherwise
 */
#define OPTION_PREFIX_DIR  "--prefix="
int zrpc_cmd_get_path_prefix_dir(char *path, unsigned int size)
{
  char *cfg_args = (char *)QUAGGA_CONFIG_ARGS;
  char *ret, *ret2;
  int len;

  if (cfg_args == NULL || cfg_args[0] == '\0')
    {
      return 0;
    }
  cfg_args = ZRPC_STRDUP ( QUAGGA_CONFIG_ARGS);
  ret = strstr(cfg_args, OPTION_PREFIX_DIR);
  if(ret == NULL)
    {
      ZRPC_FREE ( cfg_args);
      return 0;
    }
  ret+=strlen(OPTION_PREFIX_DIR);
  ret2 = strchr(ret, ' ');
  if(ret2 == NULL)
    {
	ret2 = strchr(ret, '\0');
	if(ret2 == NULL)
          {
            ZRPC_FREE (cfg_args);
	    return 0;
          }
    }
  *ret2 = '\0';
  if(size < strlen(ret) + 1)
    {
      ZRPC_FREE (cfg_args);
      return 0;
    }
  len = snprintf(path, size, "%s", ret);
  ZRPC_FREE (cfg_args);
  return len;
}
#endif

