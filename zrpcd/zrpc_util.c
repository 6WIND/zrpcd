/* 
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of ZRPC daemon.
 *
 * See the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include "zrpcd/zrpc_memory.h"
#include "zrpcd/zrpc_util.h"
#include "zrpcd/zrpc_debug.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

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
  struct in_addr addr_ipv4;

  if (!buf || !rd_rt)
    return 0;

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
      else if (!isdigit ((int) *ptr))
        return 0;
      ptr++;
      cnt++;
    }

  if (cnt == 0)
    return 0;
  /* extract as number */
  if(*ptr == ':')
    {
      strncpy(buf_local, buf, cnt);
      buf_local[cnt]='\0';
      if(dot_presence)
        {
          if(inet_pton(AF_INET, buf_local, &addr_ipv4))
            as_val = ntohl(addr_ipv4.s_addr);
          else
            return 0;
        }
      else
        as_val = atol(buf_local);
        if (as_val == 0xFFFFFFFF)
          return 0;
    }
  else
    return 0;

  /* search for vrf val */
  remaining_length = strlen(buf) - cnt;
  ptr++;
  ptr_init = ptr;
  cnt = 0;
  while(*ptr != '\0' && cnt < remaining_length)
    {
      if (!isdigit ((int) *ptr))
        return 0;
      ptr++;
      cnt++;
    }

  if (cnt == 0)
    return 0;

  /* extract vrf_number */
  if(*ptr == '\0')
    {
      strncpy(buf_local, ptr_init, cnt);
      buf_local[cnt]='\0';
      vrf_val = atoll(buf_local);
    }

  if(dot_presence)
    {
      if (vrf_val > UINT16_MAX)
        return 0;
      /* RD_TYPE_IP */
      if (type == ZRPC_UTIL_RDRT_TYPE_ROUTE_TARGET)
        {
          rd_rt[0]=1;
          rd_rt[1]=0;
        }
      else
        {
          rd_rt[0]=0;
          rd_rt[1]=1;
        }
      /* IP Address */
      rd_rt[2]= (as_val & 0xff000000) >> 24;
      rd_rt[3]= (as_val & 0x00ff0000) >> 16;
      rd_rt[4]= (as_val & 0x0000ff00) >> 8;
      rd_rt[5]= as_val & 0x000000ff;
      /* vrf */
      rd_rt[6]= (vrf_val & 0xff00) >> 8;
      rd_rt[7]= vrf_val & 0xff;
    }
  else if(as_val > 0xffff)
    {
      if (vrf_val > UINT16_MAX)
        return 0;

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
      ipv4_p->prefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
      ipv4_p->family = AF_INET;
      ret = inet_aton (buf, &ipv4_p->prefix);
      return ret;
    }
  cp = ZRPC_MALLOC ((pnt - buf) + 1);
  strncpy (cp, buf, pnt - buf);
  *(cp + (pnt - buf)) = '\0';
  ret = inet_aton (cp, &ipv4_p->prefix);
  ZRPC_FREE (cp);
  if (ret == 0)
    return 0;
  /* Get prefix length. */
  ipv4_p->prefixlen = (u_char) atoi (++pnt);
  if (ipv4_p->prefixlen > ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
    return 0;

  ipv4_p->family = AF_INET;
  return  ret;
}

int zrpc_util_convert_ipv6mappedtoipv4 (struct zrpc_prefix *pfx)
{
  struct in_addr pfx_ipv4;

  if (pfx->family != AF_INET6)
    return -1;
  memset (&pfx_ipv4, 0, sizeof(struct in_addr));
  char *ptr = (char *)&(pfx->u.prefix6.s6_addr);
  ptr+=12;
  memcpy (&pfx_ipv4, ptr, sizeof (struct in_addr));
  pfx->family = AF_INET;
  pfx->prefixlen = ZRPC_UTIL_IPV4_PREFIX_LEN_MAX;
  memcpy(&(pfx->u.prefix), &pfx_ipv4, sizeof(struct in_addr));
  return 0;
}

int zrpc_util_convert_ipv4toipv6mapped (struct zrpc_prefix *pfx)
{
  struct in6_addr pfx_ipv6;

  if (pfx->family != AF_INET)
    return -1;
  memset (&pfx_ipv6, 0, sizeof(struct in6_addr));
  char *ptr = (char *)&(pfx_ipv6.s6_addr);
  ptr+=10;
  *ptr++=0xff;
  *ptr++=0xff;
  memcpy (ptr, &(pfx->u.prefix), sizeof (struct in_addr));
  pfx->family = AF_INET6;
  pfx->prefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
  memcpy(&(pfx->u.prefix), &pfx_ipv6, sizeof(struct in6_addr));
  return 0;
}

/* assuming input buffer is on format A.B.C.D/xx 
 * return 0 if error */
int zrpc_util_str2ipv6_prefix (const char *buf, struct zrpc_ipv6_prefix *ipv6_p)
{
  char *pnt;
  char *cp;
  int ret;

  pnt = strchr (buf, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL) 
    {
      ipv6_p->prefixlen = ZRPC_UTIL_IPV6_PREFIX_LEN_MAX;
      ipv6_p->family = AF_INET6;
      ret = inet_pton (AF_INET6, buf, &ipv6_p->prefix);
      return ret;
    }
  cp = ZRPC_MALLOC ((pnt - buf) + 1);
  strncpy (cp, buf, pnt - buf);
  *(cp + (pnt - buf)) = '\0';
  ret = inet_pton (AF_INET6, cp, &ipv6_p->prefix);
  ZRPC_FREE (cp);
  if (ret == 0)
    return 0;
  ipv6_p->prefixlen = (u_char) atoi (++pnt);
  if (ipv6_p->prefixlen > ZRPC_UTIL_IPV6_PREFIX_LEN_MAX)
    return 0;
  ipv6_p->family = AF_INET6;
  return ret;
}

int zrpc_util_prefix_2str (struct zrpc_prefix *pfx, char *buf, socklen_t len)
{
  char *ptr;
  int ret = 0;

  if ( pfx->family == AF_INET && len >= ZRPC_UTIL_IPV4_LEN_MAX)
    {
      const void *src =  &pfx->u.prefix4;
      ptr = ( char *)inet_ntop (AF_INET, src, buf, (socklen_t)len);
      if (ptr == NULL)
        return 0;
      ptr += strlen(buf);
      if (pfx->prefixlen != ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
        sprintf (ptr, "/%u", pfx->prefixlen);
      return ret;
    }
  if ( pfx->family == AF_INET6 && len >= ZRPC_UTIL_IPV6_LEN_MAX)
    {
      const void *src =  &pfx->u.prefix6;
      ptr = (char *)inet_ntop (AF_INET6, src, buf, (socklen_t)len);
      if (ptr == NULL)
        return 0;
      ptr += strlen(buf);
      if (pfx->prefixlen != ZRPC_UTIL_IPV6_PREFIX_LEN_MAX)
        sprintf (ptr, "/%u", pfx->prefixlen);
    }

  if (pfx->family == AF_L2VPN && len >= ZRPC_UTIL_L2VPN_LEN_MAX)
    {
      char str[BUFSIZ];

      if (pfx->u.prefix_evpn.route_type == 3)
        {
          if (pfx->u.prefix_evpn.u.prefix_imethtag.ip_len == ZRPC_UTIL_IPV4_PREFIX_LEN_MAX)
            inet_ntop (AF_INET, &pfx->u.prefix_evpn.u.prefix_imethtag.ip.in4, str, BUFSIZ);
          else
            inet_ntop (AF_INET6, &pfx->u.prefix_evpn.u.prefix_imethtag.ip.in4, str, BUFSIZ);
          snprintf (buf, len, "[%u][%d][%s]",
                    pfx->u.prefix_evpn.u.prefix_imethtag.eth_tag_id,
                    pfx->u.prefix_evpn.u.prefix_imethtag.ip_len,
                    str);
        }
      else
        {
          if (ZRPC_L2VPN_PREFIX_HAS_IPV4(pfx))
            inet_ntop (AF_INET, &pfx->u.prefix_evpn.u.prefix_macip.ip.in4, str, BUFSIZ);
          else if (ZRPC_L2VPN_PREFIX_HAS_IPV6(pfx))
            inet_ntop (AF_INET6, &pfx->u.prefix_evpn.u.prefix_macip.ip.in6, str, BUFSIZ);
          else if (ZRPC_L2VPN_PREFIX_HAS_NOIP(pfx))
            strcpy(str, "none");
          snprintf (buf, len, "[%u][%02x:%02x:%02x:%02x:%02x:%02x/%d][%s/%d]",
                    pfx->u.prefix_evpn.u.prefix_macip.eth_tag_id,
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[0],
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[1],
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[2],
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[3],
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[4],
                    pfx->u.prefix_evpn.u.prefix_macip.mac.octet[5],
                    pfx->u.prefix_evpn.u.prefix_macip.mac_len,
                    str,
                    pfx->u.prefix_evpn.u.prefix_macip.ip_len);
        }
    }

  return ret;
}

void zrpc_util_copy_prefix (struct zrpc_prefix *dst, struct zrpc_prefix *src)
{
  dst->family = src->family;
  dst->prefixlen = src->prefixlen;

  if (dst->family == AF_INET)
    dst->u.prefix4 = src->u.prefix4;
  else if (src->family == AF_INET6)
    dst->u.prefix6 = src->u.prefix6;
  return;
}

int zrpc_util_str2_prefix (const char *buf, struct zrpc_prefix *prefix_p)
{
  struct zrpc_ipv6_prefix *ipv6_p;
  struct zrpc_ipv4_prefix *ipv4_p;
  int ret;

  ipv4_p = (struct zrpc_ipv4_prefix *)prefix_p;
  ret = zrpc_util_str2ipv4_prefix (buf, ipv4_p);
  if (ret)
    return ret;

  ipv6_p = (struct zrpc_ipv6_prefix *)prefix_p;
  ret = zrpc_util_str2ipv6_prefix (buf, ipv6_p);
  return ret;
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
  else if (type == RDRT_TYPE_IP)
    {
      struct in_addr ip_add;
      uint16_t rd_val;

      memcpy (&ip_add, pnt, 4);
      pnt+=4;
      rd_val  = ((u_int16_t) *pnt++ << 8);
      rd_val |= (u_int16_t) *pnt;

      snprintf (buf, size, "%s:%d", inet_ntoa (ip_add), rd_val);
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

#ifndef HAVE_FCNTL
/*
 * read pid number in file
 * return pid id if valid, 0 otherwise
 */
uint32_t
zrpc_util_get_pid_output (const char *path)
{
  FILE *fp;
  uint32_t pid;

  fp = fopen (path, "r");
  if (fp != NULL)
    {
      fscanf (fp, "%d\n", &pid);
      fclose (fp);
       
      return pid;
    }
  /* XXX Why do we continue instead of exiting?  This seems incompatible
     with the behavior of the fcntl version below. */
  zrpc_log("Can't fopen pid lock file %s (%u), continuing",
	    path, errno);
  return 0;
}
#else
/*
 * read pid number in file
 * return pid id if valid, 0 otherwise
 */
uint32_t
zrpc_util_get_pid_output (const char *path)
{
  int fd;
  char buf[16];
  char *ptr;
  uint32_t pid;

  fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      zrpc_log ("Can't open pid lock file %s (%s), continuing",
                path, safe_strerror(errno));
      return 0;
    }

  memset(buf, '\0', sizeof(buf));
  ptr = buf;
  read (fd, ptr, 16);
  pid = atoi(buf);

  close(fd);
  return pid;
}

#endif /* HAVE_FCNTL */

void zrpc_kill_child(const char *pidfile, const char *process_name)
{
  pid_t pid;
  int ret;

  pid = zrpc_util_get_pid_output(pidfile);
  if (pid)
    {
      ret = kill(pid, SIGINT);
      if (ret == 0)
          unlink(pidfile);
      zrpc_log("Kill %s instance (%d) %s", process_name,
               pid, ret == 0 ? "OK" : "NOK");
    }
}

/* Clean tmp files for created by bgpd/bfdd */
void zrpc_clean_tmp_files_for_bgpd_bfdd(void)
{
  DIR* dir;
  struct dirent* ent;
  char buf[512] = {0};
  const char *tmp = "/tmp";
  int ret;

  if (!(dir = opendir(tmp))) {
    zrpc_log("can't open %s", tmp);
    return;
  }
  while ((ent = readdir(dir)) != NULL) {
    if (strstr(ent->d_name, "qzc-")) {
      snprintf(buf, sizeof(buf), "%s/%s", tmp, ent->d_name);
      ret=remove(buf);
      zrpc_log("remove(%s), ret=%d\n", buf, ret);
    }
  }
  closedir(dir);
}

uint32_t zrpc_util_proc_find(const char* name) 
{
  DIR* dir;
  struct dirent* ent;
  char* endptr;
  char buf[512];

  if (!(dir = opendir("/proc"))) {
    perror("can't open /proc");
    return -1;
  }

  while((ent = readdir(dir)) != NULL) {
    /* if endptr is not a null character, the directory is not
     * entirely numeric, so ignore it */
    long lpid = strtol(ent->d_name, &endptr, 10);
    if (*endptr != '\0') {
      continue;
    }
    if (lpid == getpid())
      continue;
    /* try to open the cmdline file */
    snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
    FILE* fp = fopen(buf, "r");

    if (fp) {
      if (fgets(buf, sizeof(buf), fp) != NULL) {
        /* check the first token in the file, the program name */
        char* first = strtok(buf, " ");
        if (!strcmp(first, name)) {
          fclose(fp);
          closedir(dir);
          return lpid;
        }
      }
      fclose(fp);
    }

  }

  closedir(dir);
  return -1;
}

static uint8_t zrpc_util_convertchartohexa (uint8_t *hexa, int *error)
{
  if( (*hexa == '0') || (*hexa == '1') || (*hexa == '2') ||
      (*hexa == '3') || (*hexa == '4') || (*hexa == '5') ||
      (*hexa == '6') || (*hexa == '7') || (*hexa == '8') ||
      (*hexa == '9'))
    return (uint8_t)(*hexa)-'0';
  if((*hexa == 'a') || (*hexa == 'A'))
    return 0xa;
  if((*hexa == 'b') || (*hexa == 'B'))
    return 0xb;
  if((*hexa == 'c') || (*hexa == 'C'))
    return 0xc;
  if((*hexa == 'd') || (*hexa == 'D'))
    return 0xd;
  if((*hexa == 'e') || (*hexa == 'E'))
    return 0xe;
  if((*hexa == 'f') || (*hexa == 'F'))
    return 0xf;
  *error = -1;
  return 0;
}

/* converts to internal representation of mac address
 * returns 1 on success, 0 otherwise 
 * format accepted: AA:BB:CC:DD:EE:FF
 * if mac parameter is null, then check only
 */
int
zrpc_util_str2mac (const char *str, char *mac)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;

  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 6)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 5)
            {
              zrpc_log("[%s]: format non recognized",mac);
              return 0;
            }
          len = strlen((char *)ptr);
	} 
      else
        {
          len = ptr2 - ptr;
        }
      if(len > 5)
        {
          zrpc_log("[%s]: format non recognized",mac);
         return 0;
        }
      memcpy(temp, ptr, len);
      for(j=0;j< len;j++)
	{
	  if (k >= ZRPC_MAC_LEN)
	    return 0;
          if(mac)
            mac[k] = 0;
          car = zrpc_util_convertchartohexa (&temp[j], &error);
	  if (error)
	    return 0;
	  if(mac)
            mac[k] = car << 4;
	  j++;
          if(j == len)
            return 0;
          car = zrpc_util_convertchartohexa (&temp[j], &error) & 0xf;
	  if (error)
	    return 0;
	  if(mac)
            mac[k] |= car & 0xf;
	  k++;
	  i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(mac && 0)
    {
      zrpc_log("leave correct : %02x:%02x:%02x:%02x:%02x:%02x",
               mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
               mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
    }
  return 1;
}

/* converts to an esi
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF:GG:HH:II:JJ
 * if id is null, check only is done
 */
int
zrpc_util_str2esi (const char *str, struct zrpc_eth_segment_id *id)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;
  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 10)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 9)
            {
              zrpc_log("[%s]: format non recognized",str);
              return 0;
            }
          len = strlen((char *)ptr);
	}
      else
        {
          len = ptr2 - ptr;
        }
      memcpy(temp, ptr, len);
      if(len > 5)
        {
          zrpc_log("[%s]: format non recognized",str);
         return 0;
        }
      for(j=0;j< len;j++)
	{
	  if (k >= ZRPC_ESI_LEN)
	    return 0;
          if(id)
            id->val[k] = 0;
          car = zrpc_util_convertchartohexa (&temp[j], &error);
          if (error)
            return 0;
          if(id)
            id->val[k] = car << 4;
          j++;
          if(j == len)
            return 0;
          car = zrpc_util_convertchartohexa (&temp[j], &error) & 0xf;
          if (error)
            return 0;
          if(id)
            id->val[k] |= car & 0xf;
         k++;
         i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(id && 0)
    {
      zrpc_log("leave correct : %02x:%02x:%02x:%02x:%02x",
               id->val[0], id->val[1], id->val[2], id->val[3], id->val[4]);
      zrpc_log("%02x:%02x:%02x:%02x:%02x",
               id->val[5], id->val[6], id->val[7], id->val[8], id->val[9]);
    }
  return 1;
}

char *
zrpc_util_esi2str (struct zrpc_eth_segment_id *id)
{
  char *ptr;
  u_char *val;

  if(!id)
    return NULL;

  val = id->val;
  ptr = (char *) malloc ((ZRPC_ESI_LEN*2+ZRPC_ESI_LEN-1+1)*sizeof(char));

  snprintf (ptr, (ZRPC_ESI_LEN*2+ZRPC_ESI_LEN-1+1),
            "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            val[0], val[1], val[2], val[3], val[4],
            val[5], val[6], val[7], val[8], val[9]);

  return ptr;
}

char *
zrpc_util_mac2str (char *mac)
{
  char *ptr;

  if(!mac)
    return NULL;

  ptr = (char *) malloc ((ZRPC_MAC_LEN*2+ZRPC_MAC_LEN-1+1)*sizeof(char));

  snprintf (ptr, (ZRPC_MAC_LEN*2+ZRPC_MAC_LEN-1+1), "%02x:%02x:%02x:%02x:%02x:%02x",
           (uint8_t) mac[0], (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3],
           (uint8_t)mac[4], (uint8_t)mac[5]);

  return ptr;
}

char *zrpc_util_ecom_mac2str(char *ecom_mac)
{
  char *en;

  en = ecom_mac;
  en+=2;
  return zrpc_util_mac2str(en);
}
