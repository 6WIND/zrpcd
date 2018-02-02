/*
 * Copyright (c) 2018 6WIND
 * This file is part of ZRPC daemon.
 * See the LICENSE file.
 */

#ifndef _ZRPC_BFD_CAPNP_H
#define _ZRPC_BFD_CAPNP_H

#include "zrpcd/zrpc_util.h"
#include "zrpcd/qzcclient.h"

/* BFD instance structure.  */
struct bfd
{
  u_char     config_data_version;
  u_char     failure_threshold;
  u_int32_t  rx_interval;
  u_int32_t  tx_interval;
  u_int32_t  debounce_down;
  u_int32_t  debounce_up;
  uint8_t    multihop;

  char *logFile;
  char *logLevel;
};

capn_ptr qcapn_new_BFD(struct capn_segment *s);
void qcapn_BFD_read(struct bfd *s, capn_ptr p);
void qcapn_BFD_write(const struct bfd *s, capn_ptr p);
#endif /* _ZRPC_BFD_CAPNP_H */
