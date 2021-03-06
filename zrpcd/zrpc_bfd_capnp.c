/*
 * Copyright (c) 2018 6WIND
 * This file is part of ZRPC daemon.
 * See the LICENSE file.
 */

#include <stdbool.h>
#include "capnp_c.h"
#include "zrpcd/zrpc_bfd_capnp.h"

static const capn_text capn_val0 = {0, ""};

capn_ptr qcapn_new_BFD(struct capn_segment *s)
{
    return capn_new_struct(s, 20, 3);
}

void qcapn_BFD_write(const struct bfd *s, capn_ptr p)
{
    capn_resolve(&p);
    capn_write8(p, 0, s->config_data_version);
    capn_write8(p, 1, s->failure_threshold);
    capn_write8(p, 2, s->multihop);
    capn_write32(p, 4, s->rx_interval);
    capn_write32(p, 8, s->tx_interval);
    capn_write32(p, 12, s->debounce_down);
    capn_write32(p, 16, s->debounce_up);
    { capn_text tp = { .str = s->logFile, .len = s->logFile ? strlen(s->logFile) : 0 }; capn_set_text(p, 0, tp); }
    { capn_text tp = { .str = s->logLevel, .len = s->logLevel ? strlen(s->logLevel) : 0 }; capn_set_text(p, 1, tp); }
    { capn_text tp = { .str = s->logLevelSyslog, .len = s->logLevelSyslog ?
                       strlen(s->logLevelSyslog) : 0 }; capn_set_text(p, 2, tp); }
}

void qcapn_BFD_read(struct bfd *s, capn_ptr p)
{
    capn_resolve(&p);

    s->config_data_version = capn_read8(p, 0);
    s->failure_threshold = capn_read8(p, 1);
    s->multihop = capn_read8(p, 2);
    s->rx_interval = capn_read32(p, 4);
    s->tx_interval = capn_read32(p, 8);
    s->debounce_down = capn_read32(p, 12);
    s->debounce_up = capn_read32(p, 16);

    { capn_text tp = capn_get_text(p, 0, capn_val0); free(s->logFile); s->logFile = strdup(tp.str); }
    { capn_text tp = capn_get_text(p, 1, capn_val0); free(s->logLevel); s->logLevel = strdup(tp.str); }
    { capn_text tp = capn_get_text(p, 2, capn_val0);
      free(s->logLevelSyslog);
      s->logLevelSyslog = strdup(tp.str); }
}
