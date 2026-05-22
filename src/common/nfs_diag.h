// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 Microsoft */
#ifndef __NFS_DIAG_H
#define __NFS_DIAG_H

#include "aod_diag.h"

#define MAX_NFS_COMMANDS        70

#define NFSSLOWER               10

struct nfs_partial_event {
    __u16 nfscommand;
	union metrics metric;
};
// __u16 is sufficient for nfscommand, even though rpc_procinfo stores it as u32

#endif /* __NFS_DIAG_H */