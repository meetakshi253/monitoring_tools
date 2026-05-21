/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Microsoft */
#ifndef __AOD_DIAG_H
#define __AOD_DIAG_H

#define TASK_COMM_LEN   16
#define MAX_ENTRIES     2048
#define RINGBUF_PINNED "/sys/fs/bpf/aodrb"

/* Pinned link paths */
#define LINK_SMB_MID_ALLOC   "/sys/fs/bpf/aod_smb_mid_alloc"
#define LINK_SMB_MID_RELEASE "/sys/fs/bpf/aod_smb_mid_release"
#define LINK_NFS_SEQ_SETUP   "/sys/fs/bpf/aod_nfs_seq_setup"
#define LINK_NFS_RPC_EXIT    "/sys/fs/bpf/aod_nfs_rpc_exit"

union metrics {
	unsigned long long latency_ns;
	int retval;
};

struct event {
	int pid;
    int command;
	unsigned long long cmd_end_time_ns;
	unsigned long long rqst_id;
	union metrics metric;
	char tool;
	char task[TASK_COMM_LEN];
}; //56 bytes

#endif /* __AOD_DIAG_H */