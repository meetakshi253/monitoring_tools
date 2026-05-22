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
	__u64 latency_ns;
	int retval;
};

struct event {
	__u32 pid;
    __u16 command;
	char tool;
	__u64 cmd_end_time_ns;
	__u64 rqst_id;
	union metrics metric;
	char task[TASK_COMM_LEN];
}; //~48 bytes

#endif /* __AOD_DIAG_H */