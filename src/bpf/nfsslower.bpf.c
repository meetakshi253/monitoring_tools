// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "nfs_diag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_lat_ns = 0;
const volatile int wakeup_data_size = 256;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NFS_COMMANDS); /* NFS commands */
	__type(key, __u16); /* Command code */
	__type(value, __u8); /* Dummy value */
} denylist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 4096);
	__type(key, struct rpc_task *); /* ptr to rpc_task */
	__type(value, struct nfs_partial_event);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096); // should always be a multiple of the page size
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aodrb SEC(".maps");

static __always_inline long get_flags()
{
	long sz;
	if (!wakeup_data_size)
		return 0;
	sz = bpf_ringbuf_query(&aodrb, BPF_RB_AVAIL_DATA);
	return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

/** !Not ideal! The program still emits CORE relocations, but we are only
 * concerned about Azure VM images for now. Most of them expose the module
 * BTF. RHEL 8.10 runs the very old 4.18 kernel, which does not expose module
 * BTF, only vmlinux. But we are good because sunrpc is a part of the main
 * kernel, so rpc_task will always be relocated :)
 */

static int probe_entry(struct rpc_task *task)
{
	struct nfs_partial_event e = {};
	e.nfscommand = (__u16)BPF_CORE_READ(task, tk_msg.rpc_proc, p_statidx);

	__u8 *blocked = bpf_map_lookup_elem(&denylist, &e.nfscommand);
	if (blocked) {
		return 0;
	}

	e.metric.latency_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&temp, &task, &e, BPF_NOEXIST);
	return 0;	
}

static int probe_exit(struct rpc_task *task)
{
	struct nfs_partial_event *pe;
	struct event *e;
	long flag = get_flags();

	/* reserve space in the ringbuffer first */
	e = bpf_ringbuf_reserve(&aodrb, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	pe = bpf_map_lookup_elem(&temp, &task);
	if (!pe) {
		bpf_ringbuf_discard(e, flag);
		return 0;
	}
	bpf_map_delete_elem(&temp, &task);

	e->cmd_end_time_ns = bpf_ktime_get_ns();
	e->metric.latency_ns = e->cmd_end_time_ns - pe->metric.latency_ns;

	if (e->metric.latency_ns < min_lat_ns) {
		bpf_ringbuf_discard(e, flag);
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->rqst_id = bpf_ntohl(BPF_CORE_READ(task, tk_rqstp, rq_xid));
	e->command = pe->nfscommand;
	e->tool = NFSSLOWER;
	bpf_get_current_comm(&e->task, sizeof(e->task));
	bpf_ringbuf_submit(e, flag);

	return 0;
}

SEC("fentry/nfs4_setup_sequence")
int BPF_PROG(nfs4_setup_sequence_entry, void *client, void *args, void *res, struct rpc_task *task)
{
	return probe_entry(task);
}

SEC("kprobe/nfs4_setup_sequence")
int BPF_KPROBE(nfs4_setup_sequence_kprobe, void *client, void *args, void *res, struct rpc_task *task)
{
	return probe_entry(task);
}

SEC("fentry/rpc_exit_task")
int BPF_PROG(rpc_done_entry, struct rpc_task *task)
{
	return probe_exit(task);
}

SEC("kprobe/rpc_exit_task")
int BPF_KPROBE(rpc_done_kprobe, struct rpc_task *task)
{
	return probe_exit(task);
}