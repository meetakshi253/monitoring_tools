// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */

/* Alternate version of smbslower with just one hook */
#include "cifs_btf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_endian_le.h"
#include "smb_diag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_lat_ns = 0;
const volatile int wakeup_data_size = 256;
const volatile __u16 HZ = 250;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SMB_COMMANDS); /* SMB commands */
	__type(key, __u16); /* Command code */
	__type(value, __u8); /* Dummy value */
} denylist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 4096);
	__type(key, struct mid_q_entry *);
	__type(value, struct smb_partial_event);
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

static int probe_entry(struct mid_q_entry *mid_struct)
{
    struct event *e;
    unsigned long when_alloc, when_free;
    long flag = get_flags();

    e = bpf_ringbuf_reserve(&aodrb, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    when_alloc = BPF_CORE_READ(mid_struct, when_alloc);
    when_free = bpf_jiffies64();

    if (when_alloc > when_free) {
        bpf_ringbuf_discard(e, flag);
        return 0;
    }

    e->metric.latency_ns = (when_free - when_alloc) * (1000000000ULL / HZ);
    if (e->metric.latency_ns < min_lat_ns) {
        bpf_ringbuf_discard(e, flag);
        return 0;
    }

    e->command = bpf_le16_to_cpu(BPF_CORE_READ(mid_struct, command));
    __u8 *blocked = bpf_map_lookup_elem(&denylist, &e->command);
	if (blocked) {
		return 0;
	}

    e->cmd_end_time_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->rqst_id = BPF_CORE_READ(mid_struct, mid);
    e->tool = SMBSLOWER;
    bpf_get_current_comm(&e->task, sizeof(e->task));
    bpf_ringbuf_submit(e, flag);
    return 0;
}

/* Pre-6.19: __release_mid(struct kref *refcount) */
SEC("fentry/__release_mid")
int BPF_PROG(mid_release_kref_fentry, struct kref *refcount) {
	const typeof(((struct mid_q_entry *)0)->refcount) *__mptr =
		(const typeof(((struct mid_q_entry *)0)->refcount) *)refcount;
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)__mptr - __builtin_preserve_field_info(((struct mid_q_entry *)0)->refcount, BPF_FIELD_BYTE_OFFSET));

	return probe_entry(mid_struct);
}

SEC("kprobe/__release_mid")
int BPF_PROG(mid_release_kref_kprobe, struct kref *refcount) {
	const typeof(((struct mid_q_entry *)0)->refcount) *__mptr =
		(const typeof(((struct mid_q_entry *)0)->refcount) *)refcount;
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)__mptr - __builtin_preserve_field_info(((struct mid_q_entry *)0)->refcount, BPF_FIELD_BYTE_OFFSET));

	return probe_entry(mid_struct);
}

/* 6.19+: __release_mid(struct TCP_Server_Info *server, struct mid_q_entry *midEntry) */
SEC("fentry/__release_mid")
int BPF_PROG(mid_release_direct_fentry, void *server, struct mid_q_entry *midEntry) {
	return probe_entry(midEntry);
}

SEC("kprobe/__release_mid")
int BPF_PROG(mid_release_direct_kprobe, void *server, struct mid_q_entry *midEntry) {
	return probe_entry(midEntry);
}