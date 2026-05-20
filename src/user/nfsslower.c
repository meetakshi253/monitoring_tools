// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nfs_diag.h"
#include "nfsslower.skel.h"

#define warn(...)	     fprintf(stderr, __VA_ARGS__)

static __u64 min_lat_ms = 10;
static __u64 wakeup_data_size = 0; /* used to wake up the user space handler */

static bool include_mode = false, exclude_mode = false;
static __u8 cmd_filter[MAX_NFS_COMMANDS] = {0};

const char *argp_program_version = "nfsslower 0.1";
const char *argp_program_bug_address = "https://github.com/meetakshi253/monitoring_tools";

static const struct argp_option opts[] = {
	{ "wakeupsize", 'w', "WAKEUPSIZE", 0, "Wake up the userspace handler" },
	{ "include-cmds", 'c', "INCLUDE", 0, "Allowed NFS4 commands to trace" },
	{ "exclude-cmds", 'x', "EXCLUDE", 0, "NFS4 commands to exclude from tracing"},
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int parse_cmd_list(const char *arg, int max_cmds) {
	int count = 0;
	char *input = strdup(arg);
	if (!input) {
		return -1;
	}
	char *token = strtok(input, ",");
	while (token != NULL && count < max_cmds) {
		int cmd = (__u16)atoi(token);
		if (cmd >= 0 && cmd < MAX_NFS_COMMANDS) {
			cmd_filter[cmd] = 1;
			count++;
			token = strtok(NULL, ",");
		}
		token = strtok(NULL, ",");
	}
	free(input);
	return count;
}


static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'w':
		errno = 0;
		wakeup_data_size = strtoll(arg, NULL, 10);
		if (errno || wakeup_data_size < 0) {
			warn("invalid wakeup data size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		if (exclude_mode) {
			warn("Cannot use --include-cmds with --exclude-cmds\n");
			argp_usage(state);
			return 1;
		}
		include_mode = true;
		printf("Include mode enabled, parsing commands: %s\n", arg);
		int err = parse_cmd_list(arg, MAX_NFS_COMMANDS);
		if (err < 0) {
			warn("Failed to parse include commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in include list: %s\n", arg);
			argp_usage(state);
		}
		printf("%d", err);
		break;
	case 'x':
		if (include_mode) {
			warn("Cannot use --exclude-cmds with --include-cmds\n");
			argp_usage(state);
			return 1;
		}
		exclude_mode = true;
		printf("Exclude mode enabled, parsing commands: %s\n", arg);
		err = parse_cmd_list(arg, MAX_NFS_COMMANDS);
		if (err < 0) {
			warn("Failed to parse exclude commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in exclude list: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		min_lat_ms = strtoll(arg, NULL, 10);
		if (errno || min_lat_ms < 0) {
			warn("invalid latency (in ms): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int update_denylist_map(struct nfsslower_bpf *skel) {
	for (__u16 cmd = 0; cmd < MAX_NFS_COMMANDS; cmd ++) {
		bool deny = false;
		if (exclude_mode && cmd_filter[cmd]) deny = true;
		else if (include_mode && !cmd_filter[cmd]) deny = true;

		if (deny) {
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.denylist), &cmd, &deny, BPF_ANY) < 0) {
				warn("Failed to update denylist map for command %d\n", cmd);
				return -1;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
    struct nfsslower_bpf *skel;
	int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

    libbpf_set_print(libbpf_print_fn);

    skel = nfsslower_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    skel->rodata->min_lat_ns = min_lat_ms * 1000 * 1000;
    skel->rodata->wakeup_data_size = wakeup_data_size;

    err = nfsslower_bpf__load(skel);
    if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (update_denylist_map(skel) < 0) {
		fprintf(stderr, "Failed to update denylist map\n");
		goto cleanup;
	}

    err = nfsslower_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

	/* Pin links so BPF programs survive this process exiting */
	err = bpf_link__pin(skel->links.nfs4_setup_sequence_entry, LINK_NFS_SEQ_SETUP);
	if (err) {
		if (err == -EEXIST)
			fprintf(stderr, "BPF links already pinned. Detach first.\n");
		else
			fprintf(stderr, "Failed to pin seq_setup link: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_link__pin(skel->links.rpc_done_entry, LINK_NFS_RPC_EXIT);
	if (err) {
		if (err == -EEXIST)
			fprintf(stderr, "BPF links already pinned. Detach first.\n");
		else
			fprintf(stderr, "Failed to pin rpc_exit link: %s\n", strerror(-err));
		unlink(LINK_NFS_SEQ_SETUP);
		goto cleanup;
	}

	printf("nfsslower: BPF programs attached and pinned.\n");
	printf("  Ring buffer: %s\n", RINGBUF_PINNED);
	printf("  Detach from Python consumer to remove.\n");

cleanup:
    nfsslower_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
