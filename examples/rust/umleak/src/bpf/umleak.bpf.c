// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// #include "maps.bpf.h"
// #include "core_fixes.bpf.h"

#define ALLOCS_MAX_ENTRIES 1000000
#define STACK_FLAGS 0

const pid_t target_pid = -1;

struct alloc_record {
	u64 address;
	u64 stack_id;
	pid_t pid;
	size_t size;
	u64 ts_ns;
};

union stack_alloc_record {
	struct {
		u64 count : 40;
		u64 total_size : 24;
	};
	__u64 bits;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // pid
	__type(value, u64); // alloc size, passed to retprobe
	__uint(max_entries, 1); // assume no concurrency
} alloc_context SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // address
	__type(value, struct alloc_record);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // stack_id
	__type(value, u64); // accumulated size
	__uint(max_entries, 10240);
} stack_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size) {
	// invalid parameter
	if(size <= 0 || size > -1) {
		return 0;
	}

	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != target_pid)
		return 0;

	if (bpf_map_update_elem(&alloc_context, &pid, &size, BPF_NOEXIST)) {
		bpf_printk("unexpected %s: there should not be concurrency", __FUNCTION__);
		return -1;
	}

	return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit) {
	u64 addr = PT_REGS_RC(ctx);
	if (!addr) // alloc failure
		return 0;

	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != target_pid)
		return 0;

	const u64* size = bpf_map_lookup_elem(&alloc_context, &pid);
	if (!size) // missed alloc entry
		return 0;

	struct alloc_record record;
	__builtin_memset(&record, 0, sizeof(record));
	record.size = *size;
	record.ts_ns = bpf_ktime_get_ns();
	record.stack_id = bpf_get_stackid(ctx, &stack_traces, STACK_FLAGS);
	bpf_map_update_elem(&allocs, &addr, &record, BPF_NOEXIST);


	union stack_alloc_record *stack_record;
	stack_record = bpf_map_lookup_elem(&stack_allocs, &record.stack_id);
	if (!stack_record) {
		union stack_alloc_record zero = {.bits = 0};
		// __builtin_memset(&zero, 0, sizeof(zero));
		bpf_map_update_elem(&stack_allocs, &record.stack_id, &zero, BPF_NOEXIST);
		stack_record = bpf_map_lookup_elem(&stack_allocs, &record.stack_id);
		if (!stack_record) // unexpected
			return -1;
	}
	const union stack_alloc_record incre_record = {
		.total_size = record.size,
		.count = 1
	};
	__sync_fetch_and_add(&stack_record->bits, incre_record.bits);

	return 0;
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void *address)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != target_pid)
		return 0;
	
	const u64 addr = (u64)address;
	const struct alloc_record *record = bpf_map_lookup_elem(&allocs, &addr);
	if(!record)
		return 0;

	union stack_alloc_record *stack_record = bpf_map_lookup_elem(&stack_allocs, &record->stack_id);
	if (stack_record) {
		const union stack_alloc_record decr = {
			.total_size = record->size,
			.count = 1,
		};
		__sync_fetch_and_sub(&stack_record->bits, decr.bits);
	} else {
		return -1; // unexpected
	}

	bpf_map_delete_elem(&allocs, &addr);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
