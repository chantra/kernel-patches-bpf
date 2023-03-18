// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, 1);
	__type(value, int);
} stack_map SEC(".maps");

const volatile pid_t pid;
long err = 0;

SEC("tp/syscalls/sys_enter_getpid")
int map_update(void *ctx)
{
	const int key = 0;
	const int val = 1;

	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	err = bpf_map_update_elem(&hash_map, &key, &val, BPF_NOEXIST);

	return 0;
}

SEC("tp/syscalls/sys_enter_getppid")
int map_delete(void *ctx)
{
	const int key = 0;

	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	err = bpf_map_delete_elem(&hash_map, &key);

	return 0;
}

SEC("tp/syscalls/sys_enter_getuid")
int map_push(void *ctx)
{
	const int val = 1;

	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	err = bpf_map_push_elem(&stack_map, &val, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_geteuid")
int map_pop(void *ctx)
{
	int val;

	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	err = bpf_map_pop_elem(&stack_map, &val);

	return 0;
}

SEC("tp/syscalls/sys_enter_getgid")
int map_peek(void *ctx)
{
	int val;

	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	err = bpf_map_peek_elem(&stack_map, &val);

	return 0;
}

