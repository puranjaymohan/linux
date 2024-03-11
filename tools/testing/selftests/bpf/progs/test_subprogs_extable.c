// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} test_array SEC(".maps");

unsigned int triggered;
u64 f_version = 0;

static __u64 test_cb(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
{
	return 1;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs, int arg, struct file *ret)
{
	*(volatile long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb, NULL, 0);
	triggered++;
	return 0;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs2, int arg, struct file *ret)
{
	*(volatile long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb, NULL, 0);
	triggered++;
	return 0;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs3, int arg, struct file *ret)
{
	*(volatile long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb, NULL, 0);
	triggered++;
	return 0;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs4, int arg, struct file *ret)
{
	/* With arg = 3, bpf_testmod_return_ptr returns -EINVAL
	 * -EINVAL is 0xffffffffffffffea which is an invalid address. the
	 * JIT should add an exception table entry for the read, but
	 * ret->f_version; will wrap and form a userspace address which
	 * the userspace program has mapped. So the read should succeed if
	 * the JIT doesn't emit checks for userspace addresses in
	 * PROBE_MEM.
	 */
	if (ret && arg == 3)
		f_version = ret->f_version;
	bpf_for_each_map_elem(&test_array, test_cb, NULL, 0);
	triggered++;
	return 0;
}

char _license[] SEC("license") = "GPL";
