// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "test_subprogs_extable.skel.h"
#include <sys/mman.h>
#include <string.h>

#define BUFFER_SIZE 4096

void test_subprogs_extable(void)
{
	const int read_sz = 456;
	struct test_subprogs_extable *skel;
	u64 *ptr;
	int err;

	err = write_sysctl("/proc/sys/vm/mmap_min_addr", "0");
	if (!ASSERT_OK(err, "write_sysctl mmap_min_addr"))
		return;

	ptr = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON | MAP_FIXED, -1, 0);
	if (!ASSERT_NULL(ptr, "mmap userspace"))
		return;

	/* ptr starts at 0, the BUFFER is filled with a known value which
	 * the BPF program will read erroneously due to the overflow. It
	 * will put the value in skel->bss->f_version. If the JIT emits
	 * checks for the overflow then the read should not work and the
	 * skel->bss->f_version will be zero.
	 */
	memset(ptr, 0xff, BUFFER_SIZE);

	skel = test_subprogs_extable__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = test_subprogs_extable__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger tracepoint */
	ASSERT_OK(trigger_module_test_read(read_sz), "trigger_read");

	ASSERT_NEQ(skel->bss->triggered, 0, "verify at least one program ran");

	/*
	 * If this is not zero then the BPF program erroneously read user
	 * memory and the JIT has a bug.
	 */
	ASSERT_EQ(skel->bss->f_version, 0, "verify that read from userspace address failed");

	test_subprogs_extable__detach(skel);

cleanup:
	ASSERT_OK(munmap(ptr, BUFFER_SIZE), "unmap userspace ptr");
	test_subprogs_extable__destroy(skel);
}
