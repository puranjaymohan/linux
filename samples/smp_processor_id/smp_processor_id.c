// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)       KBUILD_MODNAME ": " fmt

#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/smp.h>

/*
 * Arbitrary large value chosen to be sufficiently large to minimize noise but
 * sufficiently small to complete quickly.
 */
static unsigned int nr_function_calls = 1000000;
module_param(nr_function_calls, uint, 0);
MODULE_PARM_DESC(nr_function_calls, "How many times to call the smp_processor_id()");

static noinline int get_cpu_id(void)
{
	return smp_processor_id();
}

static int __init smp_processor_id_sample_init(void)
{
	volatile int cpu;
	ktime_t start, end;
	u64 period;

	start = ktime_get();
	for (unsigned int i = 0; i < nr_function_calls; i++)
		cpu = get_cpu_id();
	end = ktime_get();

	period = ktime_to_ns(ktime_sub(end, start));

	pr_info("Attempted %u calls to %ps in %lluns (%lluns / call)\n",
		nr_function_calls, get_cpu_id,
		period, div_u64(period, nr_function_calls));

	/*
	 * The benchmark completed successfully, but there's no reason to keep
	 * the module around. Return an error do the user doesn't have to
	 * manually unload the module.
	 */
	return -EINVAL;
}
module_init(smp_processor_id_sample_init);

static void __exit smp_processor_id_sample_exit(void)
{
}
module_exit(smp_processor_id_sample_exit);

MODULE_AUTHOR("Puranjay Mohan");
MODULE_DESCRIPTION("Benchmark for smp_processor_id function");
MODULE_LICENSE("GPL");
