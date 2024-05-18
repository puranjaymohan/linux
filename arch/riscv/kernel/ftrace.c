// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 * Copyright (C) 2017 Andes Technology Corporation
 */

#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/memory.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/patch.h>

#ifdef CONFIG_DYNAMIC_FTRACE
void ftrace_arch_code_modify_prepare(void) __acquires(&text_mutex)
{
	mutex_lock(&text_mutex);

	/*
	 * The code sequences we use for ftrace can't be patched while the
	 * kernel is running, so we need to use stop_machine() to modify them
	 * for now.  This doesn't play nice with text_mutex, we use this flag
	 * to elide the check.
	 */
	riscv_patch_in_stop_machine = true;
}

void ftrace_arch_code_modify_post_process(void) __releases(&text_mutex)
{
	riscv_patch_in_stop_machine = false;
	mutex_unlock(&text_mutex);
}

static int ftrace_check_current_call(unsigned long hook_pos,
				     unsigned int *expected)
{
	unsigned int replaced[2];
	unsigned int nops[2] = {NOP4, NOP4};

	/* we expect nops at the hook position */
	if (!expected)
		expected = nops;

	/*
	 * Read the text we want to modify;
	 * return must be -EFAULT on read error
	 */
	if (copy_from_kernel_nofault(replaced, (void *)hook_pos,
			MCOUNT_INSN_SIZE))
		return -EFAULT;

	/*
	 * Make sure it is what we expect it to be;
	 * return must be -EINVAL on failed comparison
	 */
	if (memcmp(expected, replaced, sizeof(replaced))) {
		pr_err("%p: expected (%08x %08x) but got (%08x %08x)\n",
		       (void *)hook_pos, expected[0], expected[1], replaced[0],
		       replaced[1]);
		return -EINVAL;
	}

	return 0;
}

static int __ftrace_modify_call(unsigned long hook_pos, unsigned long target,
				bool enable, bool ra)
{
	unsigned int call[2];
	unsigned int nops[2] = {NOP4, NOP4};

	if (ra)
		make_call_ra(hook_pos, target, call);
	else
		make_call_t0(hook_pos, target, call);

	/* Replace the auipc-jalr pair at once. Return -EPERM on write error. */
	if (patch_insn_write((void *)hook_pos, enable ? call : nops, MCOUNT_INSN_SIZE))
		return -EPERM;

	return 0;
}

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_CALL_OPS
static const struct ftrace_ops *riscv64_rec_get_ops(struct dyn_ftrace *rec)
{
	const struct ftrace_ops *ops = NULL;

	if (rec->flags & FTRACE_FL_CALL_OPS_EN) {
		ops = ftrace_find_unique_ops(rec);
		WARN_ON_ONCE(!ops);
	}

	if (!ops)
		ops = &ftrace_list_ops;

	return ops;
}

static int ftrace_rec_set_ops(const struct dyn_ftrace *rec,
			      const struct ftrace_ops *ops)
{
	unsigned long literal = rec->ip - 8;

	return patch_text_nosync((void *)literal, &ops, sizeof(ops));
}

static int ftrace_rec_set_nop_ops(struct dyn_ftrace *rec)
{
	return ftrace_rec_set_ops(rec, &ftrace_nop_ops);
}

static int ftrace_rec_update_ops(struct dyn_ftrace *rec)
{
	return ftrace_rec_set_ops(rec, riscv64_rec_get_ops(rec));
}
#else
static int ftrace_rec_set_nop_ops(struct dyn_ftrace *rec) { return 0; }
static int ftrace_rec_update_ops(struct dyn_ftrace *rec) { return 0; }
#endif

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned int call[2];
	int ret;

	ret = ftrace_rec_update_ops(rec);
	if (ret)
		return ret;

	make_call_t0(rec->ip, addr, call);

	if (patch_insn_write((void *)rec->ip, call, MCOUNT_INSN_SIZE))
		return -EPERM;

	return 0;
}

int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec,
		    unsigned long addr)
{
	unsigned int nops[2] = {NOP4, NOP4};
	int ret;

	ret = ftrace_rec_set_nop_ops(rec);
	if (ret)
		return ret;

	if (patch_insn_write((void *)rec->ip, nops, MCOUNT_INSN_SIZE))
		return -EPERM;

	return 0;
}

/*
 * This is called early on, and isn't wrapped by
 * ftrace_arch_code_modify_{prepare,post_process}() and therefor doesn't hold
 * text_mutex, which triggers a lockdep failure.  SMP isn't running so we could
 * just directly poke the text, but it's simpler to just take the lock
 * ourselves.
 */
int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec)
{
	int out;

	mutex_lock(&text_mutex);
	out = ftrace_make_nop(mod, rec, MCOUNT_ADDR);
	mutex_unlock(&text_mutex);

	return out;
}

int ftrace_update_ftrace_func(ftrace_func_t func)
{
	/*
	 * When using CALL_OPS, the function to call is associated with the
	 * call site, and we don't have a global function pointer to update.
	 */
	if (IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_CALL_OPS))
		return 0;

	int ret = __ftrace_modify_call((unsigned long)&ftrace_call,
				       (unsigned long)func, true, true);
	return ret;
}

struct ftrace_modify_param {
	int command;
	atomic_t cpu_count;
};

static int __ftrace_modify_code(void *data)
{
	struct ftrace_modify_param *param = data;

	if (atomic_inc_return(&param->cpu_count) == num_online_cpus()) {
		ftrace_modify_all_code(param->command);
		/*
		 * Make sure the patching store is effective *before* we
		 * increment the counter which releases all waiting CPUs
		 * by using the release variant of atomic increment. The
		 * release pairs with the call to local_flush_icache_all()
		 * on the waiting CPU.
		 */
		atomic_inc_return_release(&param->cpu_count);
	} else {
		while (atomic_read(&param->cpu_count) <= num_online_cpus())
			cpu_relax();
	}

	local_flush_icache_all();

	return 0;
}

void arch_ftrace_update_code(int command)
{
	struct ftrace_modify_param param = { command, ATOMIC_INIT(0) };

	stop_machine(__ftrace_modify_code, &param, cpu_online_mask);
}
#endif

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
		       unsigned long addr)
{
	unsigned int call[2];
	unsigned long caller = rec->ip;
	int ret;

	make_call_t0(caller, old_addr, call);
	ret = ftrace_check_current_call(caller, call);

	if (ret)
		return ret;

	ret = ftrace_rec_update_ops(rec);
	if (ret)
		return ret;

	return __ftrace_modify_call(caller, addr, true, false);
}
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/*
 * Most of this function is copied from arm64.
 */
void prepare_ftrace_return(unsigned long *parent, unsigned long self_addr,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	/*
	 * We don't suffer access faults, so no extra fault-recovery assembly
	 * is needed here.
	 */
	old = *parent;

	if (!function_graph_enter(old, self_addr, frame_pointer, parent))
		*parent = return_hooker;
}

#ifdef CONFIG_DYNAMIC_FTRACE
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_ARGS
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	prepare_ftrace_return(&fregs->ra, ip, fregs->s0);
}
#else /* CONFIG_DYNAMIC_FTRACE_WITH_ARGS */
extern void ftrace_graph_call(void);
int ftrace_enable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call((unsigned long)&ftrace_graph_call,
				    (unsigned long)&prepare_ftrace_return, true, true);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call((unsigned long)&ftrace_graph_call,
				    (unsigned long)&prepare_ftrace_return, false, true);
}
#endif /* CONFIG_DYNAMIC_FTRACE_WITH_ARGS */
#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
