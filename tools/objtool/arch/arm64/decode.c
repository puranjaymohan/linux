// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <asm/insn.h>

#include <objtool/check.h>
#include <objtool/arch.h>
#include <objtool/elf.h>
#include <objtool/warn.h>
#include <objtool/builtin.h>
#include <arch/cfi_regs.h>

#include "../../../arch/arm64/lib/insn.c"

#define is_SP(reg)		(reg == AARCH64_INSN_REG_SP)
#define is_FP(reg)		(reg == AARCH64_INSN_REG_FP)
#define is_SPFP(reg)	(reg == AARCH64_INSN_REG_SP || reg == AARCH64_INSN_REG_FP)

#define ADD_OP(op) \
	if (!(op = calloc(1, sizeof(*op)))) \
		return -1; \
	else for (list_add_tail(&op->list, ops_list); op; op = NULL)

static unsigned long sign_extend(unsigned long x, int nbits)
{
	unsigned long sign_bit = (x >> (nbits - 1)) & 1;

	return ((~0UL + (sign_bit ^ 1)) << nbits) | x;
}

bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case AARCH64_INSN_REG_19:
	case AARCH64_INSN_REG_20:
	case AARCH64_INSN_REG_21:
	case AARCH64_INSN_REG_22:
	case AARCH64_INSN_REG_23:
	case AARCH64_INSN_REG_24:
	case AARCH64_INSN_REG_25:
	case AARCH64_INSN_REG_26:
	case AARCH64_INSN_REG_27:
	case AARCH64_INSN_REG_28:
	case AARCH64_INSN_REG_FP:
	case AARCH64_INSN_REG_LR:
		return true;
	default:
		return false;
	}
}

void arch_initial_func_cfi_state(struct cfi_init_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (call frame address) */
	state->cfa.base = CFI_SP;
	state->cfa.offset = 0;
}

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

const char *arch_nop_insn(int len)
{
	static u32 nop;

	if (len != AARCH64_INSN_SIZE)
		WARN("invalid NOP size: %d\n", len);

	if (!nop)
		nop = aarch64_insn_gen_nop();

	return (const char *)&nop;
}

const char *arch_ret_insn(int len)
{
	static u32 ret;

	if (len != AARCH64_INSN_SIZE)
		WARN("invalid RET size: %d\n", len);

	if (!ret) {
		ret = aarch64_insn_gen_branch_reg(AARCH64_INSN_REG_LR,
				AARCH64_INSN_BRANCH_RETURN);
	}

	return (const char *)&ret;
}

static int is_arm64(const struct elf *elf)
{
	switch (elf->ehdr.e_machine) {
	case EM_AARCH64: //0xB7
		return 1;
	default:
		WARN("unexpected ELF machine type %x",
		     elf->ehdr.e_machine);
		return 0;
	}
}

int arch_decode_hint_reg(u8 sp_reg, int *base)
{
	return -1;
}

static inline void make_add_op(enum aarch64_insn_register dest,
					enum aarch64_insn_register src,
					int val, struct stack_op *op)
{
	op->dest.type = OP_DEST_REG;
	op->dest.reg = dest;
	op->src.reg = src;
	op->src.type = val != 0 ? OP_SRC_ADD : OP_SRC_REG;
	op->src.offset = val;
}

static void decode_add_sub_imm(u32 instr, bool set_flags,
				  unsigned long *immediate,
				  struct stack_op *op)
{
	u32 rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, instr);
	u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, instr);

	*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, instr);

	if (instr & AARCH64_INSN_LSL_12)
		*immediate <<= 12;

	if ((!set_flags && is_SP(rd)) || is_FP(rd)
			|| is_SPFP(rn)) {
		int value;

		if (aarch64_insn_is_subs_imm(instr) || aarch64_insn_is_sub_imm(instr))
			value = -*immediate;
		else
			value = *immediate;

		make_add_op(rd, rn, value, op);
	}
}

int arch_decode_instruction(struct objtool_file *file, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	const struct elf *elf = file->elf;
	struct stack_op *op = NULL;
	u32 insn;

	if (!is_arm64(elf))
		return -1;

	if (maxlen < AARCH64_INSN_SIZE)
		return 0;

	*len = AARCH64_INSN_SIZE;
	*immediate = 0;
	*type = INSN_OTHER;

	insn = *(u32 *)(sec->data->d_buf + offset);

	switch (aarch64_get_insn_class(insn)) {
	case AARCH64_INSN_CLS_UNKNOWN:
		WARN("can't decode instruction at %s:0x%lx", sec->name, offset);
		return -1;
	case AARCH64_INSN_CLS_DP_IMM:
		/* Mov register to and from SP are aliases of add_imm */
		if (aarch64_insn_is_add_imm(insn) ||
		    aarch64_insn_is_sub_imm(insn)) {
			ADD_OP(op) {
				decode_add_sub_imm(insn, false, immediate, op);
			}
		}
		else if (aarch64_insn_is_adds_imm(insn) ||
			     aarch64_insn_is_subs_imm(insn)) {
			ADD_OP(op) {
				decode_add_sub_imm(insn, true, immediate, op);
			}
		}
		break;
	case AARCH64_INSN_CLS_DP_REG:
		if (aarch64_insn_is_mov_reg(insn)) {
			enum aarch64_insn_register rd;
			enum aarch64_insn_register rm;

			rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, insn);
			rm = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RM, insn);
			if (is_FP(rd) || is_FP(rm)) {
				ADD_OP(op) {
					make_add_op(rd, rm, 0, op);
				}
			}
		}
		break;
	default:
		break;
	}

	return 0;
}
