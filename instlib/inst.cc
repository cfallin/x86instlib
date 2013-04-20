/*
 * instlib: amd64 functional emulation
 *
 * Copyright (C) 2012 Chris Fallin <cfallin@c1f.net>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "inst.h"
#include "decoder/decode.h"

#include <setjmp.h>
#include <stdio.h>

jmp_buf ptlsim_decoder_assert_jmpbuf;

void print_uop(Instruction *inst)
{
    printf("  PC=%lx UPC=%lx (bom=%d eom=%d len=%d) %10s ra=%02d rb=%02d (imm=%lx) rc=%02d (imm=%lx) --> rd=%02d (setfl %d) rdval=%lx targ=%lx fallthrough=%lx br=%d cond=%d indir=%d taken=%d\n",
            inst->pc, inst->upc, inst->bom, inst->eom, inst->length, inst->opcodename, inst->ra, inst->rb, inst->rb_val.val, inst->rc, inst->rc_val.val, inst->rd, inst->setflags, inst->rd_val.val, inst->branch_dest, inst->branch_fall,
            inst->is_branch ? 1 : 0, inst->br_cond ? 1 : 0, inst->br_indir ? 1 : 0, inst->branch_taken ? 1 : 0);
}

void arch_ctx_init(Arch_Ctx *ctx)
{
    memset(ctx, 0, sizeof(Arch_Ctx));
}

void inst_init(Instruction *inst)
{
    memset(inst, 0, sizeof(Instruction));
    inst->ra = inst->rb = inst->rc = inst->rd = -1;
}

static int trans_reg(int reg, uint64_t pc, uint64_t length, uint64_t imm, Reg *r)
{
    switch (reg) {
        case REG_imm:
            if (r) r->val = imm;
            return -1;
        case REG_mem:
            return -1;
        case REG_rip:
            if (r) r->val = pc;
            return -1;
        case REG_selfrip:
            if (r) r->val = pc;
            return -1;
        case REG_nextrip:
            if (r) r->val = pc + length;
            return -1;
        case REG_zero:
            if (r) r->val = 0;
            return -1;
        default: return reg;
    }
}

struct cpuid_leaf {
    uint32_t eax, ebx, ecx, edx;
};

static cpuid_leaf cpuid_leaves[2] = {
    // EAX = 0: highest leaf index, Vendor ID ('!itracetool!')
    { 1, 0x72746921, 0x74656361, 0x216c6f6f },
    // EAX = 1: family (6) / model (0), feature flags (SSE, SSE2, MMX, CMOV, CMPXCHG8, TSC, FPU)
    { 0x00000600, 0, 0, 0x06808111 }
};

// see below in inst_decode() for the microcode sequence that these five uops implement.
// it is:
//    tmp0 = min(eax, 1)
//    eax = cpuid_leaves[tmp0].eax
//    ebx = cpuid_leaves[tmp0].ebx
//    ecx = cpuid_leaves[tmp0].ecx
//    edx = cpuid_leaves[tmp0].edx
static void __impl_cpuid0(IssueState& is, W64 ra, W64 rb, W64 rc, W16 raf, W16 rbf, W16 rcf)
{
    if (ra > 1) ra = 0;
    is.reg.rdflags = 0;
    is.reg.addr = 0;
    is.reg.rddata = ra;
}
static void __impl_cpuid1(IssueState& is, W64 ra, W64 rb, W64 rc, W16 raf, W16 rbf, W16 rcf)
{
    if (ra > 1) ra = 0;
    is.reg.rdflags = 0;
    is.reg.addr = 0;
    is.reg.rddata = cpuid_leaves[ra].eax;
}
static void __impl_cpuid2(IssueState& is, W64 ra, W64 rb, W64 rc, W16 raf, W16 rbf, W16 rcf)
{
    if (ra > 1) ra = 0;
    is.reg.rdflags = 0;
    is.reg.addr = 0;
    is.reg.rddata = cpuid_leaves[ra].ebx;
}
static void __impl_cpuid3(IssueState& is, W64 ra, W64 rb, W64 rc, W16 raf, W16 rbf, W16 rcf)
{
    if (ra > 1) ra = 0;
    is.reg.rdflags = 0;
    is.reg.addr = 0;
    is.reg.rddata = cpuid_leaves[ra].ecx;
}
static void __impl_cpuid4(IssueState& is, W64 ra, W64 rb, W64 rc, W16 raf, W16 rbf, W16 rcf)
{
    if (ra > 1) ra = 0;
    is.reg.rdflags = 0;
    is.reg.addr = 0;
    is.reg.rddata = cpuid_leaves[ra].edx;
}

void inst_decode(Instruction *inst, int *count, uint64_t pc, uint8_t *bytes, int *size, Machine_Ctx *machctx)
{
    static Context *ctx = 0;
    *count = 0;
    if (!ctx) ctx = new Context();
    ctx->use32 = 0;
    ctx->use64 = 1;
    ctx->seg[SEGID_CS].base = 0;
    ctx->seg[SEGID_CS].selector = 0x8;
    ctx->seg[SEGID_DS].base = 0;
    ctx->seg[SEGID_DS].selector = 0x10;
    ctx->seg[SEGID_ES].base = 0;
    ctx->seg[SEGID_ES].selector = 0x10;
    ctx->seg[SEGID_FS].base = 0;
    ctx->seg[SEGID_FS].selector = 0x10;
    ctx->seg[SEGID_GS].base = 0;
    ctx->seg[SEGID_GS].selector = 0x10;
    ctx->seg[SEGID_SS].base = 0;
    ctx->seg[SEGID_SS].selector = 0x10;

    /*
    printf("PC = %llx seq: ", pc);
    for (int i = 0; i < *size; i++)
        printf(" %02x", bytes[i]);
    printf("\n");
    */

    static TraceDecoder *decoder = 0;
    if (!decoder) decoder = new TraceDecoder(*ctx, pc);
    decoder->reset();
    decoder->flush();
    decoder->bb.reset(pc);
    decoder->bb.rip = pc;
    decoder->use64 = 1;
    decoder->dirflag = 0;
    decoder->last_flags_update_was_atomic = 0;
    decoder->rip = pc;
    decoder->ripstart = pc;

    // special case: syscall
    if (*size >= 2 && bytes[0] == 0x0f && bytes[1] == 0x05) {
        memset(&inst[0], 0, sizeof(Instruction));
        inst[0].syscall = 1;
        inst[0].pc = pc;
        inst[0].upc = 0;
        inst[0].length = 2;
        inst[0].opcodename = "syscall";
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0]._impl = 0;
        inst[0].bom = inst[0].eom = 1;
        *count = 1;
        *size = 2;
        //printf("PC = %llx: syscall\n", pc);
        return;
    }

    // special case: rdtsc
    if (*size >= 2 && bytes[0] == 0x0f && bytes[1] == 0x31) {
        memset(&inst[0], 0, sizeof(Instruction) * 2);
        inst[0].pc = pc;
        inst[0].upc = 0;
        inst[1].pc = pc;
        inst[1].upc = 1;
        inst[0].length = 2;
        inst[1].length = 2;

        inst[0].opcodename = "rdtsc-rax";
        inst[0].ra = inst[0].rb = inst[0].rc = -1;
        inst[0].rd = REG_rax;
        inst[0].rd_val.val = 0;
        inst[0]._impl = 0;
        inst[0].bom = 1;

        inst[1].opcodename = "rdtsc-rdx";
        inst[1].ra = inst[1].rb = inst[1].rc = -1;
        inst[1].rd = REG_rdx;
        inst[1].rd_val.val = 0;
        inst[1]._impl = 0;
        inst[1].eom = 1;

        *count = 2;
        *size = 2;
        return;
    }

    // special case: cpuid
    if (*size >= 2 && bytes[0] == 0x0f && bytes[1] == 0xa2) {
        memset(&inst[0], 0, sizeof(Instruction) * 5);
        for (int i = 0; i < 5; i++) {
            inst[i].pc = pc;
            inst[i].upc = i;
            inst[i].length = 2;
            inst[i].opcodename = "cpuid";
        }
        inst[0].bom = 1;
        inst[4].eom = 1;

        // we implement a mini-microcode-flow here.

        // uop 0: tmp0 = rax
        inst[0].ra = REG_rax; inst[0].rb = inst[0].rc = -1; inst[0].rd = REG_temp0;
        inst[0]._impl = (void *)__impl_cpuid0;
        // uop 1: eax = cpuid_leaves[tmp0].eax
        inst[1].ra = REG_temp0; inst[1].rb = inst[1].rc = -1; inst[1].rd = REG_rax;
        inst[1]._impl = (void *)__impl_cpuid1;
        // uop 2: ebx = cpuid_leaves[tmp0].ebx
        inst[2].ra = REG_temp0; inst[2].rb = inst[2].rc = -1; inst[2].rd = REG_rbx;
        inst[2]._impl = (void *)__impl_cpuid2;
        // uop 3: ecx = cpuid_leaves[tmp0].ecx
        inst[3].ra = REG_temp0; inst[3].rb = inst[3].rc = -1; inst[3].rd = REG_rcx;
        inst[3]._impl = (void *)__impl_cpuid3;
        // uop 4: edx = cpuid_leaves[tmp0].edx
        inst[4].ra = REG_temp0; inst[4].rb = inst[4].rc = -1; inst[4].rd = REG_rdx;
        inst[4]._impl = (void *)__impl_cpuid4;

        *size = 2;
        *count = 5;

        return;
    }

    // special case: 0f 1f xx xx xx ("hint nop")
    if (*size >= 3 && bytes[0] == 0x0f && bytes[1] == 0x1f) {

        memset(&inst[0], 0, sizeof(Instruction));

        // parse the length (ModRM byte and following). Why the hell did Intel
        // think that variable-length NOPs were a good idea?!
        uint8_t modrm = bytes[2];
        uint8_t modrm_mod = (modrm & 0xc0) >> 6;
        uint8_t modrm_rm = (modrm & 0x07);
        uint8_t sib = bytes[3];

        int extra_len = 1; // modRM byte itself
        if (modrm_mod == 0) {
            if (modrm_rm == 4)
                extra_len += 1; // SIB

            if (modrm_rm == 4 && ((sib & 0x07) == 5))
                extra_len += 4; // disp
            else if (modrm_rm == 5)
                extra_len += 4; // disp
        }
        else if (modrm_mod == 1) {
            if (modrm_rm == 4)
                extra_len += 1; // SIB
            extra_len += 1; // disp
        }
        else if (modrm_mod == 2) {
            if (modrm_rm == 4)
                extra_len += 1; // SIB
            extra_len += 4; // disp
        }

        inst[0].opcodename = "hint-nop";
        inst[0].pc = pc;
        inst[0].upc = 0;
        inst[0].length = 2 + extra_len;
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0]._impl = 0;
        inst[0].bom = inst[0].eom = 1;
        *count = 1;
        *size = 2 + extra_len;
        //printf("PC = %llx: nop\n", pc);
        return;
    }

    // special case: emms (0f 77)
    if (*size >= 2 && bytes[0] == 0x0f && bytes[1] == 0x77) {
        memset(&inst[0], 0, sizeof(Instruction));
        inst[0].opcodename = "emms-nop";
        inst[0].pc = pc;
        inst[0].upc = 0;
        inst[0].length = 2;
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0]._impl = 0;
        inst[0].bom = inst[0].eom = 1;
        *count = 1;
        *size = 2;
        return;
    }

    decoder->insnbytes = bytes;
    decoder->insnbytes_bufsize = *size;
    decoder->byteoffset = 0;
    decoder->bb.reset();
    decoder->transbufcount = 0;

    bool ok = false;
    if (setjmp(ptlsim_decoder_assert_jmpbuf))
        ok = false;
    else
        ok = decoder->translate();

    *size = decoder->byteoffset;

    if (!ok) {
        *count = 1;
        *size = 0;
        memset(inst, 0, sizeof(Instruction));
        inst->pc = pc;
        inst->upc = 0;
        inst->fault = FAULT_INVALID;
        return;
    }

    *count = 0;

    for (int i = 0; i < decoder->transbufcount; i++) {
        Instruction *in = &inst[i];
        (*count)++;
        TransOp *op = &decoder->transbuf[i];
        memset(in, 0, sizeof(Instruction));

        in->pc = pc;
        in->upc = i;
        in->length = *size;

        in->opcode = op->opcode;
        in->type = opinfo[op->opcode].opclass;
        in->opcodename = opinfo[op->opcode].name;

        if (!op->nouserflags)
            in->setflags = op->setflags;

        in->ra = trans_reg(op->ra, pc, *size, 0, &in->ra_val);
        in->rb = trans_reg(op->rb, pc, *size, op->rbimm, &in->rb_val);
        in->rc = trans_reg(op->rc, pc, *size, op->rcimm, &in->rc_val);
        in->rd = trans_reg(op->rd, pc, *size, 0, NULL);

        in->is_branch = (in->type & OPCLASS_BRANCH);
        in->br_indir = (in->type & OPCLASS_INDIR_BRANCH);
        in->br_cond = (in->type & OPCLASS_COND_BRANCH);
        in->br_call = (bytes[0] == 0xe8 || bytes[0] == 0xff) &&
            i == decoder->transbufcount - 1;
        in->br_ret = (bytes[0] == 0xc3) &&
            i == decoder->transbufcount - 1;
        if (in->is_branch && !in->br_cond) in->branch_taken = 1;

        if (in->br_cond) {
            in->branch_targ = op->riptaken;
            in->branch_fall = op->ripseq;
        }
        else if (in->is_branch) {
            in->branch_fall = 0;
            in->branch_targ = op->riptaken;
            in->branch_dest = op->riptaken;
        }
        else {
            in->branch_fall = op->ripseq;
        }

        in->serialize = (in->type & OPCLASS_ASSIST) ? 1 : 0;
        //if (in->serialize) printf("serialize: assist (PC %lx)\n", pc);

        in->is_mem = (in->type & (OPCLASS_LOAD | OPCLASS_STORE));
        in->is_load = (in->type & OPCLASS_LOAD);
        in->is_sta = (in->type & OPCLASS_STORE);
        in->mem_size = 1 << op->size;

        in->_impl = (void *)get_synthcode_for_uop(op->opcode, op->size, op->setflags,
                op->cond, op->extshift, 0, op->internal);

        // rdtsc?
        if (i == 0 && in->ra == REG_ctx && in->rb_val.val == 0xd8) {
            in->opcode = 0;
            in->type = 0;
            in->opcodename = "special";
            in->ra = -1;
            in->rb = -1;
            in->rc = -1;
            in->rd_val.val = 0;
            in->_impl = 0;

            in++;
            memcpy(&inst[1], &inst[0], sizeof(Instruction));
            (*count)++;
            in->upc = 1;
            in->_impl = 0;
            inst[0].rd = 0;
            inst[1].rd = 2;

            break;
        }

        // read from FS?
        else if (in->ra == REG_ctx && in->rb_val.val == 0x270) {
            in->opcode = 0;
            in->type = 0;
            in->opcodename = "fs_read";
            in->ra = -1;
            in->rb = -1;
            in->rc = -1;
            in->rd_val.val = machctx->fs;
            in->_impl = 0;
        }

        // any other read from ``ctx'' structure -- unsupported x86 corner case
        // of some sort (like FPU Control Word, etc).  Just force a
        // serialization, which the backend interprets as a
        // nuke-to-functional-state (a la syscall handling).
        else if (in->ra == REG_ctx && in->rb_val.val != 0x270) {
            in->serialize = 1;
            //printf("serialize: ctx + %lx (PC %lx)\n", in->rb_val.val, pc);
        }
    }

    // post-special case: xchg: serialize -> force a nuke
    if (
            // XCHG with no prefix.
            (bytes[0] == 0x86 || bytes[0] == 0x87 || (bytes[0] > 0x90 && bytes[0] <= 0x97)) ||
            // with FS prefix...
            (*size >= 2 && bytes[0] == 0x64 &&
                (bytes[1] == 0x86 || bytes[1] == 0x87 || (bytes[1] > 0x90 && bytes[1] <= 0x97)))) {
        memset(&inst[0], 0, sizeof(Instruction));
        inst[0].opcodename = "serializing-xchg";
        *count = 1;
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0].serialize = 1;
        //printf("serialize: xchg (PC %lx)\n", pc);
    }

    // post-special case: lock prefix -> force a nuke
    if (bytes[0] == 0xf0) {
        memset(&inst[0], 0, sizeof(Instruction));
        inst[0].opcodename = "serializing-locked-instruction";
        *count = 1;
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0].serialize = 1;
        //printf("serialize: lock (PC %lx)\n", pc);
    }

    // post-pass: expand stores into sta/std pairs
    for (int i = 0; i < *count; i++) {

        // at each sta, insert an std following
        if (inst[i].is_sta) {
            // push following insts out
            (*count)++;
            for (int j = *count - 1; j > i; j--)
                inst[j] = inst[j - 1];

            // set up std
            inst[i + 1].is_sta = false;
            inst[i + 1].is_std = true;

            // remove rc (data reg) from sta and put it on std
            inst[i + 1].rc = inst[i].rc;
            inst[i + 1].rc_val = inst[i].rc_val;
            inst[i].rc = -1;
            inst[i].rc_val.val = 0;

            // remove ra, rb (address computation) from std
            inst[i + 1].ra = -1;
            inst[i + 1].rb = -1;

            inst[i].opcodename = "sta";
            inst[i + 1].opcodename = "std";
        }
    }

    if (*count == 0) {
        memset(&inst[0], 0, sizeof(Instruction));
        inst[0].opcodename = "nop";
        inst[0].pc = pc;
        inst[0].upc = 0;
        inst[0].length = *size;
        inst[0].ra = inst[0].rb = inst[0].rc = inst[0].rd = -1;
        inst[0]._impl = 0;
        inst[0].bom = inst[0].eom = 1;
        inst[0].serialize = 1;
        //printf("serialize: bad insn (PC %lx)\n", pc);
        *count = 1;
    }

    inst[0].bom = 1;
    inst[*count - 1].eom = 1;

    for (int i = 0; i < *count; i++) {
        inst[i].pc = pc;
        inst[i].upc = i;
    }

#ifdef UOPTRACE
    printf("PC = %llx: uops:\n", pc);
    for (int i = 0; i < *count; i++)
        print_uop(&inst[i]);
#endif
}

void inst_exec(Instruction *inst)
{
    IssueState is;
    is.reg.rdflags = 0;
    is.reg.rddata = 0;

    if (inst->is_load || inst->is_sta) {
        uint64_t addr = 0;
        inst->mem_addr = inst->ra_val.val + inst->rb_val.val;
    }
    else if (inst->is_std) {
        inst->mem_value = inst->rc_val.val;
    }
    else if (inst->opcode == OP_mf) {
        inst->rd_val.val = 0;
    }
    else {
        uopimpl_func_t f = (uopimpl_func_t)inst->_impl;

        if (inst->is_branch) {
            is.brreg.riptaken = inst->branch_targ;
            is.brreg.ripseq = inst->branch_fall;
        }

        if (f) {
            f(is, inst->ra_val.val, inst->rb_val.val, inst->rc_val.val,
                    inst->ra_val.flags, inst->rb_val.flags, inst->rc_val.flags);

            inst->rd_val.val = is.reg.rddata;
            inst->rd_val.flags = is.reg.rdflags;
        }

        if (inst->is_branch && inst->br_cond) {
            inst->branch_dest = is.reg.rddata;
            inst->branch_taken = (inst->branch_dest != inst->branch_fall);
        }
        else if (inst->is_branch && inst->br_indir) {
            inst->branch_dest = is.reg.rddata;
            inst->branch_targ = is.reg.rddata;
        }
    }

#ifdef EXECTRACE
    printf("** exec: ");
    print_uop(inst);
    printf("     (ra = %x flags = %x)\n", inst->ra_val.val, inst->ra_val.flags);
    printf("     (rb = %x flags = %x)\n", inst->rb_val.val, inst->rb_val.flags);
    printf("     (rc = %x flags = %x)\n", inst->rc_val.val, inst->rc_val.flags);
    printf(" --> (rd = %x flags = %x)\n", inst->rd_val.val, inst->rd_val.flags);
#endif
}

void inst_postld(Instruction *inst)
{
    if (inst->type & OPCLASS_LOAD) {
        if (inst->opcode == OP_ldx) {
            switch(inst->mem_size) {
                case 1:
                    inst->rd_val.val = (inst->mem_value & 0x7f) |
                        ((inst->mem_value & 0x80) ? 0xffffffffffffff80 : 0);
                    break;
                case 2:
                    inst->rd_val.val = (inst->mem_value & 0x7fff) |
                        ((inst->mem_value & 0x8000) ? 0xffffffffffff8000 : 0);
                    break;
                case 4:
                    inst->rd_val.val = (inst->mem_value & 0x7fffffff) |
                        ((inst->mem_value & 0x80000000) ? 0xffffffff80000000 : 0);
                    break;
                case 8:
                    inst->rd_val.val = inst->mem_value;
                    break;
                default:
                    assert(false);
            }
        }
        else {
            inst->rd_val.val = inst->mem_value;
        }
    }
}

void inst_regread(Instruction *inst, Arch_Ctx *ctx)
{
    if (inst->ra != -1 && inst->ra < INSTLIB_NREGS)
        inst->ra_val = ctx->rf[inst->ra];
    if (inst->rb != -1 && inst->rb < INSTLIB_NREGS)
        inst->rb_val = ctx->rf[inst->rb];
    if (inst->rc != -1 && inst->rc < INSTLIB_NREGS)
        inst->rc_val = ctx->rf[inst->rc];

    if (inst->is_std) {
        /*
        printf("inst_regread: std: read sta = %lx\n", ctx->sta);
        */
        inst->mem_addr = ctx->sta;
    }
}

void inst_writeback(Instruction *inst, Arch_Ctx *ctx)
{
    if (inst->rd != -1 && inst->rd < INSTLIB_NREGS) {
        if (inst->rd != REG_zero) {
            //printf("set value (reg %d): %llx\n", inst->rd, inst->rd_val.val);
            ctx->rf[inst->rd].val = inst->rd_val.val;
            ctx->rf[inst->rd].flags = inst->rd_val.flags;
        }

        if (inst->setflags && (inst->rd != REG_zero)) {
            ctx->rf[inst->rd].flags = inst->rd_val.flags;
            //printf("set flags (%d): %llx\n", inst->setflags, inst->rd_val.flags);
        }
    }

    if (inst->setflags & SETFLAG_ZF)
        ctx->rf[REG_zf].flags = inst->rd_val.flags;
    if (inst->setflags & SETFLAG_CF)
        ctx->rf[REG_cf].flags = inst->rd_val.flags;
    if (inst->setflags & SETFLAG_OF)
        ctx->rf[REG_of].flags = inst->rd_val.flags;

    inst_construct_flags(ctx);

    ctx->pc = inst->is_branch ? inst->rd_val.val : (inst->pc + inst->length);
    ctx->upc = 0;

    if (inst->is_sta) {
        /*
        printf("inst writeback: set sta = %lx (ra = %lx rb = %lx rd = %lx)\n",
                inst->mem_addr, inst->ra_val.val, inst->rb_val.val, inst->rd_val.val);
                */
        ctx->sta = inst->mem_addr;
    }
}

void inst_construct_flags(Arch_Ctx *ctx)
{
    uint16_t newflags =
        (FLAG_OF & ctx->rf[REG_of].flags) |
        (FLAG_CF & ctx->rf[REG_cf].flags) |
        (FLAG_ZAPS & ctx->rf[REG_zf].flags) |
        (~(FLAG_OF | FLAG_CF | FLAG_ZAPS) & ctx->rf[REG_flags].flags);

    /*
    printf("construct flags: of=%04x cf=%04x zaps=%04x flags=%04x --> %04x\n",
            ctx->rf[REG_of].flags,
            ctx->rf[REG_cf].flags,
            ctx->rf[REG_zf].flags,
            ctx->rf[REG_flags].flags,
            newflags);
    */

    ctx->rf[REG_flags].flags = newflags;
}

void inst_deconstruct_flags(Arch_Ctx *ctx)
{
    //printf("deconstruct flags (%x)\n", ctx->rf[REG_flags].flags);
    ctx->rf[REG_of].flags = ctx->rf[REG_flags].flags & FLAG_OF;
    ctx->rf[REG_cf].flags = ctx->rf[REG_flags].flags & FLAG_CF;
    ctx->rf[REG_zf].flags = ctx->rf[REG_flags].flags & FLAG_ZAPS;
}

void uop_impl_collcc(IssueState& state, W64 ra, W64 rb, W64 rc, W16 raflags, W16 rbflags, W16 rcflags);

void inst_synthesize_collcc(Instruction *in)
{
    memset(in, 0, sizeof(Instruction));
    in->bom = in->eom = 1;
    in->opcodename = "synth-collcc";
    in->ra = REG_zf;
    in->rb = REG_cf;
    in->rc = REG_of;
    in->rd = REG_flags;
    in->setflags = 7;
    in->_impl = (void *)&uop_impl_collcc;
}

#ifdef __TEST__
int main(int argc, char **argv)
{
    uint8_t bytes[32];
    argc--; argv++;
    for (int i = 0; i < argc; i++) {
        bytes[i] = strtoull(argv[i], NULL, 16);
    }

    Instruction insts[32];
    int count = 0;
    int size = argc;

    Machine_Ctx machctx = { 0xdeadbeef, };

    inst_decode(insts, &count, 0, bytes, &size, &machctx);

    for (int i = 0; i < count; i++)
        print_uop(&insts[i]);

    return 0;
}
#endif
