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

#ifndef _INSTLIB_INST_H_
#define _INSTLIB_INST_H_

#include <stdint.h>

//#define UOPTRACE
//#define EXECTRACE

// uarch reg count: architectural state, plus temps used in the
// macroinsn->uop translation. This "u-architectural state" is
// the architectural state really implemented by the machine, e.g.
// as the number of logical registers during renaming.
#define INSTLIB_NREGS_UARCH 88 /* from decoder/ptlhwdef.h */

// full reg count: uarch regs, plus temps we allow the "user" (hardware
// optimizer) to allocate. These temps are guaranteed not to be used by
// uop translations and can allow further renaming. All nominally-uarch-level
// functional interfaces (e.g. Funcsim) have this many registers so that
// they can directly retire (write back) optimized uops using the additional
// temps.

// number of tmps
#define INSTLIB_USERTMPS 128
// first tmp
#define INSTLIB_USERTMP INSTLIB_NREGS_UARCH

// total number of regs
#define INSTLIB_NREGS (INSTLIB_NREGS_UARCH + INSTLIB_USERTMPS)

// last reg which can be used to communicate across macroinsns (i.e., not uISA temps)
#define INSTLIB_NREGS_MACROINSN 72 /* from decoder/ptlhwdef.h */


#define INSTLIB_MAX_UOPS 16 /* from decoder/ptlhwdef.h */

#define FAULT_INVALID 1
#define FAULT_DIV0    2
#define FAULT_SYSCALL 3

/* A note on flag handling:
 *
 * Every microarchitectural register has a 64-bit data value and an f-bit flags
 * value.
 *
 * Initially, a dedicated register (FLAG_REG) holds don't-care in its data and
 * the full set of flags in its flags.
 *
 * Inidividual flags are renamed. There are n (FLAG_COUNT) of these flags.
 * There are n virtual-microarchitectual registers (starting with
 * FLAG_REG_BASE) that point to the current real-microarchitectural register
 * holding that flag. Each of these flags has a bit in the ``setflags'' mask on
 * every uop. If that bit is set on a uop, then the uop writes to the given
 * destination register, but the pointer is moved to point to that destination
 * register as well.
 */

#define FLAG_N 3
#define FLAG_REG_BASE 80 /* (REG_zf) big n in setflags mask maps to base+n "arch reg pointer" */
#define FLAG_REG 57
#define FLAG_ALL 7 /* bitmask */

typedef struct Reg {
    uint64_t val;
    int flags;
} Reg;

typedef struct Instruction {
    /* PC of this instruction */
    uint64_t pc;
    /* uPC of this instruction */
    uint64_t upc;
    int bom, eom; /* beginning-of-macroinst, end-of-macroinst */
    int length;   /* instruction length */

    /* opcode */
    int opcode;
    int type;
    const char *opcodename;
    int syscall;

    /* register source values */
    int ra, rb, rc; /* -1 for none */
    Reg ra_val, rb_val, rc_val;

    /* register dest value */
    int rd; /* -1 for none */
    Reg rd_val;
    int setflags; /* FLAG_COUNT-bit bitmask: if bit n is set, then map FLAG_REG_BASE+n reg to rd */

    /* memory access information */
    int is_mem;       /* is this a load/store? */
    int is_load, is_sta, is_std; /* load or store {address, data}? (sta comes first, then std) */
    uint64_t mem_addr; /* address if applicable */
    uint64_t mem_physaddr; /* translated address if applicable */
    int mem_size;  /* memory operand size in bytes */
    uint64_t mem_value; /* value loaded from memory or to be written to memory */

    /* branch information */
    int is_branch;        /* is this a branch? */
    int br_indir;         /* indirect branch (incl. call or ret)? */
    int br_cond;          /* is this a conditional branch? */
    int br_call;          /* is this a call? */
    int br_ret;           /* is this a ret? */
    uint64_t branch_targ; /* branch destination (if taken) */
    uint64_t branch_fall; /* branch fallthrough (if not taken) */
    int branch_taken;     /* branch taken? (set as soon as resolved: in decode
                             for unconditional, execute for conditional) */
    uint64_t branch_dest; /* resolved branchd destination */

    /* need to serialize (for assist, etc)? */
    int serialize;

    /* fault information */
    int fault;

    /* internal */
    void *_impl;
} Instruction;


typedef struct Arch_Ctx {

    /* register file state */
    Reg rf[INSTLIB_NREGS];

    /* program counter in fetch stage */
    uint64_t pc;
    uint64_t upc;

    /* implicit store-address register (for sta-std pairs) */
    uint64_t sta;

} Arch_Ctx;

typedef struct {
    uint64_t fs;
} Machine_Ctx;

#ifdef __cplusplus
extern "C" {
#endif

/* initialize an arch context to reset state */
void arch_ctx_init(Arch_Ctx *ctx);

/* decode an instruction from the given instruction bytes.
 * takes array of Instruction in 'inst' and array size in *count;
 * returns number of filled insts in *count. Array size should be at
 * least INSTLIB_MAX_UOPS. Size of incoming bytestream in *size;
 * number of bytes consumed returned in *size. */
void inst_decode(Instruction *inst, int *count, uint64_t pc, uint8_t *bytes, int *size, Machine_Ctx *machctx);

/* read an instruction's input registers from the given arch context
 * (may be done instead by a more sophisticated CPU model, e.g.
 * out-of-order and/or bypassing). N.B. Does not handle loads. */
void inst_regread(Instruction *inst, Arch_Ctx *ctx);

/* execute an instruction's operation given the values attached to the
 * structure (does not handle loads/stores) */
void inst_exec(Instruction *inst);

/* perform post-load fixups after filling in mem_value */
void inst_postld(Instruction *inst);

/* write back the instruction's results to the architectural state
 * (may be doen instead by a more sophisticated CPU model as above).
 * N.B. Does not handle stores. */
void inst_writeback(Instruction *inst, Arch_Ctx *ctx);

/* fix-up flags register from individually renamed parts */
void inst_construct_flags(Arch_Ctx *ctx);
/* fix-up individually renamed parts from forced flags register */
void inst_deconstruct_flags(Arch_Ctx *ctx);

/* construct a synthetic collcc op which will collect flags components */
void inst_synthesize_collcc(Instruction *inst);

#ifdef __cplusplus
}
#endif

#endif
