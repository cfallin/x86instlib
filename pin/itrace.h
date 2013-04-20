/*
 * itrace: instruction traces + mem images for checked execution-driven simulation.
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

#ifndef _ITRACE_H_
#define _ITRACE_H_

/*
 * itrace format on disk:
 *
 * - an itrace consists of three files: the register trace, the store trace, the image
 *   descriptor, the image data file.
 *
 * - the register trace is a sequence of itrace_rec_t records, dumped to disk,
 *   in little-endian format, gzipped.
 *
 * - the store trace is a sequence of itrace_store_t records, dumped to disk,
 *   in little-endian format, gzipped.
 *
 * - the memory descriptor dump is a sequence of itrace_pagedesc_t records,
 *   likewise in little-endian format and gzipped.
 *
 * - finally, the image file is a sequence of page-aligned blocks of data, as
 *   described by the pagedesc_t records, which correspond to the benchmark's
 *   memory data at time zero (or before first touch, equivalently). A new
 *   memory image is dumped after every register trace entry that has the
 *   ``is_syscall'' flag set (since a syscall may update any memory).
 */

#include <stdint.h>

typedef struct {
    uint64_t regs[64]; // 16 GPRs (RAX..R15) + 32 half-XMM regs (XMM0L, XMM0H, ..., XMM15H) + 8 MMX + 8 spare
    uint64_t rflags;
    uint64_t rip;
    uint64_t fsbase;
    uint64_t is_syscall; // this is a syscall. expect a new memory dump following.
    uint64_t num_stores; // associated store record in store trace? (indicates store *count*)
} itrace_rec_t;

typedef struct {
    uint64_t address;
    uint64_t data[4];
    uint64_t size;
    uint64_t auxflags; // 0 == this thread; 1 == injection from other thread, syscall, IO, etc
} itrace_store_t;

#define ITRACE_MAX_STORESIZE 32

#define ITRACE_STORE_SELF  0
#define ITRACE_STORE_OTHER 1

#define ITRACE_PAGESIZE 4096

typedef struct {
    uint64_t lin_addr; // linear address
} itrace_pagedesc_t;

#define ITRACE_READ 1
#define ITRACE_WRITE 2

void *itrace_open(const char *dirname, int mode);
void  itrace_close(void *it);

/* itrace writer */
void itrace_dump_page(void *it, uint64_t lin_addr, void *data);
void itrace_dump_insn(void *it, itrace_rec_t *regs);
void itrace_dump_store(void *it, itrace_store_t *store);
void itrace_flush(void *it);

/* itrace reader -- these return non-zero on EOF or error */
int itrace_read_pagedesc(void *it, uint64_t *addr); // read next page's address
int itrace_read_page(void *it, void *p);            // call after read_pagedesc; read associated data
int itrace_read_rec(void *it, itrace_rec_t *regs);
int itrace_read_store(void *it, itrace_store_t *store);

#endif
