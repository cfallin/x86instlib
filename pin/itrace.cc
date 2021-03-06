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

/*
 * An itrace is an "instruction trace" which is really a limited memory
 * snapshot coupled with a register state sequence (a dump of integer registers
 * after every instruction boundary), designed to be used with an
 * execute-at-execute simulator. The tracer lazily creates a memory image
 * consisting of pages touched by the application during execution. Using this
 * partial memory image, and the initial register snapshot, the backend can
 * simulate execution, using the retired right-path register state as a check
 * to its own retired instructions. If any incorrect register value is seen in
 * the retired state, the backend can simply restart using the trace's register
 * state. So the actual instructions during simulation are still generated by
 * the backend simulator, not provided by the trace (and the backend can
 * speculate and go offpath, up to the limit of the partial memory image it has
 * available); but the trace provides enough information to do this simulation
 * and check it at every step, correcting if necessary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <queue>
#include <set>
#include <map>
#include <dlfcn.h>

#include <pin.H>
#include <xed-iclass-enum.h>
#include <xed-category-enum.h>

#include "itrace.h"
#include "sha1.h"

using namespace LEVEL_BASE;
using namespace std;

KNOB<uint64_t> KnobSkip(KNOB_MODE_WRITEONCE, "pintool", "s", "0",
        "instructions to skip before starting the trace");
KNOB<uint64_t> KnobCount(KNOB_MODE_WRITEONCE, "pintool", "c", "100000000",
        "instructions to trace before exiting");
KNOB<string> KnobTraceDir(KNOB_MODE_WRITEONCE, "pintool", "o", "",
        "trace basename (thread traces will be created as <basename>.<tid>)");
KNOB<string> KnobLog(KNOB_MODE_WRITEONCE, "pintool", "l", "",
        "log output file (stderr by default)");

FILE *log = NULL;

#if 1
#define DEBUG(x) /* nothing */
#else
#define DEBUG(x) x
#endif

struct Sha1Hash {
    uint8_t digest[SHA1_DIGEST_SIZE];

    void hash(char *page) {
        SHA1_CTX s;
        SHA1_Init(&s);
        SHA1_Update(&s, (const uint8_t *)page, ITRACE_PAGESIZE);
        SHA1_Final(&s, digest);
    }

    bool operator==(const Sha1Hash& other) const {
        return !memcmp(digest, other.digest, SHA1_DIGEST_SIZE);
    }
    bool operator!=(const Sha1Hash& other) const {
        return ! (*this == other);
    }
};

int64_t skip_insns = 0, skip_epochs = 0, skipped_insns = 0;
int skip_mode = 0;

#define MAX_THDS 64

struct ThreadState {
    void *itrace;

    itrace_rec_t itrace_rec;
    itrace_store_t itrace_store;
    int itrace_dump_store;
    bool prev_store;
    uint64_t prev_store_addr;
    int prev_store_size;

    map<uint64_t, char*> touched_pages;
    map<uint64_t, Sha1Hash> touched_pages_dumped_hash;

    uint64_t traced_insns;

    queue<itrace_store_t> otherthd_injections;
    bool dump_injections;
} ts[MAX_THDS];

PIN_MUTEX injmutex; // must hold this mutex to touch the cross-thread injections queues

void Fini(INT32 code, void *p);

const char *trace_basename;

void ctx_from_reg(itrace_rec_t *regs, CONTEXT *ctx)
{
    REG intregs[] = { LEVEL_BASE::REG_RAX, LEVEL_BASE::REG_RCX, LEVEL_BASE::REG_RDX, LEVEL_BASE::REG_RBX, LEVEL_BASE::REG_RSP, LEVEL_BASE::REG_RBP, LEVEL_BASE::REG_RSI, LEVEL_BASE::REG_RDI,
        LEVEL_BASE::REG_R8, LEVEL_BASE::REG_R9, LEVEL_BASE::REG_R10, LEVEL_BASE::REG_R11, LEVEL_BASE::REG_R12, LEVEL_BASE::REG_R13, LEVEL_BASE::REG_R14, LEVEL_BASE::REG_R15 };

    memset(regs->regs, 0, sizeof(regs->regs));

    for (int i = 0; i < 16; i++)
        regs->regs[i] = PIN_GetContextReg(ctx, intregs[i]);

    regs->rflags = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RFLAGS);
    regs->rip = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP);
    regs->fsbase = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_FS_BASE);

    FPSTATE fpstate;
    PIN_GetContextFPState(ctx, &fpstate);

    // first part of fpstate is just an FXSAVE record.
    // XMM regs are at byte 160+ (i.e., qword 20+)
    // MMX regs are at byte 32+ (i.e., qword 4+) and occupy
    // 16 bytes each (upper 8 bytes are reserved)
    uint64_t *fxsave = (uint64_t *)&fpstate;

    for (int i = 0; i < 32; i++)
        regs->regs[i + 16] = fxsave[i + 20];

    for (int i = 0; i < 8; i++)
        regs->regs[i + 48] = fxsave[2*i + 4];
}

void itrace_check_open(int tid)
{
    if (!ts[tid].itrace) {
        char buf[4096];
        snprintf(buf, sizeof(buf), "%s.%d.%d", trace_basename, getpid(), tid);
        ts[tid].itrace = itrace_open(buf, ITRACE_WRITE);
        if (!ts[tid].itrace) {
            fprintf(stderr, "Could not open trace '%s' for writing.\n", buf);
            exit(1);
        }

        ts[tid].traced_insns = 0;
    }
}

/***************** PIN CALLBACKS *********************/

void cb_CheckPrevStore(int tid)
{
    if (skip_mode) return;
    if (ts[tid].prev_store) {
        uint8_t *p = (uint8_t *)ts[tid].prev_store_addr;
        uint8_t *dst = (uint8_t *)ts[tid].itrace_store.data;

        ts[tid].itrace_store.address = ts[tid].prev_store_addr;
        ts[tid].itrace_store.size = ts[tid].prev_store_size;
        memset(ts[tid].itrace_store.data, 0, ITRACE_MAX_STORESIZE);
        memcpy(ts[tid].itrace_store.data, (void *)ts[tid].prev_store_addr, ts[tid].prev_store_size);
        ts[tid].itrace_store.auxflags = 0; // reserved for future expansion
        ts[tid].itrace_rec.num_stores++;
        ts[tid].itrace_dump_store = 1;

        /*
        printf("store: addr %lx size %d data:\n    ", ts[tid].itrace_store.address, ts[tid].itrace_store.size);
        for (int i = 0; i < ts[tid].itrace_store.size; i++) {
            printf("%02x ", ((uint8_t*)ts[tid].itrace_store.data)[i]);
        }
        printf("\n");
        */

        ts[tid].prev_store = false;

        // set up store injections for all other threads
        PIN_MutexLock(&injmutex);
        for (int t = 0; t < MAX_THDS; t++) {
            if (t == tid) continue;
            if (!ts[t].itrace) continue;

            /*
            printf("injection from tid %d to tid %d for store addr %lx size %d data %lx\n",
                    tid, t, ts[tid].itrace_store.address, ts[tid].itrace_store.size, ts[tid].itrace_store.data);
                    */
            ts[t].otherthd_injections.push(ts[tid].itrace_store);
        }
        PIN_MutexUnlock(&injmutex);
    }
}

void cb_BeforeMem(int tid, ADDRINT addr)
{
    if (skip_mode) return;
    // split pages
    const uint64_t mask = ~(0xfffULL);
    if (((addr + 8) & mask) != (addr & mask))
        cb_BeforeMem(tid, addr + 8);

    addr &= ~(0xfffULL);
    if (ts[tid].touched_pages.find(addr) == ts[tid].touched_pages.end()) {
        void *p = (void *)addr;
        char *buf = (char *)malloc(ITRACE_PAGESIZE);
        PIN_SafeCopy(buf, p, ITRACE_PAGESIZE);
        ts[tid].touched_pages[addr] = buf;
    }

    ts[tid].dump_injections = true;
}

void post_syscall_touch_mem(int tid)
{
    for (map<uint64_t, char *>::iterator it = ts[tid].touched_pages.begin();
            it != ts[tid].touched_pages.end(); it++) {
        free(it->second);
        it->second = NULL;
    }

    ts[tid].touched_pages.clear();
}

void flush_pages(int tid)
{
    itrace_check_open(tid);

    int idx = 0;
    for (map<uint64_t, char *>::iterator it = ts[tid].touched_pages.begin();
            it != ts[tid].touched_pages.end(); it++, idx++) {

        Sha1Hash s;

        uint64_t addr = it->first;
        char *data = it->second;

        if (!data) {
            data = (char *)malloc(ITRACE_PAGESIZE);
            PIN_SafeCopy(data, (void *)addr, ITRACE_PAGESIZE);
            it->second = data;
        }

        s.hash(data);
        if (ts[tid].touched_pages_dumped_hash.find(addr) == ts[tid].touched_pages_dumped_hash.end() ||
                s != ts[tid].touched_pages_dumped_hash[addr]) {
            ts[tid].touched_pages_dumped_hash[addr] = s;
            itrace_dump_page(ts[tid].itrace, addr, data);
        }

    }

    itrace_dump_page(ts[tid].itrace, 0, NULL);
    itrace_flush(ts[tid].itrace);
}

void cb_BeforeSyscall(unsigned int tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
    if (skip_mode) return;
    ts[tid].itrace_rec.is_syscall = 1;
    flush_pages(tid);
}

void cb_AfterSyscall(unsigned int tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
    if (skip_mode) return;
    post_syscall_touch_mem(tid);
}

void cb_BeforeLock(int tid)
{
    if (skip_mode) return;
    ts[tid].dump_injections = true;
}

void cb_BeforeInsn(int tid, CONTEXT *ctx)
{
    if (skip_mode) return;
    itrace_check_open(tid);

    cb_BeforeMem(tid, PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
    ctx_from_reg(&ts[tid].itrace_rec, ctx);

    if (ts[tid].dump_injections) {
        PIN_MutexLock(&injmutex); // matched by unlock below
        ts[tid].itrace_rec.num_stores += ts[tid].otherthd_injections.size();
    }

    itrace_dump_insn(ts[tid].itrace, &ts[tid].itrace_rec);
    if (ts[tid].itrace_dump_store) {
        itrace_dump_store(ts[tid].itrace, &ts[tid].itrace_store);
        ts[tid].itrace_dump_store = 0;
    }

    if (ts[tid].dump_injections) {
        //printf("Dumping injections for tid %d:\n", tid);
        while (!ts[tid].otherthd_injections.empty()) {
            itrace_store_t strec = ts[tid].otherthd_injections.front();
            ts[tid].otherthd_injections.pop();
            strec.auxflags = ITRACE_STORE_OTHER;
            //printf("* %lx\n", strec.address);
            itrace_dump_store(ts[tid].itrace, &strec);
        }
        PIN_MutexUnlock(&injmutex); // matched by lock above
        ts[tid].dump_injections = false;
    }

    memset(&ts[tid].itrace_rec, 0, sizeof(itrace_rec_t));

    ts[tid].traced_insns++;

    if ((ts[tid].traced_insns % 1000000) == 0) {
        fprintf(log, "Traced %lu instructions (TID %d).\n", ts[tid].traced_insns, tid);
        fflush(log);
    }

    if (KnobCount.Value() > 0 && ts[tid].traced_insns >= KnobCount.Value()) {
        fprintf(log, "Finishing.\n");
        fflush(log);
        Fini(0, 0);
        exit(0);
    }

    memset(&ts[tid].itrace_rec, 0, sizeof(itrace_rec_t));
    memset(&ts[tid].itrace_store, 0, sizeof(itrace_store_t));
}

void cb_BeforeStore(int tid, ADDRINT addr, int size)
{
    if (skip_mode) return;
    itrace_check_open(tid);
    ts[tid].prev_store = true;
    ts[tid].prev_store_addr = addr;
    ts[tid].prev_store_size = size;
    assert(size <= ITRACE_MAX_STORESIZE);
}

void cb_AfterRDTSC(CONTEXT *ctx)
{
    if (skip_mode) return;
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RAX, 0);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDX, 0);
    PIN_ExecuteAt(ctx);
}

static bool is_cpuid(INS ins)
{
    uint8_t bytes[16] = {0, };
    ADDRINT rip = INS_Address(ins);
    PIN_SafeCopy(bytes, (void *)rip, 16);
    return (bytes[0] == 0x0f && bytes[1] == 0xa2);
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

void cb_BeforeCPUID(CONTEXT *ctx)
{
    uint32_t eax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX);
    if (eax > 1) eax = 0;

    // set values according to our emulated CPUID leaves
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RAX, cpuid_leaves[eax].eax);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RBX, cpuid_leaves[eax].ebx);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RCX, cpuid_leaves[eax].ecx);
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RDX, cpuid_leaves[eax].edx);

    // skip over actual CPUID instruction
    PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP,
            PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) + 2);

    PIN_ExecuteAt(ctx);
}

ADDRINT cb_SkipIf(uint64_t count)
{
    // note: no locking here: OK if we're slightly off when multiple threads run.
    skip_insns -= count;
    return (skip_insns <= 0);
}

void cb_SkipThen()
{
    PIN_MutexLock(&injmutex);
    skip_epochs--;
    if (skip_epochs > 0) {
        skipped_insns += 1000000;
        skip_insns = 1000000;
        fprintf(log, "Skipping: %ld / %ld\n", skipped_insns, KnobSkip.Value());
        fflush(log);
    }
    else {
        skip_insns = 0;
        skip_mode = 0;
        PIN_RemoveInstrumentation();
        fprintf(log, "Done skipping, starting trace\n", 0);
        fflush(log);
    }
    PIN_MutexUnlock(&injmutex);
}

void Instr_Ins(INS ins, void *p)
{
    uint8_t bytes[16] = {0, };
    ADDRINT rip = INS_Address(ins);
    PIN_SafeCopy(bytes, (void *)rip, 16);

    if (INS_LockPrefix(ins)) {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeLock,
            IARG_THREAD_ID,
            IARG_CALL_ORDER, 0,
            IARG_END);
    }

    INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)cb_CheckPrevStore,
            IARG_THREAD_ID,
            IARG_CALL_ORDER, 1,
            IARG_END);

    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeStore,
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_CALL_ORDER, 2,
                IARG_END);
    }

    for (int i = 0; i < INS_MemoryOperandCount(ins); i++) {
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeMem,
                IARG_THREAD_ID,
                IARG_MEMORYOP_EA, i,
                IARG_CALL_ORDER, 3,
                IARG_END);
    }

    INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeInsn,
            IARG_THREAD_ID,
            IARG_CONTEXT,
            IARG_CALL_ORDER, 4,
            IARG_END);

    if (is_cpuid(ins))
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeCPUID,
                IARG_CONTEXT,
                IARG_CALL_ORDER, 5,
                IARG_END);

    if (INS_IsRDTSC(ins))
        INS_InsertCall(
                ins, IPOINT_AFTER, (AFUNPTR)cb_AfterRDTSC,
                IARG_CONTEXT,
                IARG_END);
}

void TRACE_Ins(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        if (skip_mode) {
            // skip mode: nominally we have one if/then instrumentation pair
            // per basic block. however, if a BB has a CPUID, we need to
            // go per-instruction and hook the CPUID. This is so we get
            // the right emulated CPUID values even during program/glibc startup
            // (when we're skipping).
            bool has_cpuid = false;
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
                if (is_cpuid(ins)) has_cpuid = true;

            if (!has_cpuid) {
                BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR)cb_SkipIf,
                        IARG_UINT32, BBL_NumIns(bbl),
                        IARG_END);
                BBL_InsertThenCall(bbl, IPOINT_BEFORE, (AFUNPTR)cb_SkipThen,
                        IARG_END);
            }
            else {
                for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)cb_SkipIf,
                            IARG_CALL_ORDER, 0,
                            IARG_UINT32, 1,
                            IARG_END);
                    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)cb_SkipThen,
                            IARG_CALL_ORDER, 1,
                            IARG_END);
                    if (is_cpuid(ins))
                        INS_InsertCall(
                                ins, IPOINT_BEFORE, (AFUNPTR)cb_BeforeCPUID,
                                IARG_CONTEXT,
                                IARG_CALL_ORDER, 2,
                                IARG_END);

                }
            }
        }
        else {
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
                Instr_Ins(ins, v);
        }
    }
}

void Init()
{
    skip_insns = KnobSkip.Value();
    if (skip_insns > 0)
        skip_mode = 1;

    skip_epochs = skip_insns / 1000000;
    skip_insns -= skip_epochs * 1000000;
    skipped_insns = 0;

    trace_basename = KnobTraceDir.Value().c_str();

    for (int i = 0; i < MAX_THDS; i++) {
        ts[i].itrace = NULL;
        ts[i].prev_store = false;
        ts[i].itrace_dump_store = 0;
        memset(&ts[i].itrace_rec, 0, sizeof(itrace_rec_t));
        memset(&ts[i].itrace_store, 0, sizeof(itrace_store_t));
    }
    PIN_MutexInit(&injmutex);
}

void Fini(INT32 code, void *p)
{
    for (int i = 0; i < MAX_THDS; i++) {
        if (ts[i].itrace) {
            fprintf(log, "Finishing: flushing pages for tid %d\n", i);
            fflush(log);
            flush_pages(i);
            itrace_close(ts[i].itrace);
            fprintf(log, "Traced %lu instructions in thread %d.\n", ts[i].traced_insns, i);
            fflush(log);
        }
    }

    if (log != stderr)
        fclose(log);
}


void usage()
{
    fprintf(stderr, "Usage: pin -t pintool.so [options] -- {command}\n\n");
    fprintf(stderr, "%s\n", KNOB_BASE::StringKnobSummary().c_str());
}

int main(int argc, char **argv)
{
    //Initialize PIN
    if (PIN_Init(argc, argv)) {
        usage();
        return 1;
    }

    if (KnobLog.Value() != "") {
        char filename[1024];
        snprintf(filename, sizeof(filename), "%s.%d", KnobLog.Value().c_str(), getpid());
        log = fopen(filename, "w");
    }
    if (!log)
        log = stderr;
    
    //Instrument instructions
    TRACE_AddInstrumentFunction(TRACE_Ins, 0);
    PIN_AddSyscallEntryFunction(cb_BeforeSyscall, 0);
    PIN_AddSyscallExitFunction(cb_AfterSyscall, 0);

    PIN_AddFiniFunction(Fini, 0);

    Init();

    PIN_StartProgram();

    return 0;
}
