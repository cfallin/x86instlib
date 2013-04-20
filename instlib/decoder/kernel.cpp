//
// PTLsim: Cycle Accurate x86-64 Simulator
// Linux Kernel Interface
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlsim.h>
#include <config.h>
#include <stats.h>
#include <kernel.h>
#include <loader.h>

#define __INSIDE_PTLSIM__
#include <ptlcalls.h>

// Userspace PTLsim only supports one VCPU:
int current_vcpuid() { return 0; }

static inline W64 do_syscall_64bit(W64 syscallid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  assert(false);
  return 0;
}

struct user_desc_32bit {
  W32 entry_number;
  W32 base_addr;
  W32 limit;
  W32 seg_32bit:1;
  W32 contents:2;
  W32 read_exec_only:1;
  W32 limit_in_pages:1;
  W32 seg_not_present:1;
  W32 useable:1;
};

#ifdef __x86_64__
// Parameters in: ebx ecx edx esi edi ebp
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
    assert(false);
    return 0;
}

Waddr get_fs_base() {
    return 0;
}

Waddr get_gs_base() {
    return 0;
}

#else
// We need this here because legacy x86 readily runs out of registers:
static W32 tempsysid;

// 32-bit only
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  tempsysid = sysid;

  asm volatile ("push %%ebp ; movl %%eax,%%ebp ; movl tempsysid,%%eax ; int $0x80 ; pop %%ebp" : "=a" (rc) :
                "b" (arg1), "c" (arg2), "d" (arg3), 
                "S" (arg4), "D" (arg5), "0" (arg6));
  return rc;
}

Waddr get_fs_base() {
  user_desc_32bit ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number = ctx.seg[SEGID_FS].selector >> 3;
  int rc = sys_get_thread_area((user_desc*)&ud);
  return (rc) ? 0 : ud.base_addr;
}

Waddr get_gs_base() {
  user_desc_32bit ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number = ctx.seg[SEGID_GS].selector >> 3;
  int rc = sys_get_thread_area((user_desc*)&ud);
  return (rc) ? 0 : ud.base_addr;
}

#endif // !__x86_64__

int Context::write_segreg(unsigned int segid, W16 selector) {
  // Normal userspace PTLsim: assume it's OK
  assert(segid < SEGID_COUNT);

  seg[segid].selector = selector;
  update_shadow_segment_descriptors();
  return 0;
}

void Context::update_shadow_segment_descriptors() {
  W64 limit = (use64) ? 0xffffffffffffffffULL : 0xffffffffULL;

  SegmentDescriptorCache& cs = seg[SEGID_CS];
  cs.present = 1;
  cs.base = 0;
  cs.limit = limit;

  virt_addr_mask = limit;

  SegmentDescriptorCache& ss = seg[SEGID_SS];
  ss.present = 1;
  ss.base = 0;
  ss.limit = limit;

  SegmentDescriptorCache& ds = seg[SEGID_DS];
  ds.present = 1;
  ds.base = 0;
  ds.limit = limit;

  SegmentDescriptorCache& es = seg[SEGID_ES];
  es.present = 1;
  es.base = 0;
  es.limit = limit;
  
  SegmentDescriptorCache& fs = seg[SEGID_FS];
  fs.present = 1;
  fs.base = get_fs_base();
  fs.limit = limit;

  SegmentDescriptorCache& gs = seg[SEGID_GS];
  gs.present = 1;
  gs.base = get_gs_base();
  gs.limit = limit;
}

// Avoid c++ scoping problems:

extern "C" void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
    assert(false);
}

//
// Shadow page accessibility table format (x86-64 only): 
// Top level:  1048576 bytes: 131072 64-bit pointers to chunks
//
// Leaf level: 65536 bytes per chunk: 524288 bits, one per 4 KB page
// Total: 131072 chunks x 524288 pages per chunk x 4 KB per page = 48 bits virtual address space
// Total: 17 bits       + 19 bits                + 12 bits       = 48 bits virtual address space
//
// In 32-bit version, SPAT is a flat 131072-byte bit vector.
//

byte& AddressSpace::pageid_to_map_byte(spat_t top, Waddr pageid) {
    assert(false);
    static byte x;
    return x;
}

void AddressSpace::make_accessible(void* p, Waddr size, spat_t top) {
    assert(false);
}

void AddressSpace::make_inaccessible(void* p, Waddr size, spat_t top) {
    assert(false);
}

AddressSpace::AddressSpace() { }

AddressSpace::~AddressSpace() { }

AddressSpace::spat_t AddressSpace::allocmap() {
    return 0;
}
void AddressSpace::freemap(AddressSpace::spat_t top) {
}

void AddressSpace::reset() {
}

void AddressSpace::setattr(void* start, Waddr length, int prot) {
  assert(false);
}

int AddressSpace::getattr(void* addr) {
    assert(false);
  return 0;
}
 
int AddressSpace::mprotect(void* start, Waddr length, int prot) {
    assert(false);
  return 0;
}

int AddressSpace::munmap(void* start, Waddr length) {
    assert(false);
  return 0;
}

void* AddressSpace::mmap(void* start, Waddr length, int prot, int flags, int fd, W64 offset) {
    assert(false);
    return 0;
}

void* AddressSpace::mremap(void* start, Waddr oldlength, Waddr newlength, int flags) {
    assert(false);
    return 0;
}

void* AddressSpace::setbrk(void* reqbrk) {
    assert(false);
    return 0;
}

W64 ldt_seg_base_cache[LDT_SIZE];

// Saved and restored by asm code:
FXSAVEStruct x87state;
W16 saved_cs;
W16 saved_ss;
W16 saved_ds;
W16 saved_es;
W16 saved_fs;
W16 saved_gs;

void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  assert(false);
}

//
// SYSCALL instruction from x86-64 mode
//

void handle_syscall_64bit() {
    assert(false);
}

void handle_syscall_32bit(int semantics) {
  assert(false);
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
    assert(false);
}
