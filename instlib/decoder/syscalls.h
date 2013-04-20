// -*- c++ -*-
//
// System Calls
//
// Copyright 2004-2008 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef __SYSCALLS_H__
#define __SYSCALLS_H__

extern "C" {
  int sys_open(const char* pathname, int flags, int mode);
  int sys_close(int fd);
  ssize_t sys_read(int fd, void* buf, size_t count);
  ssize_t sys_write(int fd, const void* buf, size_t count);
  ssize_t sys_fdatasync(int fd);
  W64 sys_seek(int fd, W64 offset, unsigned int origin);
  int sys_unlink(const char* pathname);
  int sys_rename(const char* oldpath, const char* newpath);
  
  void* sys_mmap(void* start, size_t length, int prot, int flags, int fd, W64 offset);
  int sys_munmap(void * start, size_t length);
  void* sys_mremap(void* old_address, size_t old_size, size_t new_size, unsigned long flags);
  int sys_mprotect(void* addr, size_t len, int prot);
  int sys_madvise(void* addr, size_t len, int action);
  int sys_mlock(const void *addr, size_t len);  
  int sys_munlock(const void *addr, size_t len); 
  int sys_mlockall(int flags);  
  int sys_munlockall(void);
  
  pid_t sys_fork();
  int sys_execve(const char* filename, const char** argv, const char** envp);
  
  pid_t sys_gettid();
  pid_t sys_getpid();
  void sys_exit(int code);
  void* sys_brk(void* newbrk);
  int sys_readlink(const char *path, char *buf, size_t bufsiz);
  W64 sys_nanosleep(W64 nsec);

  struct utsname;
  int sys_uname(struct utsname* buf);
  
  void* malloc(size_t size) __attribute__((__malloc__));
  void free(void* ptr);
  char* getenv(const char* name);
  int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

  int sys_gettimeofday(struct timeval* tv, struct timezone* tz);
  time_t sys_time(time_t* t);
  pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage);

  typedef void (*kernel_sighandler_t)(int signo, siginfo_t *si, void *context);

  // From glibc sysdeps/unix/sysv/linux/kernel_sigaction.h for kernels >= 2.2.x:
  struct kernel_sigaction {
    kernel_sighandler_t k_sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer) (void);
    sigset_t sa_mask;
  };

  long sys_rt_sigaction(int sig, const struct kernel_sigaction* act, struct kernel_sigaction* oldact, size_t sigsetsize);
  int sys_getrlimit(int resource, struct rlimit* rlim);
#ifdef __x86_64__
  W64 sys_arch_prctl(int code, void* addr);
  W64 sys_ptrace(int request, pid_t pid, W64 addr, W64 data);
#else
  int sys_get_thread_area(struct user_desc *u_info);
  W32 sys_ptrace(int request, pid_t pid, W32 addr, W32 data);
#endif
};

#ifdef INLINED_SYSCALLS
#define syslinkage static inline
#else
#define syslinkage extern "C"
#endif

#ifdef __x86_64__

#undef __syscall_return
#define __syscall_return(type, res) return (type)(res);
#define __syscall_clobber "r11","rcx","memory" 
#define __syscall "syscall"

#define declare_syscall0(sysid,type,name) syslinkage type name(void) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall1(sysid,type,name,type1,arg1) syslinkage type name(type1 arg1) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) syslinkage type name(type1 arg1,type2 arg2) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) syslinkage type name(type1 arg1,type2 arg2,type3 arg3) { \
  long __res; asm volatile (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)) : \
  __syscall_clobber); __syscall_return(type,__res); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
  syslinkage type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
  long __res; asm volatile ("movq %5,%%r10 ;" __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
  "d" ((long)(arg3)),"g" ((long)(arg4)) : __syscall_clobber,"r10" ); __syscall_return(type,__res); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
  syslinkage type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) { long __res; asm volatile ("movq %5,%%r10 ; movq %6,%%r8 ; " __syscall \
  : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)) : \
  __syscall_clobber,"r8","r10"); __syscall_return(type,__res); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
  syslinkage type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { long __res; asm volatile \
  ("movq %5,%%r10 ; movq %6,%%r8 ; movq %7,%%r9 ; " __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
   "d" ((long)(arg3)), "g" ((long)(arg4)), "g" ((long)(arg5)), "g" ((long)(arg6)) : __syscall_clobber,"r8","r10","r9" ); __syscall_return(type,__res); }

#define __NR_read                                0
#define __NR_write                               1
#define __NR_open                                2
#define __NR_close                               3
#define __NR_stat                                4
#define __NR_fstat                               5
#define __NR_lstat                               6
#define __NR_poll                                7
#define __NR_lseek                               8
#define __NR_mmap                                9
#define __NR_mprotect                           10
#define __NR_munmap                             11
#define __NR_brk                                12
#define __NR_rt_sigaction                       13
#define __NR_rt_sigprocmask                     14
#define __NR_rt_sigreturn                       15
#define __NR_ioctl                              16
#define __NR_pread64                            17
#define __NR_pwrite64                           18
#define __NR_readv                              19
#define __NR_writev                             20
#define __NR_access                             21
#define __NR_pipe                               22
#define __NR_select                             23
#define __NR_sched_yield                        24
#define __NR_mremap                             25
#define __NR_msync                              26
#define __NR_mincore                            27
#define __NR_madvise                            28
#define __NR_shmget                             29
#define __NR_shmat                              30
#define __NR_shmctl                             31
#define __NR_dup                                32
#define __NR_dup2                               33
#define __NR_pause                              34
#define __NR_nanosleep                          35
#define __NR_getitimer                          36
#define __NR_alarm                              37
#define __NR_setitimer                          38
#define __NR_getpid                             39
#define __NR_sendfile                           40
#define __NR_socket                             41
#define __NR_connect                            42
#define __NR_accept                             43
#define __NR_sendto                             44
#define __NR_recvfrom                           45
#define __NR_sendmsg                            46
#define __NR_recvmsg                            47
#define __NR_shutdown                           48
#define __NR_bind                               49
#define __NR_listen                             50
#define __NR_getsockname                        51
#define __NR_getpeername                        52
#define __NR_socketpair                         53
#define __NR_setsockopt                         54
#define __NR_getsockopt                         55
#define __NR_clone                              56
#define __NR_fork                               57
#define __NR_vfork                              58
#define __NR_execve                             59
#define __NR_exit                               60
#define __NR_wait4                              61
#define __NR_kill                               62
#define __NR_uname                              63
#define __NR_semget                             64
#define __NR_semop                              65
#define __NR_semctl                             66
#define __NR_shmdt                              67
#define __NR_msgget                             68
#define __NR_msgsnd                             69
#define __NR_msgrcv                             70
#define __NR_msgctl                             71
#define __NR_fcntl                              72
#define __NR_flock                              73
#define __NR_fsync                              74
#define __NR_fdatasync                          75
#define __NR_truncate                           76
#define __NR_ftruncate                          77
#define __NR_getdents                           78
#define __NR_getcwd                             79
#define __NR_chdir                              80
#define __NR_fchdir                             81
#define __NR_rename                             82
#define __NR_mkdir                              83
#define __NR_rmdir                              84
#define __NR_creat                              85
#define __NR_link                               86
#define __NR_unlink                             87
#define __NR_symlink                            88
#define __NR_readlink                           89
#define __NR_chmod                              90
#define __NR_fchmod                             91
#define __NR_chown                              92
#define __NR_fchown                             93
#define __NR_lchown                             94
#define __NR_umask                              95
#define __NR_gettimeofday                       96
#define __NR_getrlimit                          97
#define __NR_getrusage                          98
#define __NR_sysinfo                            99
#define __NR_times                             100
#define __NR_ptrace                            101
#define __NR_getuid                            102
#define __NR_syslog                            103
#define __NR_getgid                            104
#define __NR_setuid                            105
#define __NR_setgid                            106
#define __NR_geteuid                           107
#define __NR_getegid                           108
#define __NR_setpgid                           109
#define __NR_getppid                           110
#define __NR_getpgrp                           111
#define __NR_setsid                            112
#define __NR_setreuid                          113
#define __NR_setregid                          114
#define __NR_getgroups                         115
#define __NR_setgroups                         116
#define __NR_setresuid                         117
#define __NR_getresuid                         118
#define __NR_setresgid                         119
#define __NR_getresgid                         120
#define __NR_getpgid                           121
#define __NR_setfsuid                          122
#define __NR_setfsgid                          123
#define __NR_getsid                            124
#define __NR_capget                            125
#define __NR_capset                            126
#define __NR_rt_sigpending                     127
#define __NR_rt_sigtimedwait                   128
#define __NR_rt_sigqueueinfo                   129
#define __NR_rt_sigsuspend                     130
#define __NR_sigaltstack                       131
#define __NR_utime                             132
#define __NR_mknod                             133
#define __NR_uselib                            134
#define __NR_personality                       135
#define __NR_ustat                             136
#define __NR_statfs                            137
#define __NR_fstatfs                           138
#define __NR_sysfs                             139
#define __NR_getpriority                       140
#define __NR_setpriority                       141
#define __NR_sched_setparam                    142
#define __NR_sched_getparam                    143
#define __NR_sched_setscheduler                144
#define __NR_sched_getscheduler                145
#define __NR_sched_get_priority_max            146
#define __NR_sched_get_priority_min            147
#define __NR_sched_rr_get_interval             148
#define __NR_mlock                             149
#define __NR_munlock                           150
#define __NR_mlockall                          151
#define __NR_munlockall                        152
#define __NR_vhangup                           153
#define __NR_modify_ldt                        154
#define __NR_pivot_root                        155
#define __NR__sysctl                           156
#define __NR_prctl                             157
#define __NR_arch_prctl                        158
#define __NR_adjtimex                          159
#define __NR_setrlimit                         160
#define __NR_chroot                            161
#define __NR_sync                              162
#define __NR_acct                              163
#define __NR_settimeofday                      164
#define __NR_mount                             165
#define __NR_umount2                           166
#define __NR_swapon                            167
#define __NR_swapoff                           168
#define __NR_reboot                            169
#define __NR_sethostname                       170
#define __NR_setdomainname                     171
#define __NR_iopl                              172
#define __NR_ioperm                            173
#define __NR_create_module                     174
#define __NR_init_module                       175
#define __NR_delete_module                     176
#define __NR_get_kernel_syms                   177
#define __NR_query_module                      178
#define __NR_quotactl                          179
#define __NR_nfsservctl                        180
#define __NR_getpmsg                           181	/* reserved for LiS/STREAMS */
#define __NR_putpmsg                           182	/* reserved for LiS/STREAMS */
#define __NR_afs_syscall                       183	/* reserved for AFS */ 
#define __NR_tuxcall      		184 /* reserved for tux */
#define __NR_security			185
#define __NR_gettid		186
#define __NR_readahead		187
#define __NR_setxattr		188
#define __NR_lsetxattr		189
#define __NR_fsetxattr		190
#define __NR_getxattr		191
#define __NR_lgetxattr		192
#define __NR_fgetxattr		193
#define __NR_listxattr		194
#define __NR_llistxattr		195
#define __NR_flistxattr		196
#define __NR_removexattr	197
#define __NR_lremovexattr	198
#define __NR_fremovexattr	199
#define __NR_tkill	200
#define __NR_time      201
#define __NR_futex     202
#define __NR_sched_setaffinity    203
#define __NR_sched_getaffinity     204
#define __NR_set_thread_area	205
#define __NR_io_setup	206
#define __NR_io_destroy	207
#define __NR_io_getevents	208
#define __NR_io_submit	209
#define __NR_io_cancel	210
#define __NR_get_thread_area	211
#define __NR_lookup_dcookie	212
#define __NR_epoll_create	213
#define __NR_epoll_ctl_old	214
#define __NR_epoll_wait_old	215
#define __NR_remap_file_pages	216
#define __NR_getdents64	217
#define __NR_set_tid_address	218
#define __NR_restart_syscall	219
#define __NR_semtimedop		220
#define __NR_fadvise64		221
#define __NR_timer_create		222
#define __NR_timer_settime		223
#define __NR_timer_gettime		224
#define __NR_timer_getoverrun		225
#define __NR_timer_delete	226
#define __NR_clock_settime	227
#define __NR_clock_gettime	228
#define __NR_clock_getres	229
#define __NR_clock_nanosleep	230
#define __NR_exit_group		231
#define __NR_epoll_wait		232
#define __NR_epoll_ctl		233
#define __NR_tgkill		234
#define __NR_utimes		235
#define __NR_vserver		236
#define __NR_mbind 		237
#define __NR_set_mempolicy 	238
#define __NR_get_mempolicy 	239
#define __NR_mq_open 		240
#define __NR_mq_unlink 		241
#define __NR_mq_timedsend 	242
#define __NR_mq_timedreceive	243
#define __NR_mq_notify 		244
#define __NR_mq_getsetattr 	245
#define __NR_kexec_load 	246
#define __NR_waitid		247
#define __NR_add_key		248
#define __NR_request_key	249
#define __NR_keyctl		250
#define __NR_ioprio_set		251
#define __NR_ioprio_get		252
#define __NR_inotify_init	253
#define __NR_inotify_add_watch	254
#define __NR_inotify_rm_watch	255
#define __NR_syscall_max __NR_inotify_rm_watch

#else

//
// 32-bit x86:
//

#undef __syscall_return
#define __syscall_return(type, res) return (type)(res);

#define declare_syscall0(sysid,type,name) syslinkage type name(void) { long __res; asm volatile ("int $0x80" \
  : "=a" (__res) : "0" (sysid)); __syscall_return(type,__res); }

#define declare_syscall1(sysid,type,name,type1,arg1) syslinkage type name(type1 arg1) { long __res; \
  asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1))); __syscall_return(type,__res); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) syslinkage type name(type1 arg1,type2 arg2) { \
  long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2))); __syscall_return(type,__res); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) syslinkage type name(type1 arg1,type2 arg2,type3 arg3) { \
  long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3))); __syscall_return(type,__res); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) syslinkage type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
  { long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4))); \
  __syscall_return(type,__res); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, type5,arg5) syslinkage type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
  { long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
  __syscall_return(type,__res); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, type5,arg5,type6,arg6) \
  syslinkage type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { \
  long __res = arg6; asm volatile ("push %%ebp ; movl %%eax,%%ebp ; movl %1,%%eax ; int $0x80 ; pop %%ebp" : "+a" (__res) \
	: "i" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); __syscall_return(type,__res); }

#define __NR_restart_syscall      0
#define __NR_exit		  1
#define __NR_fork		  2
#define __NR_read		  3
#define __NR_write		  4
#define __NR_open		  5
#define __NR_close		  6
#define __NR_waitpid		  7
#define __NR_creat		  8
#define __NR_link		  9
#define __NR_unlink		 10
#define __NR_execve		 11
#define __NR_chdir		 12
#define __NR_time		 13
#define __NR_mknod		 14
#define __NR_chmod		 15
#define __NR_lchown		 16
#define __NR_break		 17
#define __NR_oldstat		 18
#define __NR_lseek		 19
#define __NR_getpid		 20
#define __NR_mount		 21
#define __NR_umount		 22
#define __NR_setuid		 23
#define __NR_getuid		 24
#define __NR_stime		 25
#define __NR_ptrace		 26
#define __NR_alarm		 27
#define __NR_oldfstat		 28
#define __NR_pause		 29
#define __NR_utime		 30
#define __NR_stty		 31
#define __NR_gtty		 32
#define __NR_access		 33
#define __NR_nice		 34
#define __NR_ftime		 35
#define __NR_sync		 36
#define __NR_kill		 37
#define __NR_rename		 38
#define __NR_mkdir		 39
#define __NR_rmdir		 40
#define __NR_dup		 41
#define __NR_pipe		 42
#define __NR_times		 43
#define __NR_prof		 44
#define __NR_brk		 45
#define __NR_setgid		 46
#define __NR_getgid		 47
#define __NR_signal		 48
#define __NR_geteuid		 49
#define __NR_getegid		 50
#define __NR_acct		 51
#define __NR_umount2		 52
#define __NR_lock		 53
#define __NR_ioctl		 54
#define __NR_fcntl		 55
#define __NR_mpx		 56
#define __NR_setpgid		 57
#define __NR_ulimit		 58
#define __NR_oldolduname	 59
#define __NR_umask		 60
#define __NR_chroot		 61
#define __NR_ustat		 62
#define __NR_dup2		 63
#define __NR_getppid		 64
#define __NR_getpgrp		 65
#define __NR_setsid		 66
#define __NR_sigaction		 67
#define __NR_sgetmask		 68
#define __NR_ssetmask		 69
#define __NR_setreuid		 70
#define __NR_setregid		 71
#define __NR_sigsuspend		 72
#define __NR_sigpending		 73
#define __NR_sethostname	 74
#define __NR_setrlimit		 75
#define __NR_getrlimit		 76	/* Back compatible 2Gig limited rlimit */
#define __NR_getrusage		 77
#define __NR_gettimeofday	 78
#define __NR_settimeofday	 79
#define __NR_getgroups		 80
#define __NR_setgroups		 81
#define __NR_select		 82
#define __NR_symlink		 83
#define __NR_oldlstat		 84
#define __NR_readlink		 85
#define __NR_uselib		 86
#define __NR_swapon		 87
#define __NR_reboot		 88
#define __NR_readdir		 89
#define __NR_mmap		 90
#define __NR_munmap		 91
#define __NR_truncate		 92
#define __NR_ftruncate		 93
#define __NR_fchmod		 94
#define __NR_fchown		 95
#define __NR_getpriority	 96
#define __NR_setpriority	 97
#define __NR_profil		 98
#define __NR_statfs		 99
#define __NR_fstatfs		100
#define __NR_ioperm		101
#define __NR_socketcall		102
#define __NR_syslog		103
#define __NR_setitimer		104
#define __NR_getitimer		105
#define __NR_stat		106
#define __NR_lstat		107
#define __NR_fstat		108
#define __NR_olduname		109
#define __NR_iopl		110
#define __NR_vhangup		111
#define __NR_idle		112
#define __NR_vm86old		113
#define __NR_wait4		114
#define __NR_swapoff		115
#define __NR_sysinfo		116
#define __NR_ipc		117
#define __NR_fsync		118
#define __NR_sigreturn		119
#define __NR_clone		120
#define __NR_setdomainname	121
#define __NR_uname		122
#define __NR_modify_ldt		123
#define __NR_adjtimex		124
#define __NR_mprotect		125
#define __NR_sigprocmask	126
#define __NR_create_module	127
#define __NR_init_module	128
#define __NR_delete_module	129
#define __NR_get_kernel_syms	130
#define __NR_quotactl		131
#define __NR_getpgid		132
#define __NR_fchdir		133
#define __NR_bdflush		134
#define __NR_sysfs		135
#define __NR_personality	136
#define __NR_afs_syscall	137 /* Syscall for Andrew File System */
#define __NR_setfsuid		138
#define __NR_setfsgid		139
#define __NR__llseek		140
#define __NR_getdents		141
#define __NR__newselect		142
#define __NR_flock		143
#define __NR_msync		144
#define __NR_readv		145
#define __NR_writev		146
#define __NR_getsid		147
#define __NR_fdatasync		148
#define __NR__sysctl		149
#define __NR_mlock		150
#define __NR_munlock		151
#define __NR_mlockall		152
#define __NR_munlockall		153
#define __NR_sched_setparam		154
#define __NR_sched_getparam		155
#define __NR_sched_setscheduler		156
#define __NR_sched_getscheduler		157
#define __NR_sched_yield		158
#define __NR_sched_get_priority_max	159
#define __NR_sched_get_priority_min	160
#define __NR_sched_rr_get_interval	161
#define __NR_nanosleep		162
#define __NR_mremap		163
#define __NR_setresuid		164
#define __NR_getresuid		165
#define __NR_vm86		166
#define __NR_query_module	167
#define __NR_poll		168
#define __NR_nfsservctl		169
#define __NR_setresgid		170
#define __NR_getresgid		171
#define __NR_prctl              172
#define __NR_rt_sigreturn	173
#define __NR_rt_sigaction	174
#define __NR_rt_sigprocmask	175
#define __NR_rt_sigpending	176
#define __NR_rt_sigtimedwait	177
#define __NR_rt_sigqueueinfo	178
#define __NR_rt_sigsuspend	179
#define __NR_pread64		180
#define __NR_pwrite64		181
#define __NR_chown		182
#define __NR_getcwd		183
#define __NR_capget		184
#define __NR_capset		185
#define __NR_sigaltstack	186
#define __NR_sendfile		187
#define __NR_getpmsg		188	/* some people actually want streams */
#define __NR_putpmsg		189	/* some people actually want streams */
#define __NR_vfork		190
#define __NR_ugetrlimit		191	/* SuS compliant getrlimit */
#define __NR_mmap2		192
#define __NR_truncate64		193
#define __NR_ftruncate64	194
#define __NR_stat64		195
#define __NR_lstat64		196
#define __NR_fstat64		197
#define __NR_lchown32		198
#define __NR_getuid32		199
#define __NR_getgid32		200
#define __NR_geteuid32		201
#define __NR_getegid32		202
#define __NR_setreuid32		203
#define __NR_setregid32		204
#define __NR_getgroups32	205
#define __NR_setgroups32	206
#define __NR_fchown32		207
#define __NR_setresuid32	208
#define __NR_getresuid32	209
#define __NR_setresgid32	210
#define __NR_getresgid32	211
#define __NR_chown32		212
#define __NR_setuid32		213
#define __NR_setgid32		214
#define __NR_setfsuid32		215
#define __NR_setfsgid32		216
#define __NR_pivot_root		217
#define __NR_mincore		218
#define __NR_madvise		219
#define __NR_madvise1		219	/* delete when C lib stub is removed */
#define __NR_getdents64		220
#define __NR_fcntl64		221
/* 223 is unused */
#define __NR_gettid		224
#define __NR_readahead		225
#define __NR_setxattr		226
#define __NR_lsetxattr		227
#define __NR_fsetxattr		228
#define __NR_getxattr		229
#define __NR_lgetxattr		230
#define __NR_fgetxattr		231
#define __NR_listxattr		232
#define __NR_llistxattr		233
#define __NR_flistxattr		234
#define __NR_removexattr	235
#define __NR_lremovexattr	236
#define __NR_fremovexattr	237
#define __NR_tkill		238
#define __NR_sendfile64		239
#define __NR_futex		240
#define __NR_sched_setaffinity	241
#define __NR_sched_getaffinity	242
#define __NR_set_thread_area	243
#define __NR_get_thread_area	244
#define __NR_io_setup		245
#define __NR_io_destroy		246
#define __NR_io_getevents	247
#define __NR_io_submit		248
#define __NR_io_cancel		249
#define __NR_fadvise64		250
#define __NR_set_zone_reclaim	251
#define __NR_exit_group		252
#define __NR_lookup_dcookie	253
#define __NR_epoll_create	254
#define __NR_epoll_ctl		255
#define __NR_epoll_wait		256
#define __NR_remap_file_pages	257
#define __NR_set_tid_address	258
#define __NR_timer_create	259
#define __NR_timer_settime	(__NR_timer_create+1)
#define __NR_timer_gettime	(__NR_timer_create+2)
#define __NR_timer_getoverrun	(__NR_timer_create+3)
#define __NR_timer_delete	(__NR_timer_create+4)
#define __NR_clock_settime	(__NR_timer_create+5)
#define __NR_clock_gettime	(__NR_timer_create+6)
#define __NR_clock_getres	(__NR_timer_create+7)
#define __NR_clock_nanosleep	(__NR_timer_create+8)
#define __NR_statfs64		268
#define __NR_fstatfs64		269
#define __NR_tgkill		270
#define __NR_utimes		271
#define __NR_fadvise64_64	272
#define __NR_vserver		273
#define __NR_mbind		274
#define __NR_get_mempolicy	275
#define __NR_set_mempolicy	276
#define __NR_mq_open 		277
#define __NR_mq_unlink		(__NR_mq_open+1)
#define __NR_mq_timedsend	(__NR_mq_open+2)
#define __NR_mq_timedreceive	(__NR_mq_open+3)
#define __NR_mq_notify		(__NR_mq_open+4)
#define __NR_mq_getsetattr	(__NR_mq_open+5)
#define __NR_sys_kexec_load	283
#define __NR_waitid		284
/* #define __NR_sys_setaltroot	285 */
#define __NR_add_key		286
#define __NR_request_key	287
#define __NR_keyctl		288
#define __NR_ioprio_set		289
#define __NR_ioprio_get		290
#define __NR_inotify_init	291
#define __NR_inotify_add_watch	292
#define __NR_inotify_rm_watch	293

#define NR_syscalls 294

#endif

#endif
