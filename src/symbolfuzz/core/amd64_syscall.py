class Constant(int):
    def __new__(cls, s, i):
        obj = super(Constant, cls).__new__(cls, i)
        obj.s = s
        return obj

    def __str__(self):
        return self.s

    def __repr__(self):
        return 'Constant(%r, %#x)' % (self.s,int(self))

SYS32_restart_syscall = Constant('SYS32_restart_syscall',0)
SYS32_exit = Constant('SYS32_exit',1)
SYS32_fork = Constant('SYS32_fork',2)
SYS32_read = Constant('SYS32_read',3)
SYS32_write = Constant('SYS32_write',4)
SYS32_open = Constant('SYS32_open',5)
SYS32_close = Constant('SYS32_close',6)
SYS32_waitpid = Constant('SYS32_waitpid',7)
SYS32_creat = Constant('SYS32_creat',8)
SYS32_link = Constant('SYS32_link',9)
SYS32_unlink = Constant('SYS32_unlink',10)
SYS32_execve = Constant('SYS32_execve',11)
SYS32_chdir = Constant('SYS32_chdir',12)
SYS32_time = Constant('SYS32_time',13)
SYS32_mknod = Constant('SYS32_mknod',14)
SYS32_chmod = Constant('SYS32_chmod',15)
SYS32_lchown = Constant('SYS32_lchown',16)
SYS32_break = Constant('SYS32_break',17)
SYS32_oldstat = Constant('SYS32_oldstat',18)
SYS32_lseek = Constant('SYS32_lseek',19)
SYS32_getpid = Constant('SYS32_getpid',20)
SYS32_mount = Constant('SYS32_mount',21)
SYS32_umount = Constant('SYS32_umount',22)
SYS32_setuid = Constant('SYS32_setuid',23)
SYS32_getuid = Constant('SYS32_getuid',24)
SYS32_stime = Constant('SYS32_stime',25)
SYS32_ptrace = Constant('SYS32_ptrace',26)
SYS32_alarm = Constant('SYS32_alarm',27)
SYS32_oldfstat = Constant('SYS32_oldfstat',28)
SYS32_pause = Constant('SYS32_pause',29)
SYS32_utime = Constant('SYS32_utime',30)
SYS32_stty = Constant('SYS32_stty',31)
SYS32_gtty = Constant('SYS32_gtty',32)
SYS32_access = Constant('SYS32_access',33)
SYS32_nice = Constant('SYS32_nice',34)
SYS32_ftime = Constant('SYS32_ftime',35)
SYS32_sync = Constant('SYS32_sync',36)
SYS32_kill = Constant('SYS32_kill',37)
SYS32_rename = Constant('SYS32_rename',38)
SYS32_mkdir = Constant('SYS32_mkdir',39)
SYS32_rmdir = Constant('SYS32_rmdir',40)
SYS32_dup = Constant('SYS32_dup',41)
SYS32_pipe = Constant('SYS32_pipe',42)
SYS32_times = Constant('SYS32_times',43)
SYS32_prof = Constant('SYS32_prof',44)
SYS32_brk = Constant('SYS32_brk',45)
SYS32_setgid = Constant('SYS32_setgid',46)
SYS32_getgid = Constant('SYS32_getgid',47)
SYS32_signal = Constant('SYS32_signal',48)
SYS32_geteuid = Constant('SYS32_geteuid',49)
SYS32_getegid = Constant('SYS32_getegid',50)
SYS32_acct = Constant('SYS32_acct',51)
SYS32_umount2 = Constant('SYS32_umount2',52)
SYS32_lock = Constant('SYS32_lock',53)
SYS32_ioctl = Constant('SYS32_ioctl',54)
SYS32_fcntl = Constant('SYS32_fcntl',55)
SYS32_mpx = Constant('SYS32_mpx',56)
SYS32_setpgid = Constant('SYS32_setpgid',57)
SYS32_ulimit = Constant('SYS32_ulimit',58)
SYS32_oldolduname = Constant('SYS32_oldolduname',59)
SYS32_umask = Constant('SYS32_umask',60)
SYS32_chroot = Constant('SYS32_chroot',61)
SYS32_ustat = Constant('SYS32_ustat',62)
SYS32_dup2 = Constant('SYS32_dup2',63)
SYS32_getppid = Constant('SYS32_getppid',64)
SYS32_getpgrp = Constant('SYS32_getpgrp',65)
SYS32_setsid = Constant('SYS32_setsid',66)
SYS32_sigaction = Constant('SYS32_sigaction',67)
SYS32_sgetmask = Constant('SYS32_sgetmask',68)
SYS32_ssetmask = Constant('SYS32_ssetmask',69)
SYS32_setreuid = Constant('SYS32_setreuid',70)
SYS32_setregid = Constant('SYS32_setregid',71)
SYS32_sigsuspend = Constant('SYS32_sigsuspend',72)
SYS32_sigpending = Constant('SYS32_sigpending',73)
SYS32_sethostname = Constant('SYS32_sethostname',74)
SYS32_setrlimit = Constant('SYS32_setrlimit',75)
SYS32_getrlimit = Constant('SYS32_getrlimit',76)
SYS32_getrusage = Constant('SYS32_getrusage',77)
SYS32_gettimeofday = Constant('SYS32_gettimeofday',78)
SYS32_settimeofday = Constant('SYS32_settimeofday',79)
SYS32_getgroups = Constant('SYS32_getgroups',80)
SYS32_setgroups = Constant('SYS32_setgroups',81)
SYS32_select = Constant('SYS32_select',82)
SYS32_symlink = Constant('SYS32_symlink',83)
SYS32_oldlstat = Constant('SYS32_oldlstat',84)
SYS32_readlink = Constant('SYS32_readlink',85)
SYS32_uselib = Constant('SYS32_uselib',86)
SYS32_swapon = Constant('SYS32_swapon',87)
SYS32_reboot = Constant('SYS32_reboot',88)
SYS32_readdir = Constant('SYS32_readdir',89)
SYS32_mmap = Constant('SYS32_mmap',90)
SYS32_munmap = Constant('SYS32_munmap',91)
SYS32_truncate = Constant('SYS32_truncate',92)
SYS32_ftruncate = Constant('SYS32_ftruncate',93)
SYS32_fchmod = Constant('SYS32_fchmod',94)
SYS32_fchown = Constant('SYS32_fchown',95)
SYS32_getpriority = Constant('SYS32_getpriority',96)
SYS32_setpriority = Constant('SYS32_setpriority',97)
SYS32_profil = Constant('SYS32_profil',98)
SYS32_statfs = Constant('SYS32_statfs',99)
SYS32_fstatfs = Constant('SYS32_fstatfs',100)
SYS32_ioperm = Constant('SYS32_ioperm',101)
SYS32_socketcall = Constant('SYS32_socketcall',102)
SYS32_syslog = Constant('SYS32_syslog',103)
SYS32_setitimer = Constant('SYS32_setitimer',104)
SYS32_getitimer = Constant('SYS32_getitimer',105)
SYS32_stat = Constant('SYS32_stat',106)
SYS32_lstat = Constant('SYS32_lstat',107)
SYS32_fstat = Constant('SYS32_fstat',108)
SYS32_olduname = Constant('SYS32_olduname',109)
SYS32_iopl = Constant('SYS32_iopl',110)
SYS32_vhangup = Constant('SYS32_vhangup',111)
SYS32_idle = Constant('SYS32_idle',112)
SYS32_vm86old = Constant('SYS32_vm86old',113)
SYS32_wait4 = Constant('SYS32_wait4',114)
SYS32_swapoff = Constant('SYS32_swapoff',115)
SYS32_sysinfo = Constant('SYS32_sysinfo',116)
SYS32_ipc = Constant('SYS32_ipc',117)
SYS32_fsync = Constant('SYS32_fsync',118)
SYS32_sigreturn = Constant('SYS32_sigreturn',119)
SYS32_clone = Constant('SYS32_clone',120)
SYS32_setdomainname = Constant('SYS32_setdomainname',121)
SYS32_uname = Constant('SYS32_uname',122)
SYS32_modify_ldt = Constant('SYS32_modify_ldt',123)
SYS32_adjtimex = Constant('SYS32_adjtimex',124)
SYS32_mprotect = Constant('SYS32_mprotect',125)
SYS32_sigprocmask = Constant('SYS32_sigprocmask',126)
SYS32_create_module = Constant('SYS32_create_module',127)
SYS32_init_module = Constant('SYS32_init_module',128)
SYS32_delete_module = Constant('SYS32_delete_module',129)
SYS32_get_kernel_syms = Constant('SYS32_get_kernel_syms',130)
SYS32_quotactl = Constant('SYS32_quotactl',131)
SYS32_getpgid = Constant('SYS32_getpgid',132)
SYS32_fchdir = Constant('SYS32_fchdir',133)
SYS32_bdflush = Constant('SYS32_bdflush',134)
SYS32_sysfs = Constant('SYS32_sysfs',135)
SYS32_personality = Constant('SYS32_personality',136)
SYS32_afs_syscall = Constant('SYS32_afs_syscall',137)
SYS32_setfsuid = Constant('SYS32_setfsuid',138)
SYS32_setfsgid = Constant('SYS32_setfsgid',139)
SYS32__llseek = Constant('SYS32__llseek',140)
SYS32_getdents = Constant('SYS32_getdents',141)
SYS32__newselect = Constant('SYS32__newselect',142)
SYS32_flock = Constant('SYS32_flock',143)
SYS32_msync = Constant('SYS32_msync',144)
SYS32_readv = Constant('SYS32_readv',145)
SYS32_writev = Constant('SYS32_writev',146)
SYS32_getsid = Constant('SYS32_getsid',147)
SYS32_fdatasync = Constant('SYS32_fdatasync',148)
SYS32__sysctl = Constant('SYS32__sysctl',149)
SYS32_mlock = Constant('SYS32_mlock',150)
SYS32_munlock = Constant('SYS32_munlock',151)
SYS32_mlockall = Constant('SYS32_mlockall',152)
SYS32_munlockall = Constant('SYS32_munlockall',153)
SYS32_sched_setparam = Constant('SYS32_sched_setparam',154)
SYS32_sched_getparam = Constant('SYS32_sched_getparam',155)
SYS32_sched_setscheduler = Constant('SYS32_sched_setscheduler',156)
SYS32_sched_getscheduler = Constant('SYS32_sched_getscheduler',157)
SYS32_sched_yield = Constant('SYS32_sched_yield',158)
SYS32_sched_get_priority_max = Constant('SYS32_sched_get_priority_max',159)
SYS32_sched_get_priority_min = Constant('SYS32_sched_get_priority_min',160)
SYS32_sched_rr_get_interval = Constant('SYS32_sched_rr_get_interval',161)
SYS32_nanosleep = Constant('SYS32_nanosleep',162)
SYS32_mremap = Constant('SYS32_mremap',163)
SYS32_setresuid = Constant('SYS32_setresuid',164)
SYS32_getresuid = Constant('SYS32_getresuid',165)
SYS32_vm86 = Constant('SYS32_vm86',166)
SYS32_query_module = Constant('SYS32_query_module',167)
SYS32_poll = Constant('SYS32_poll',168)
SYS32_nfsservctl = Constant('SYS32_nfsservctl',169)
SYS32_setresgid = Constant('SYS32_setresgid',170)
SYS32_getresgid = Constant('SYS32_getresgid',171)
SYS32_prctl = Constant('SYS32_prctl',172)
SYS32_rt_sigreturn = Constant('SYS32_rt_sigreturn',173)
SYS32_rt_sigaction = Constant('SYS32_rt_sigaction',174)
SYS32_rt_sigprocmask = Constant('SYS32_rt_sigprocmask',175)
SYS32_rt_sigpending = Constant('SYS32_rt_sigpending',176)
SYS32_rt_sigtimedwait = Constant('SYS32_rt_sigtimedwait',177)
SYS32_rt_sigqueueinfo = Constant('SYS32_rt_sigqueueinfo',178)
SYS32_rt_sigsuspend = Constant('SYS32_rt_sigsuspend',179)
SYS32_pread64 = Constant('SYS32_pread64',180)
SYS32_pwrite64 = Constant('SYS32_pwrite64',181)
SYS32_chown = Constant('SYS32_chown',182)
SYS32_getcwd = Constant('SYS32_getcwd',183)
SYS32_capget = Constant('SYS32_capget',184)
SYS32_capset = Constant('SYS32_capset',185)
SYS32_sigaltstack = Constant('SYS32_sigaltstack',186)
SYS32_sendfile = Constant('SYS32_sendfile',187)
SYS32_getpmsg = Constant('SYS32_getpmsg',188)
SYS32_putpmsg = Constant('SYS32_putpmsg',189)
SYS32_vfork = Constant('SYS32_vfork',190)
SYS32_ugetrlimit = Constant('SYS32_ugetrlimit',191)
SYS32_mmap2 = Constant('SYS32_mmap2',192)
SYS32_truncate64 = Constant('SYS32_truncate64',193)
SYS32_ftruncate64 = Constant('SYS32_ftruncate64',194)
SYS32_stat64 = Constant('SYS32_stat64',195)
SYS32_lstat64 = Constant('SYS32_lstat64',196)
SYS32_fstat64 = Constant('SYS32_fstat64',197)
SYS32_lchown32 = Constant('SYS32_lchown32',198)
SYS32_getuid32 = Constant('SYS32_getuid32',199)
SYS32_getgid32 = Constant('SYS32_getgid32',200)
SYS32_geteuid32 = Constant('SYS32_geteuid32',201)
SYS32_getegid32 = Constant('SYS32_getegid32',202)
SYS32_setreuid32 = Constant('SYS32_setreuid32',203)
SYS32_setregid32 = Constant('SYS32_setregid32',204)
SYS32_getgroups32 = Constant('SYS32_getgroups32',205)
SYS32_setgroups32 = Constant('SYS32_setgroups32',206)
SYS32_fchown32 = Constant('SYS32_fchown32',207)
SYS32_setresuid32 = Constant('SYS32_setresuid32',208)
SYS32_getresuid32 = Constant('SYS32_getresuid32',209)
SYS32_setresgid32 = Constant('SYS32_setresgid32',210)
SYS32_getresgid32 = Constant('SYS32_getresgid32',211)
SYS32_chown32 = Constant('SYS32_chown32',212)
SYS32_setuid32 = Constant('SYS32_setuid32',213)
SYS32_setgid32 = Constant('SYS32_setgid32',214)
SYS32_setfsuid32 = Constant('SYS32_setfsuid32',215)
SYS32_setfsgid32 = Constant('SYS32_setfsgid32',216)
SYS32_pivot_root = Constant('SYS32_pivot_root',217)
SYS32_mincore = Constant('SYS32_mincore',218)
SYS32_madvise = Constant('SYS32_madvise',219)
SYS32_madvise1 = Constant('SYS32_madvise1',219)
SYS32_getdents64 = Constant('SYS32_getdents64',220)
SYS32_fcntl64 = Constant('SYS32_fcntl64',221)
SYS32_gettid = Constant('SYS32_gettid',224)
SYS32_readahead = Constant('SYS32_readahead',225)
SYS32_setxattr = Constant('SYS32_setxattr',226)
SYS32_lsetxattr = Constant('SYS32_lsetxattr',227)
SYS32_fsetxattr = Constant('SYS32_fsetxattr',228)
SYS32_getxattr = Constant('SYS32_getxattr',229)
SYS32_lgetxattr = Constant('SYS32_lgetxattr',230)
SYS32_fgetxattr = Constant('SYS32_fgetxattr',231)
SYS32_listxattr = Constant('SYS32_listxattr',232)
SYS32_llistxattr = Constant('SYS32_llistxattr',233)
SYS32_flistxattr = Constant('SYS32_flistxattr',234)
SYS32_removexattr = Constant('SYS32_removexattr',235)
SYS32_lremovexattr = Constant('SYS32_lremovexattr',236)
SYS32_fremovexattr = Constant('SYS32_fremovexattr',237)
SYS32_tkill = Constant('SYS32_tkill',238)
SYS32_sendfile64 = Constant('SYS32_sendfile64',239)
SYS32_futex = Constant('SYS32_futex',240)
SYS32_sched_setaffinity = Constant('SYS32_sched_setaffinity',241)
SYS32_sched_getaffinity = Constant('SYS32_sched_getaffinity',242)
SYS32_set_thread_area = Constant('SYS32_set_thread_area',243)
SYS32_get_thread_area = Constant('SYS32_get_thread_area',244)
SYS32_io_setup = Constant('SYS32_io_setup',245)
SYS32_io_destroy = Constant('SYS32_io_destroy',246)
SYS32_io_getevents = Constant('SYS32_io_getevents',247)
SYS32_io_submit = Constant('SYS32_io_submit',248)
SYS32_io_cancel = Constant('SYS32_io_cancel',249)
SYS32_fadvise64 = Constant('SYS32_fadvise64',250)
SYS32_exit_group = Constant('SYS32_exit_group',252)
SYS32_lookup_dcookie = Constant('SYS32_lookup_dcookie',253)
SYS32_epoll_create = Constant('SYS32_epoll_create',254)
SYS32_epoll_ctl = Constant('SYS32_epoll_ctl',255)
SYS32_epoll_wait = Constant('SYS32_epoll_wait',256)
SYS32_remap_file_pages = Constant('SYS32_remap_file_pages',257)
SYS32_set_tid_address = Constant('SYS32_set_tid_address',258)
SYS32_timer_create = Constant('SYS32_timer_create',259)
SYS32_timer_settime = Constant('SYS32_timer_settime',(222+1))
SYS32_timer_gettime = Constant('SYS32_timer_gettime',(222+2))
SYS32_timer_getoverrun = Constant('SYS32_timer_getoverrun',(222+3))
SYS32_timer_delete = Constant('SYS32_timer_delete',(222+4))
SYS32_clock_settime = Constant('SYS32_clock_settime',(222+5))
SYS32_clock_gettime = Constant('SYS32_clock_gettime',(222+6))
SYS32_clock_getres = Constant('SYS32_clock_getres',(222+7))
SYS32_clock_nanosleep = Constant('SYS32_clock_nanosleep',(222+8))
SYS32_statfs64 = Constant('SYS32_statfs64',268)
SYS32_fstatfs64 = Constant('SYS32_fstatfs64',269)
SYS32_tgkill = Constant('SYS32_tgkill',270)
SYS32_utimes = Constant('SYS32_utimes',271)
SYS32_fadvise64_64 = Constant('SYS32_fadvise64_64',272)
SYS32_vserver = Constant('SYS32_vserver',273)
SYS32_mbind = Constant('SYS32_mbind',274)
SYS32_get_mempolicy = Constant('SYS32_get_mempolicy',275)
SYS32_set_mempolicy = Constant('SYS32_set_mempolicy',276)
SYS32_mq_open = Constant('SYS32_mq_open',277)
SYS32_mq_unlink = Constant('SYS32_mq_unlink',(240+1))
SYS32_mq_timedsend = Constant('SYS32_mq_timedsend',(240+2))
SYS32_mq_timedreceive = Constant('SYS32_mq_timedreceive',(240+3))
SYS32_mq_notify = Constant('SYS32_mq_notify',(240+4))
SYS32_mq_getsetattr = Constant('SYS32_mq_getsetattr',(240+5))
SYS32_kexec_load = Constant('SYS32_kexec_load',283)
SYS32_waitid = Constant('SYS32_waitid',284)
SYS32_add_key = Constant('SYS32_add_key',286)
SYS32_request_key = Constant('SYS32_request_key',287)
SYS32_keyctl = Constant('SYS32_keyctl',288)
SYS32_ioprio_set = Constant('SYS32_ioprio_set',289)
SYS32_ioprio_get = Constant('SYS32_ioprio_get',290)
SYS32_inotify_init = Constant('SYS32_inotify_init',291)
SYS32_inotify_add_watch = Constant('SYS32_inotify_add_watch',292)
SYS32_inotify_rm_watch = Constant('SYS32_inotify_rm_watch',293)
SYS32_migrate_pages = Constant('SYS32_migrate_pages',294)
SYS32_openat = Constant('SYS32_openat',295)
SYS32_mkdirat = Constant('SYS32_mkdirat',296)
SYS32_mknodat = Constant('SYS32_mknodat',297)
SYS32_fchownat = Constant('SYS32_fchownat',298)
SYS32_futimesat = Constant('SYS32_futimesat',299)
SYS32_fstatat64 = Constant('SYS32_fstatat64',300)
SYS32_unlinkat = Constant('SYS32_unlinkat',301)
SYS32_renameat = Constant('SYS32_renameat',302)
SYS32_linkat = Constant('SYS32_linkat',303)
SYS32_symlinkat = Constant('SYS32_symlinkat',304)
SYS32_readlinkat = Constant('SYS32_readlinkat',305)
SYS32_fchmodat = Constant('SYS32_fchmodat',306)
SYS32_faccessat = Constant('SYS32_faccessat',307)
SYS32_pselect6 = Constant('SYS32_pselect6',308)
SYS32_ppoll = Constant('SYS32_ppoll',309)
SYS32_unshare = Constant('SYS32_unshare',310)
SYS32_set_robust_list = Constant('SYS32_set_robust_list',311)
SYS32_get_robust_list = Constant('SYS32_get_robust_list',312)
SYS32_splice = Constant('SYS32_splice',313)
SYS32_sync_file_range = Constant('SYS32_sync_file_range',314)
SYS32_tee = Constant('SYS32_tee',315)
SYS32_vmsplice = Constant('SYS32_vmsplice',316)
SYS32_move_pages = Constant('SYS32_move_pages',317)
SYS32_getcpu = Constant('SYS32_getcpu',318)
SYS32_epoll_pwait = Constant('SYS32_epoll_pwait',319)
SYS32_utimensat = Constant('SYS32_utimensat',320)
SYS32_signalfd = Constant('SYS32_signalfd',321)
SYS32_timerfd_create = Constant('SYS32_timerfd_create',322)
SYS32_eventfd = Constant('SYS32_eventfd',323)
SYS32_fallocate = Constant('SYS32_fallocate',324)
SYS32_timerfd_settime = Constant('SYS32_timerfd_settime',325)
SYS32_timerfd_gettime = Constant('SYS32_timerfd_gettime',326)
SYS32_signalfd4 = Constant('SYS32_signalfd4',327)
SYS32_eventfd2 = Constant('SYS32_eventfd2',328)
SYS32_epoll_create1 = Constant('SYS32_epoll_create1',329)
SYS32_dup3 = Constant('SYS32_dup3',330)
SYS32_pipe2 = Constant('SYS32_pipe2',331)
SYS32_inotify_init1 = Constant('SYS32_inotify_init1',332)
SYS32_preadv = Constant('SYS32_preadv',333)
SYS32_pwritev = Constant('SYS32_pwritev',334)
SYS32_rt_tgsigqueueinfo = Constant('SYS32_rt_tgsigqueueinfo',335)
SYS32_perf_event_open = Constant('SYS32_perf_event_open',336)
SYS32_recvmmsg = Constant('SYS32_recvmmsg',337)
SYS32_fanotify_init = Constant('SYS32_fanotify_init',338)
SYS32_fanotify_mark = Constant('SYS32_fanotify_mark',339)
SYS32_prlimit64 = Constant('SYS32_prlimit64',340)
SYS32_name_to_handle_at = Constant('SYS32_name_to_handle_at',341)
SYS32_open_by_handle_at = Constant('SYS32_open_by_handle_at',342)
SYS32_clock_adjtime = Constant('SYS32_clock_adjtime',343)
SYS32_syncfs = Constant('SYS32_syncfs',344)
SYS32_sendmmsg = Constant('SYS32_sendmmsg',345)
SYS32_setns = Constant('SYS32_setns',346)
SYS32_process_vm_readv = Constant('SYS32_process_vm_readv',347)
SYS32_process_vm_writev = Constant('SYS32_process_vm_writev',348)
SYS_accept = Constant('SYS_accept',43)
SYS_accept4 = Constant('SYS_accept4',288)
SYS_access = Constant('SYS_access',21)
SYS_acct = Constant('SYS_acct',163)
SYS_add_key = Constant('SYS_add_key',248)
SYS_adjtimex = Constant('SYS_adjtimex',159)
SYS_afs_syscall = Constant('SYS_afs_syscall',183)
SYS_alarm = Constant('SYS_alarm',37)
SYS_arch_prctl = Constant('SYS_arch_prctl',158)
SYS_bind = Constant('SYS_bind',49)
SYS_brk = Constant('SYS_brk',12)
SYS_capget = Constant('SYS_capget',125)
SYS_capset = Constant('SYS_capset',126)
SYS_chdir = Constant('SYS_chdir',80)
SYS_chmod = Constant('SYS_chmod',90)
SYS_chown = Constant('SYS_chown',92)
SYS_chroot = Constant('SYS_chroot',161)
SYS_clock_getres = Constant('SYS_clock_getres',229)
SYS_clock_gettime = Constant('SYS_clock_gettime',228)
SYS_clock_nanosleep = Constant('SYS_clock_nanosleep',230)
SYS_clock_settime = Constant('SYS_clock_settime',227)
SYS_clone = Constant('SYS_clone',56)
SYS_close = Constant('SYS_close',3)
SYS_connect = Constant('SYS_connect',42)
SYS_creat = Constant('SYS_creat',85)
SYS_create_module = Constant('SYS_create_module',174)
SYS_delete_module = Constant('SYS_delete_module',176)
SYS_dup = Constant('SYS_dup',32)
SYS_dup2 = Constant('SYS_dup2',33)
SYS_dup3 = Constant('SYS_dup3',292)
SYS_epoll_create = Constant('SYS_epoll_create',213)
SYS_epoll_create1 = Constant('SYS_epoll_create1',291)
SYS_epoll_ctl = Constant('SYS_epoll_ctl',233)
SYS_epoll_ctl_old = Constant('SYS_epoll_ctl_old',214)
SYS_epoll_pwait = Constant('SYS_epoll_pwait',281)
SYS_epoll_wait = Constant('SYS_epoll_wait',232)
SYS_epoll_wait_old = Constant('SYS_epoll_wait_old',215)
SYS_eventfd = Constant('SYS_eventfd',284)
SYS_eventfd2 = Constant('SYS_eventfd2',290)
SYS_execve = Constant('SYS_execve',59)
SYS_exit = Constant('SYS_exit',60)
SYS_exit_group = Constant('SYS_exit_group',231)
SYS_faccessat = Constant('SYS_faccessat',269)
SYS_fadvise64 = Constant('SYS_fadvise64',221)
SYS_fallocate = Constant('SYS_fallocate',285)
SYS_fanotify_init = Constant('SYS_fanotify_init',300)
SYS_fanotify_mark = Constant('SYS_fanotify_mark',301)
SYS_fchdir = Constant('SYS_fchdir',81)
SYS_fchmod = Constant('SYS_fchmod',91)
SYS_fchmodat = Constant('SYS_fchmodat',268)
SYS_fchown = Constant('SYS_fchown',93)
SYS_fchownat = Constant('SYS_fchownat',260)
SYS_fcntl = Constant('SYS_fcntl',72)
SYS_fdatasync = Constant('SYS_fdatasync',75)
SYS_fgetxattr = Constant('SYS_fgetxattr',193)
SYS_flistxattr = Constant('SYS_flistxattr',196)
SYS_flock = Constant('SYS_flock',73)
SYS_fork = Constant('SYS_fork',57)
SYS_fremovexattr = Constant('SYS_fremovexattr',199)
SYS_fsetxattr = Constant('SYS_fsetxattr',190)
SYS_fstat = Constant('SYS_fstat',5)
SYS_fstatfs = Constant('SYS_fstatfs',138)
SYS_fsync = Constant('SYS_fsync',74)
SYS_ftruncate = Constant('SYS_ftruncate',77)
SYS_futex = Constant('SYS_futex',202)
SYS_futimesat = Constant('SYS_futimesat',261)
SYS_getcwd = Constant('SYS_getcwd',79)
SYS_getdents = Constant('SYS_getdents',78)
SYS_getdents64 = Constant('SYS_getdents64',217)
SYS_getegid = Constant('SYS_getegid',108)
SYS_geteuid = Constant('SYS_geteuid',107)
SYS_getgid = Constant('SYS_getgid',104)
SYS_getgroups = Constant('SYS_getgroups',115)
SYS_getitimer = Constant('SYS_getitimer',36)
SYS_get_kernel_syms = Constant('SYS_get_kernel_syms',177)
SYS_get_mempolicy = Constant('SYS_get_mempolicy',239)
SYS_getpeername = Constant('SYS_getpeername',52)
SYS_getpgid = Constant('SYS_getpgid',121)
SYS_getpgrp = Constant('SYS_getpgrp',111)
SYS_getpid = Constant('SYS_getpid',39)
SYS_getpmsg = Constant('SYS_getpmsg',181)
SYS_getppid = Constant('SYS_getppid',110)
SYS_getpriority = Constant('SYS_getpriority',140)
SYS_getresgid = Constant('SYS_getresgid',120)
SYS_getresuid = Constant('SYS_getresuid',118)
SYS_getrlimit = Constant('SYS_getrlimit',97)
SYS_get_robust_list = Constant('SYS_get_robust_list',274)
SYS_getrusage = Constant('SYS_getrusage',98)
SYS_getsid = Constant('SYS_getsid',124)
SYS_getsockname = Constant('SYS_getsockname',51)
SYS_getsockopt = Constant('SYS_getsockopt',55)
SYS_get_thread_area = Constant('SYS_get_thread_area',211)
SYS_gettid = Constant('SYS_gettid',186)
SYS_gettimeofday = Constant('SYS_gettimeofday',96)
SYS_getuid = Constant('SYS_getuid',102)
SYS_getxattr = Constant('SYS_getxattr',191)
SYS_init_module = Constant('SYS_init_module',175)
SYS_inotify_add_watch = Constant('SYS_inotify_add_watch',254)
SYS_inotify_init = Constant('SYS_inotify_init',253)
SYS_inotify_init1 = Constant('SYS_inotify_init1',294)
SYS_inotify_rm_watch = Constant('SYS_inotify_rm_watch',255)
SYS_io_cancel = Constant('SYS_io_cancel',210)
SYS_ioctl = Constant('SYS_ioctl',16)
SYS_io_destroy = Constant('SYS_io_destroy',207)
SYS_io_getevents = Constant('SYS_io_getevents',208)
SYS_ioperm = Constant('SYS_ioperm',173)
SYS_iopl = Constant('SYS_iopl',172)
SYS_ioprio_get = Constant('SYS_ioprio_get',252)
SYS_ioprio_set = Constant('SYS_ioprio_set',251)
SYS_io_setup = Constant('SYS_io_setup',206)
SYS_io_submit = Constant('SYS_io_submit',209)
SYS_kexec_load = Constant('SYS_kexec_load',246)
SYS_keyctl = Constant('SYS_keyctl',250)
SYS_kill = Constant('SYS_kill',62)
SYS_lchown = Constant('SYS_lchown',94)
SYS_lgetxattr = Constant('SYS_lgetxattr',192)
SYS_link = Constant('SYS_link',86)
SYS_linkat = Constant('SYS_linkat',265)
SYS_listen = Constant('SYS_listen',50)
SYS_listxattr = Constant('SYS_listxattr',194)
SYS_llistxattr = Constant('SYS_llistxattr',195)
SYS_lookup_dcookie = Constant('SYS_lookup_dcookie',212)
SYS_lremovexattr = Constant('SYS_lremovexattr',198)
SYS_lseek = Constant('SYS_lseek',8)
SYS_lsetxattr = Constant('SYS_lsetxattr',189)
SYS_lstat = Constant('SYS_lstat',6)
SYS_madvise = Constant('SYS_madvise',28)
SYS_mbind = Constant('SYS_mbind',237)
SYS_migrate_pages = Constant('SYS_migrate_pages',256)
SYS_mincore = Constant('SYS_mincore',27)
SYS_mkdir = Constant('SYS_mkdir',83)
SYS_mkdirat = Constant('SYS_mkdirat',258)
SYS_mknod = Constant('SYS_mknod',133)
SYS_mknodat = Constant('SYS_mknodat',259)
SYS_mlock = Constant('SYS_mlock',149)
SYS_mlockall = Constant('SYS_mlockall',151)
SYS_mmap = Constant('SYS_mmap',9)
SYS_modify_ldt = Constant('SYS_modify_ldt',154)
SYS_mount = Constant('SYS_mount',165)
SYS_move_pages = Constant('SYS_move_pages',279)
SYS_mprotect = Constant('SYS_mprotect',10)
SYS_mq_getsetattr = Constant('SYS_mq_getsetattr',245)
SYS_mq_notify = Constant('SYS_mq_notify',244)
SYS_mq_open = Constant('SYS_mq_open',240)
SYS_mq_timedreceive = Constant('SYS_mq_timedreceive',243)
SYS_mq_timedsend = Constant('SYS_mq_timedsend',242)
SYS_mq_unlink = Constant('SYS_mq_unlink',241)
SYS_mremap = Constant('SYS_mremap',25)
SYS_msgctl = Constant('SYS_msgctl',71)
SYS_msgget = Constant('SYS_msgget',68)
SYS_msgrcv = Constant('SYS_msgrcv',70)
SYS_msgsnd = Constant('SYS_msgsnd',69)
SYS_msync = Constant('SYS_msync',26)
SYS_munlock = Constant('SYS_munlock',150)
SYS_munlockall = Constant('SYS_munlockall',152)
SYS_munmap = Constant('SYS_munmap',11)
SYS_nanosleep = Constant('SYS_nanosleep',35)
SYS_newfstatat = Constant('SYS_newfstatat',262)
SYS_nfsservctl = Constant('SYS_nfsservctl',180)
SYS_open = Constant('SYS_open',2)
SYS_openat = Constant('SYS_openat',257)
SYS_pause = Constant('SYS_pause',34)
SYS_perf_event_open = Constant('SYS_perf_event_open',298)
SYS_personality = Constant('SYS_personality',135)
SYS_pipe = Constant('SYS_pipe',22)
SYS_pipe2 = Constant('SYS_pipe2',293)
SYS_pivot_root = Constant('SYS_pivot_root',155)
SYS_poll = Constant('SYS_poll',7)
SYS_ppoll = Constant('SYS_ppoll',271)
SYS_prctl = Constant('SYS_prctl',157)
SYS_pread = Constant('SYS_pread',17)
SYS_preadv = Constant('SYS_preadv',295)
SYS_prlimit64 = Constant('SYS_prlimit64',302)
SYS_pselect6 = Constant('SYS_pselect6',270)
SYS_ptrace = Constant('SYS_ptrace',101)
SYS_putpmsg = Constant('SYS_putpmsg',182)
SYS_pwrite = Constant('SYS_pwrite',18)
SYS_pwritev = Constant('SYS_pwritev',296)
SYS_query_module = Constant('SYS_query_module',178)
SYS_quotactl = Constant('SYS_quotactl',179)
SYS_read = Constant('SYS_read',0)
SYS_readahead = Constant('SYS_readahead',187)
SYS_readlink = Constant('SYS_readlink',89)
SYS_readlinkat = Constant('SYS_readlinkat',267)
SYS_readv = Constant('SYS_readv',19)
SYS_reboot = Constant('SYS_reboot',169)
SYS_recvfrom = Constant('SYS_recvfrom',45)
SYS_recvmmsg = Constant('SYS_recvmmsg',299)
SYS_recvmsg = Constant('SYS_recvmsg',47)
SYS_remap_file_pages = Constant('SYS_remap_file_pages',216)
SYS_removexattr = Constant('SYS_removexattr',197)
SYS_rename = Constant('SYS_rename',82)
SYS_renameat = Constant('SYS_renameat',264)
SYS_request_key = Constant('SYS_request_key',249)
SYS_restart_syscall = Constant('SYS_restart_syscall',219)
SYS_rmdir = Constant('SYS_rmdir',84)
SYS_rt_sigaction = Constant('SYS_rt_sigaction',13)
SYS_rt_sigpending = Constant('SYS_rt_sigpending',127)
SYS_rt_sigprocmask = Constant('SYS_rt_sigprocmask',14)
SYS_rt_sigqueueinfo = Constant('SYS_rt_sigqueueinfo',129)
SYS_rt_sigreturn = Constant('SYS_rt_sigreturn',15)
SYS_rt_sigsuspend = Constant('SYS_rt_sigsuspend',130)
SYS_rt_sigtimedwait = Constant('SYS_rt_sigtimedwait',128)
SYS_rt_tgsigqueueinfo = Constant('SYS_rt_tgsigqueueinfo',297)
SYS_sched_getaffinity = Constant('SYS_sched_getaffinity',204)
SYS_sched_getparam = Constant('SYS_sched_getparam',143)
SYS_sched_get_priority_max = Constant('SYS_sched_get_priority_max',146)
SYS_sched_get_priority_min = Constant('SYS_sched_get_priority_min',147)
SYS_sched_getscheduler = Constant('SYS_sched_getscheduler',145)
SYS_sched_rr_get_interval = Constant('SYS_sched_rr_get_interval',148)
SYS_sched_setaffinity = Constant('SYS_sched_setaffinity',203)
SYS_sched_setparam = Constant('SYS_sched_setparam',142)
SYS_sched_setscheduler = Constant('SYS_sched_setscheduler',144)
SYS_sched_yield = Constant('SYS_sched_yield',24)
SYS_security = Constant('SYS_security',185)
SYS_select = Constant('SYS_select',23)
SYS_semctl = Constant('SYS_semctl',66)
SYS_semget = Constant('SYS_semget',64)
SYS_semop = Constant('SYS_semop',65)
SYS_semtimedop = Constant('SYS_semtimedop',220)
SYS_sendfile = Constant('SYS_sendfile',40)
SYS_sendmsg = Constant('SYS_sendmsg',46)
SYS_sendto = Constant('SYS_sendto',44)
SYS_setdomainname = Constant('SYS_setdomainname',171)
SYS_setfsgid = Constant('SYS_setfsgid',123)
SYS_setfsuid = Constant('SYS_setfsuid',122)
SYS_setgid = Constant('SYS_setgid',106)
SYS_setgroups = Constant('SYS_setgroups',116)
SYS_sethostname = Constant('SYS_sethostname',170)
SYS_setitimer = Constant('SYS_setitimer',38)
SYS_set_mempolicy = Constant('SYS_set_mempolicy',238)
SYS_setpgid = Constant('SYS_setpgid',109)
SYS_setpriority = Constant('SYS_setpriority',141)
SYS_setregid = Constant('SYS_setregid',114)
SYS_setresgid = Constant('SYS_setresgid',119)
SYS_setresuid = Constant('SYS_setresuid',117)
SYS_setreuid = Constant('SYS_setreuid',113)
SYS_setrlimit = Constant('SYS_setrlimit',160)
SYS_set_robust_list = Constant('SYS_set_robust_list',273)
SYS_setsid = Constant('SYS_setsid',112)
SYS_setsockopt = Constant('SYS_setsockopt',54)
SYS_set_thread_area = Constant('SYS_set_thread_area',205)
SYS_set_tid_address = Constant('SYS_set_tid_address',218)
SYS_settimeofday = Constant('SYS_settimeofday',164)
SYS_setuid = Constant('SYS_setuid',105)
SYS_setxattr = Constant('SYS_setxattr',188)
SYS_shmat = Constant('SYS_shmat',30)
SYS_shmctl = Constant('SYS_shmctl',31)
SYS_shmdt = Constant('SYS_shmdt',67)
SYS_shmget = Constant('SYS_shmget',29)
SYS_shutdown = Constant('SYS_shutdown',48)
SYS_sigaltstack = Constant('SYS_sigaltstack',131)
SYS_signalfd = Constant('SYS_signalfd',282)
SYS_signalfd4 = Constant('SYS_signalfd4',289)
SYS_socket = Constant('SYS_socket',41)
SYS_socketpair = Constant('SYS_socketpair',53)
SYS_splice = Constant('SYS_splice',275)
SYS_stat = Constant('SYS_stat',4)
SYS_statfs = Constant('SYS_statfs',137)
SYS_swapoff = Constant('SYS_swapoff',168)
SYS_swapon = Constant('SYS_swapon',167)
SYS_symlink = Constant('SYS_symlink',88)
SYS_symlinkat = Constant('SYS_symlinkat',266)
SYS_sync = Constant('SYS_sync',162)
SYS_sync_file_range = Constant('SYS_sync_file_range',277)
SYS__sysctl = Constant('SYS__sysctl',156)
SYS_sysfs = Constant('SYS_sysfs',139)
SYS_sysinfo = Constant('SYS_sysinfo',99)
SYS_syslog = Constant('SYS_syslog',103)
SYS_tee = Constant('SYS_tee',276)
SYS_tgkill = Constant('SYS_tgkill',234)
SYS_time = Constant('SYS_time',201)
SYS_timer_create = Constant('SYS_timer_create',222)
SYS_timer_delete = Constant('SYS_timer_delete',226)
SYS_timerfd = Constant('SYS_timerfd',283)
SYS_timerfd_gettime = Constant('SYS_timerfd_gettime',287)
SYS_timerfd_settime = Constant('SYS_timerfd_settime',286)
SYS_timer_getoverrun = Constant('SYS_timer_getoverrun',225)
SYS_timer_gettime = Constant('SYS_timer_gettime',224)
SYS_timer_settime = Constant('SYS_timer_settime',223)
SYS_times = Constant('SYS_times',100)
SYS_tkill = Constant('SYS_tkill',200)
SYS_truncate = Constant('SYS_truncate',76)
SYS_tuxcall = Constant('SYS_tuxcall',184)
SYS_umask = Constant('SYS_umask',95)
SYS_umount2 = Constant('SYS_umount2',166)
SYS_uname = Constant('SYS_uname',63)
SYS_unlink = Constant('SYS_unlink',87)
SYS_unlinkat = Constant('SYS_unlinkat',263)
SYS_unshare = Constant('SYS_unshare',272)
SYS_uselib = Constant('SYS_uselib',134)
SYS_ustat = Constant('SYS_ustat',136)
SYS_utime = Constant('SYS_utime',132)
SYS_utimensat = Constant('SYS_utimensat',280)
SYS_utimes = Constant('SYS_utimes',235)
SYS_vfork = Constant('SYS_vfork',58)
SYS_vhangup = Constant('SYS_vhangup',153)
SYS_vmsplice = Constant('SYS_vmsplice',278)
SYS_vserver = Constant('SYS_vserver',236)
SYS_wait4 = Constant('SYS_wait4',61)
SYS_waitid = Constant('SYS_waitid',247)
SYS_write = Constant('SYS_write',1)
SYS_writev = Constant('SYS_writev',20)
