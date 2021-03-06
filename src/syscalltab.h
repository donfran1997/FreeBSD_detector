#include <sys/syscall.h>

#ifndef  HOOK_SYSCALL_TAB
#define  HOOK_SYSCALL_TAB
//#define MAX_SYSCALLS 551
static char * syscalltab[SYS_MAXSYSCALL][2] = {
    {"0",  "nosys"},
    {"1",  "sys_sys_exit"},
    {"2",  "sys_fork"},
    {"3",  "sys_read"},
    {"4",  "sys_write"},
    {"5",  "sys_open"},
    {"6",  "sys_close"},
    {"7",  "sys_wait4"},
    {"8",  "nosys"},
    {"9",  "sys_link"},
    {"10",  "sys_unlink"},
    {"11",  "nosys"},
    {"12",  "sys_chdir"},
    {"13",  "sys_fchdir"},
    {"14",  "sys_mknod"},
    {"15",  "sys_chmod"},
    {"16",  "sys_chown"},
    {"17",  "sys_obreak"},
    {"18",  "freebsd4_getfsstat"},
    {"19",  "nosys"},
    {"20",  "sys_getpid"},
    {"21",  "sys_mount"},
    {"22",  "sys_unmount"},
    {"23",  "sys_setuid"},
    {"24",  "sys_getuid"},
    {"25",  "sys_geteuid"},
    {"26",  "sys_ptrace"},
    {"27",  "sys_recvmsg"},
    {"28",  "sys_sendmsg"},
    {"29",  "sys_recvfrom"},
    {"30",  "sys_accept"},
    {"31",  "sys_getpeername"},
    {"32",  "sys_getsockname"},
    {"33",  "sys_access"},
    {"34",  "sys_chflags"},
    {"35",  "sys_fchflags"},
    {"36",  "sys_sync"},
    {"37",  "sys_kill"},
    {"38",  "nosys"},
    {"39",  "sys_getppid"},
    {"40",  "nosys"},
    {"41",  "sys_dup"},
    {"42",  "freebsd10_pipe"},
    {"43",  "sys_getegid"},
    {"44",  "sys_profil"},
    {"45",  "sys_ktrace"},
    {"46",  "nosys"},
    {"47",  "sys_getgid"},
    {"48",  "nosys"},
    {"49",  "sys_getlogin"},
    {"50",  "sys_setlogin"},
    {"51",  "sys_acct"},
    {"52",  "nosys"},
    {"53",  "sys_sigaltstack"},
    {"54",  "sys_ioctl"},
    {"55",  "sys_reboot"},
    {"56",  "sys_revoke"},
    {"57",  "sys_symlink"},
    {"58",  "sys_readlink"},
    {"59",  "sys_execve"},
    {"60",  "sys_umask"},
    {"61",  "sys_chroot"},
    {"62",  "nosys"},
    {"63",  "nosys"},
    {"64",  "nosys"},
    {"65",  "sys_msync"},
    {"66",  "sys_vfork"},
    {"67",  "nosys"},
    {"68",  "nosys"},
    {"69",  "sys_sbrk"},
    {"70",  "sys_sstk"},
    {"71",  "nosys"},
    {"72",  "sys_ovadvise"},
    {"73",  "sys_munmap"},
    {"74",  "sys_mprotect"},
    {"75",  "sys_madvise"},
    {"76",  "nosys"},
    {"77",  "nosys"},
    {"78",  "sys_mincore"},
    {"79",  "sys_getgroups"},
    {"80",  "sys_setgroups"},
    {"81",  "sys_getpgrp"},
    {"82",  "sys_setpgid"},
    {"83",  "sys_setitimer"},
    {"84",  "nosys"},
    {"85",  "sys_swapon"},
    {"86",  "sys_getitimer"},
    {"87",  "nosys"},
    {"88",  "nosys"},
    {"89",  "sys_getdtablesize"},
    {"90",  "sys_dup2"},
    {"91",  "nosys"},
    {"92",  "sys_fcntl"},
    {"93",  "sys_select"},
    {"94",  "nosys"},
    {"95",  "sys_fsync"},
    {"96",  "sys_setpriority"},
    {"97",  "sys_socket"},
    {"98",  "sys_connect"},
    {"99",  "nosys"},
    {"100",  "sys_getpriority"},
    {"101",  "nosys"},
    {"102",  "nosys"},
    {"103",  "nosys"},
    {"104",  "sys_bind"},
    {"105",  "sys_setsockopt"},
    {"106",  "sys_listen"},
    {"107",  "nosys"},
    {"108",  "nosys"},
    {"109",  "nosys"},
    {"110",  "nosys"},
    {"111",  "nosys"},
    {"112",  "nosys"},
    {"113",  "nosys"},
    {"114",  "nosys"},
    {"115",  "nosys"},
    {"116",  "sys_gettimeofday"},
    {"117",  "sys_getrusage"},
    {"118",  "sys_getsockopt"},
    {"119",  "nosys"},
    {"120",  "sys_readv"},
    {"121",  "sys_writev"},
    {"122",  "sys_settimeofday"},
    {"123",  "sys_fchown"},
    {"124",  "sys_fchmod"},
    {"125",  "nosys"},
    {"126",  "sys_setreuid"},
    {"127",  "sys_setregid"},
    {"128",  "sys_rename"},
    {"129",  "nosys"},
    {"130",  "nosys"},
    {"131",  "sys_flock"},
    {"132",  "sys_mkfifo"},
    {"133",  "sys_sendto"},
    {"134",  "sys_shutdown"},
    {"135",  "sys_socketpair"},
    {"136",  "sys_mkdir"},
    {"137",  "sys_rmdir"},
    {"138",  "sys_utimes"},
    {"139",  "nosys"},
    {"140",  "sys_adjtime"},
    {"141",  "nosys"},
    {"142",  "nosys"},
    {"143",  "nosys"},
    {"144",  "nosys"},
    {"145",  "nosys"},
    {"146",  "nosys"},
    {"147",  "sys_setsid"},
    {"148",  "sys_quotactl"},
    {"149",  "nosys"},
    {"150",  "nosys"},
    {"151",  "nosys"},
    {"152",  "nosys"},
    {"153",  "nosys"},
    {"154",  "sys_nlm_syscall"},
    {"155",  "sys_nfssvc"},
    {"156",  "nosys"},
    {"157",  "freebsd4_statfs"},
    {"158",  "freebsd4_fstatfs"},
    {"159",  "nosys"},
    {"160",  "sys_lgetfh"},
    {"161",  "sys_getfh"},
    {"162",  "freebsd4_getdomainname"},
    {"163",  "freebsd4_setdomainname"},
    {"164",  "freebsd4_uname"},
    {"165",  "sysarch"},
    {"166",  "sys_rtprio"},
    {"167",  "nosys"},
    {"168",  "nosys"},
    {"169",  "sys_semsys"},
    {"170",  "sys_msgsys"},
    {"171",  "sys_shmsys"},
    {"172",  "nosys"},
    {"173",  "freebsd6_pread"},
    {"174",  "freebsd6_pwrite"},
    {"175",  "sys_setfib"},
    {"176",  "sys_ntp_adjtime"},
    {"177",  "nosys"},
    {"178",  "nosys"},
    {"179",  "nosys"},
    {"180",  "nosys"},
    {"181",  "sys_setgid"},
    {"182",  "sys_setegid"},
    {"183",  "sys_seteuid"},
    {"184",  "nosys"},
    {"185",  "nosys"},
    {"186",  "nosys"},
    {"187",  "nosys"},
    {"188",  "sys_stat"},
    {"189",  "sys_fstat"},
    {"190",  "sys_lstat"},
    {"191",  "sys_pathconf"},
    {"192",  "sys_fpathconf"},
    {"193",  "nosys"},
    {"194",  "sys_getrlimit"},
    {"195",  "sys_setrlimit"},
    {"196",  "sys_getdirentries"},
    {"197",  "freebsd6_mmap"},
    {"198",  "nosys"},
    {"199",  "freebsd6_lseek"},
    {"200",  "freebsd6_truncate"},
    {"201",  "freebsd6_ftruncate"},
    {"202",  "sys___sysctl"},
    {"203",  "sys_mlock"},
    {"204",  "sys_munlock"},
    {"205",  "sys_undelete"},
    {"206",  "sys_futimes"},
    {"207",  "sys_getpgid"},
    {"208",  "nosys"},
    {"209",  "sys_poll"},
    {"210",  "lkmnosys"},
    {"211",  "lkmnosys"},
    {"212",  "lkmnosys"},
    {"213",  "lkmnosys"},
    {"214",  "lkmnosys"},
    {"215",  "lkmnosys"},
    {"216",  "lkmnosys"},
    {"217",  "lkmnosys"},
    {"218",  "lkmnosys"},
    {"219",  "lkmnosys"},
    {"220",  "freebsd7___semctl"},
    {"221",  "sys_semget"},
    {"222",  "sys_semop"},
    {"223",  "nosys"},
    {"224",  "freebsd7_msgctl"},
    {"225",  "sys_msgget"},
    {"226",  "sys_msgsnd"},
    {"227",  "sys_msgrcv"},
    {"228",  "sys_shmat"},
    {"229",  "freebsd7_shmctl"},
    {"230",  "sys_shmdt"},
    {"231",  "sys_shmget"},
    {"232",  "sys_clock_gettime"},
    {"233",  "sys_clock_settime"},
    {"234",  "sys_clock_getres"},
    {"235",  "sys_ktimer_create"},
    {"236",  "sys_ktimer_delete"},
    {"237",  "sys_ktimer_settime"},
    {"238",  "sys_ktimer_gettime"},
    {"239",  "sys_ktimer_getoverrun"},
    {"240",  "sys_nanosleep"},
    {"241",  "sys_ffclock_getcounter"},
    {"242",  "sys_ffclock_setestimate"},
    {"243",  "sys_ffclock_getestimate"},
    {"244",  "sys_clock_nanosleep"},
    {"245",  "nosys"},
    {"246",  "nosys"},
    {"247",  "sys_clock_getcpuclockid2"},
    {"248",  "sys_ntp_gettime"},
    {"249",  "nosys"},
    {"250",  "sys_minherit"},
    {"251",  "sys_rfork"},
    {"252",  "sys_openbsd_poll"},
    {"253",  "sys_issetugid"},
    {"254",  "sys_lchown"},
    {"255",  "sys_aio_read"},
    {"256",  "sys_aio_write"},
    {"257",  "sys_lio_listio"},
    {"258",  "nosys"},
    {"259",  "nosys"},
    {"260",  "nosys"},
    {"261",  "nosys"},
    {"262",  "nosys"},
    {"263",  "nosys"},
    {"264",  "nosys"},
    {"265",  "nosys"},
    {"266",  "nosys"},
    {"267",  "nosys"},
    {"268",  "nosys"},
    {"269",  "nosys"},
    {"270",  "nosys"},
    {"271",  "nosys"},
    {"272",  "sys_getdents"},
    {"273",  "nosys"},
    {"274",  "sys_lchmod"},
    {"275",  "sys_lchown"},
    {"276",  "sys_lutimes"},
    {"277",  "sys_msync"},
    {"278",  "sys_nstat"},
    {"279",  "sys_nfstat"},
    {"280",  "sys_nlstat"},
    {"281",  "nosys"},
    {"282",  "nosys"},
    {"283",  "nosys"},
    {"284",  "nosys"},
    {"285",  "nosys"},
    {"286",  "nosys"},
    {"287",  "nosys"},
    {"288",  "nosys"},
    {"289",  "sys_preadv"},
    {"290",  "sys_pwritev"},
    {"291",  "nosys"},
    {"292",  "nosys"},
    {"293",  "nosys"},
    {"294",  "nosys"},
    {"295",  "nosys"},
    {"296",  "nosys"},
    {"297",  "freebsd4_fhstatfs"},
    {"298",  "sys_fhopen"},
    {"299",  "sys_fhstat"},
    {"300",  "sys_modnext"},
    {"301",  "sys_modstat"},
    {"302",  "sys_modfnext"},
    {"303",  "sys_modfind"},
    {"304",  "sys_kldload"},
    {"305",  "sys_kldunload"},
    {"306",  "sys_kldfind"},
    {"307",  "sys_kldnext"},
    {"308",  "sys_kldstat"},
    {"309",  "sys_kldfirstmod"},
    {"310",  "sys_getsid"},
    {"311",  "sys_setresuid"},
    {"312",  "sys_setresgid"},
    {"313",  "nosys"},
    {"314",  "sys_aio_return"},
    {"315",  "sys_aio_suspend"},
    {"316",  "sys_aio_cancel"},
    {"317",  "sys_aio_error"},
    {"318",  "freebsd6_aio_read"},
    {"319",  "freebsd6_aio_write"},
    {"320",  "freebsd6_lio_listio"},
    {"321",  "sys_yield"},
    {"322",  "nosys"},
    {"323",  "nosys"},
    {"324",  "sys_mlockall"},
    {"325",  "sys_munlockall"},
    {"326",  "sys___getcwd"},
    {"327",  "sys_sched_setparam"},
    {"328",  "sys_sched_getparam"},
    {"329",  "sys_sched_setscheduler"},
    {"330",  "sys_sched_getscheduler"},
    {"331",  "sys_sched_yield"},
    {"332",  "sys_sched_get_priority_max"},
    {"333",  "sys_sched_get_priority_min"},
    {"334",  "sys_sched_rr_get_interval"},
    {"335",  "sys_utrace"},
    {"336",  "freebsd4_sendfile"},
    {"337",  "sys_kldsym"},
    {"338",  "sys_jail"},
    {"339",  "lkmressys"},
    {"340",  "sys_sigprocmask"},
    {"341",  "sys_sigsuspend"},
    {"342",  "freebsd4_sigaction"},
    {"343",  "sys_sigpending"},
    {"344",  "freebsd4_sigreturn"},
    {"345",  "sys_sigtimedwait"},
    {"346",  "sys_sigwaitinfo"},
    {"347",  "sys___acl_get_file"},
    {"348",  "sys___acl_set_file"},
    {"349",  "sys___acl_get_fd"},
    {"350",  "sys___acl_set_fd"},
    {"351",  "sys___acl_delete_file"},
    {"352",  "sys___acl_delete_fd"},
    {"353",  "sys___acl_aclcheck_file"},
    {"354",  "sys___acl_aclcheck_fd"},
    {"355",  "sys_extattrctl"},
    {"356",  "sys_extattr_set_file"},
    {"357",  "sys_extattr_get_file"},
    {"358",  "sys_extattr_delete_file"},
    {"359",  "sys_aio_waitcomplete"},
    {"360",  "sys_getresuid"},
    {"361",  "sys_getresgid"},
    {"362",  "sys_kqueue"},
    {"363",  "sys_kevent"},
    {"364",  "nosys"},
    {"365",  "nosys"},
    {"366",  "nosys"},
    {"367",  "nosys"},
    {"368",  "nosys"},
    {"369",  "nosys"},
    {"370",  "nosys"},
    {"371",  "sys_extattr_set_fd"},
    {"372",  "sys_extattr_get_fd"},
    {"373",  "sys_extattr_delete_fd"},
    {"374",  "sys___setugid"},
    {"375",  "nosys"},
    {"376",  "sys_eaccess"},
    {"377",  "lkmressys"},
    {"378",  "sys_nmount"},
    {"379",  "nosys"},
    {"380",  "nosys"},
    {"381",  "nosys"},
    {"382",  "nosys"},
    {"383",  "nosys"},
    {"384",  "sys___mac_get_proc"},
    {"385",  "sys___mac_set_proc"},
    {"386",  "sys___mac_get_fd"},
    {"387",  "sys___mac_get_file"},
    {"388",  "sys___mac_set_fd"},
    {"389",  "sys___mac_set_file"},
    {"390",  "sys_kenv"},
    {"391",  "sys_lchflags"},
    {"392",  "sys_uuidgen"},
    {"393",  "sys_sendfile"},
    {"394",  "sys_mac_syscall"},
    {"395",  "sys_getfsstat"},
    {"396",  "sys_statfs"},
    {"397",  "sys_fstatfs"},
    {"398",  "sys_fhstatfs"},
    {"399",  "nosys"},
    {"400",  "lkmressys"},
    {"401",  "lkmressys"},
    {"402",  "lkmressys"},
    {"403",  "lkmressys"},
    {"404",  "lkmressys"},
    {"405",  "lkmressys"},
    {"406",  "lkmressys"},
    {"407",  "lkmressys"},
    {"408",  "lkmressys"},
    {"409",  "sys___mac_get_pid"},
    {"410",  "sys___mac_get_link"},
    {"411",  "sys___mac_set_link"},
    {"412",  "sys_extattr_set_link"},
    {"413",  "sys_extattr_get_link"},
    {"414",  "sys_extattr_delete_link"},
    {"415",  "sys___mac_execve"},
    {"416",  "sys_sigaction"},
    {"417",  "sys_sigreturn"},
    {"418",  "nosys"},
    {"419",  "nosys"},
    {"420",  "nosys"},
    {"421",  "sys_getcontext"},
    {"422",  "sys_setcontext"},
    {"423",  "sys_swapcontext"},
    {"424",  "sys_swapoff"},
    {"425",  "sys___acl_get_link"},
    {"426",  "sys___acl_set_link"},
    {"427",  "sys___acl_delete_link"},
    {"428",  "sys___acl_aclcheck_link"},
    {"429",  "sys_sigwait"},
    {"430",  "sys_thr_create"},
    {"431",  "sys_thr_exit"},
    {"432",  "sys_thr_self"},
    {"433",  "sys_thr_kill"},
    {"434",  "nosys"},
    {"435",  "nosys"},
    {"436",  "sys_jail_attach"},
    {"437",  "sys_extattr_list_fd"},
    {"438",  "sys_extattr_list_file"},
    {"439",  "sys_extattr_list_link"},
    {"440",  "nosys"},
    {"441",  "lkmressys"},
    {"442",  "sys_thr_suspend"},
    {"443",  "sys_thr_wake"},
    {"444",  "sys_kldunloadf"},
    {"445",  "sys_audit"},
    {"446",  "sys_auditon"},
    {"447",  "sys_getauid"},
    {"448",  "sys_setauid"},
    {"449",  "sys_getaudit"},
    {"450",  "sys_setaudit"},
    {"451",  "sys_getaudit_addr"},
    {"452",  "sys_setaudit_addr"},
    {"453",  "sys_auditctl"},
    {"454",  "sys__umtx_op"},
    {"455",  "sys_thr_new"},
    {"456",  "sys_sigqueue"},
    {"457",  "lkmressys"},
    {"458",  "lkmressys"},
    {"459",  "lkmressys"},
    {"460",  "lkmressys"},
    {"461",  "lkmressys"},
    {"462",  "lkmressys"},
    {"463",  "sys_abort2"},
    {"464",  "sys_thr_set_name"},
    {"465",  "sys_aio_fsync"},
    {"466",  "sys_rtprio_thread"},
    {"467",  "nosys"},
    {"468",  "nosys"},
    {"469",  "nosys"},
    {"470",  "nosys"},
    {"471",  "sys_sctp_peeloff"},
    {"472",  "sys_sctp_generic_sendmsg"},
    {"473",  "sys_sctp_generic_sendmsg_iov"},
    {"474",  "sys_sctp_generic_recvmsg"},
    {"475",  "sys_pread"},
    {"476",  "sys_pwrite"},
    {"477",  "sys_mmap"},
    {"478",  "sys_lseek"},
    {"479",  "sys_truncate"},
    {"480",  "sys_ftruncate"},
    {"481",  "sys_thr_kill2"},
    {"482",  "sys_shm_open"},
    {"483",  "sys_shm_unlink"},
    {"484",  "sys_cpuset"},
    {"485",  "sys_cpuset_setid"},
    {"486",  "sys_cpuset_getid"},
    {"487",  "sys_cpuset_getaffinity"},
    {"488",  "sys_cpuset_setaffinity"},
    {"489",  "sys_faccessat"},
    {"490",  "sys_fchmodat"},
    {"491",  "sys_fchownat"},
    {"492",  "sys_fexecve"},
    {"493",  "sys_fstatat"},
    {"494",  "sys_futimesat"},
    {"495",  "sys_linkat"},
    {"496",  "sys_mkdirat"},
    {"497",  "sys_mkfifoat"},
    {"498",  "sys_mknodat"},
    {"499",  "sys_openat"},
    {"500",  "sys_readlinkat"},
    {"501",  "sys_renameat"},
    {"502",  "sys_symlinkat"},
    {"503",  "sys_unlinkat"},
    {"504",  "sys_posix_openpt"},
    {"505",  "lkmressys"},
    {"506",  "sys_jail_get"},
    {"507",  "sys_jail_set"},
    {"508",  "sys_jail_remove"},
    {"509",  "sys_closefrom"},
    {"510",  "sys___semctl"},
    {"511",  "sys_msgctl"},
    {"512",  "sys_shmctl"},
    {"513",  "sys_lpathconf"},
    {"514",  "nosys"},
    {"515",  "sys___cap_rights_get"},
    {"516",  "sys_cap_enter"},
    {"517",  "sys_cap_getmode"},
    {"518",  "sys_pdfork"},
    {"519",  "sys_pdkill"},
    {"520",  "sys_pdgetpid"},
    {"521",  "nosys"},
    {"522",  "sys_pselect"},
    {"523",  "sys_getloginclass"},
    {"524",  "sys_setloginclass"},
    {"525",  "sys_rctl_get_racct"},
    {"526",  "sys_rctl_get_rules"},
    {"527",  "sys_rctl_get_limits"},
    {"528",  "sys_rctl_add_rule"},
    {"529",  "sys_rctl_remove_rule"},
    {"530",  "sys_posix_fallocate"},
    {"531",  "sys_posix_fadvise"},
    {"532",  "sys_wait6"},
    {"533",  "sys_cap_rights_limit"},
    {"534",  "sys_cap_ioctls_limit"},
    {"535",  "sys_cap_ioctls_get"},
    {"536",  "sys_cap_fcntls_limit"},
    {"537",  "sys_cap_fcntls_get"},
    {"538",  "sys_bindat"},
    {"539",  "sys_connectat"},
    {"540",  "sys_chflagsat"},
    {"541",  "sys_accept4"},
    {"542",  "sys_pipe2"},
    {"543",  "sys_aio_mlock"},
    {"544",  "sys_procctl"},
    {"545",  "sys_ppoll"},
    {"546",  "sys_futimens"},
    {"547",  "sys_utimensat"},
    {"548",  "sys_numa_getaffinity"},
    {"549",  "sys_numa_setaffinity"},
    {"550",  "sys_fdatasync"}
};


#endif
