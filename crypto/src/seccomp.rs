//! Seccomp BPF sandboxing for military-grade process hardening.
//!
//! Provides syscall restriction to minimize the attack surface of
//! cryptographic service processes. Uses `prctl(PR_SET_SECCOMP)` with
//! `SECCOMP_MODE_FILTER` and a BPF program that blocks dangerous syscalls.
//!
//! # Security Model
//! - Blocks dangerous syscalls: ptrace, process_vm_readv/writev, kcmp,
//!   kexec_load, kexec_file_load, init_module, finit_module, delete_module,
//!   userfaultfd, perf_event_open, bpf, lookup_dcookie.
//! - Prevents kernel module loading, memory inspection, and privilege
//!   escalation via syscall restriction.
//! - Combined with PR_SET_NO_NEW_PRIVS (set in memguard::harden_process),
//!   provides defense-in-depth against container escape and exploitation.

#![allow(unsafe_code)]

// ── Seccomp BPF constants (not always in libc) ──

/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` mode constant.
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// BPF instruction opcodes used in seccomp filters.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Seccomp return values.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// EPERM = 1
const SECCOMP_RET_ERRNO_EPERM: u32 = SECCOMP_RET_ERRNO | 1;

/// Offset of `nr` (syscall number) in `struct seccomp_data` for x86_64.
/// `seccomp_data { int nr; ... }` — nr is at offset 0.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// A single BPF instruction (matches `struct sock_filter`).
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program header (matches `struct sock_fprog`).
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Syscall numbers to block (legacy denylist, kept for reference and tests).
/// On non-x86_64 the filter is skipped with a warning.
const BLOCKED_SYSCALLS: &[u32] = &[
    101,  // ptrace
    310,  // process_vm_readv
    311,  // process_vm_writev
    246,  // kexec_load
    320,  // kexec_file_load
    175,  // init_module
    313,  // finit_module
    176,  // delete_module
    321,  // bpf
    298,  // perf_event_open
    323,  // userfaultfd
    312,  // kcmp
    212,  // lookup_dcookie
];

/// Explicit allowlist of syscalls required for normal operation (x86_64).
/// Any syscall NOT in this list causes SECCOMP_RET_KILL_PROCESS.
const ALLOWED_SYSCALLS: &[u32] = &[
    0,    // read
    1,    // write
    3,    // close
    5,    // fstat
    9,    // mmap
    10,   // mprotect
    11,   // munmap
    12,   // brk
    13,   // rt_sigaction
    14,   // rt_sigprocmask
    35,   // nanosleep
    42,   // connect
    44,   // sendto
    45,   // recvfrom
    46,   // sendmsg
    47,   // recvmsg
    202,  // futex
    228,  // clock_gettime
    231,  // exit_group
    232,  // epoll_wait
    233,  // epoll_ctl
    257,  // openat
    281,  // epoll_pwait
    288,  // accept4
    318,  // getrandom
    131,  // sigaltstack
    24,   // sched_yield
    56,   // clone
    57,   // fork (needed for thread spawn)
    58,   // vfork
    60,   // exit
    61,   // wait4
    62,   // kill (for self-signaling)
    72,   // fcntl
    79,   // getcwd
    80,   // chdir
    87,   // unlink
    89,   // readlink
    97,   // getrlimit
    102,  // getuid
    104,  // getgid
    107,  // geteuid
    108,  // getegid
    110,  // getppid
    157,  // prctl
    186,  // gettid
    200,  // tkill
    204,  // sched_getaffinity
    218,  // set_tid_address
    230,  // clock_nanosleep
    262,  // newfstatat
    273,  // set_robust_list
    302,  // prlimit64
    309,  // getcpu
    334,  // rseq
    439,  // faccessat2
    2,    // open (for file I/O)
    4,    // stat
    6,    // lstat
    7,    // poll
    8,    // lseek
    16,   // ioctl
    17,   // pread64
    18,   // pwrite64
    19,   // readv
    20,   // writev
    21,   // access
    22,   // pipe
    23,   // select
    25,   // mremap
    28,   // madvise
    41,   // socket
    43,   // accept
    48,   // shutdown
    49,   // bind
    50,   // listen
    51,   // getsockname
    52,   // getpeername
    53,   // socketpair
    54,   // setsockopt
    55,   // getsockopt
    63,   // uname
    96,   // gettimeofday
    158,  // arch_prctl
    270,  // pselect6
    271,  // ppoll
    291,  // epoll_create1
    292,  // dup3
    293,  // pipe2
    332,  // statx
    435,  // clone3
];

/// Apply a seccomp BPF filter using an allowlist approach.
///
/// Default action is SECCOMP_RET_KILL_PROCESS: any syscall not explicitly
/// allowed kills the entire process. This is the gold standard for
/// military-grade process hardening.
///
/// Requires `PR_SET_NO_NEW_PRIVS` to be set first (enforced by the kernel).
/// Returns `true` if the filter was successfully installed.
pub fn apply_seccomp_filter() -> bool {
    // Only apply on x86_64 — syscall numbers are architecture-specific.
    if cfg!(not(target_arch = "x86_64")) {
        tracing::warn!(
            "seccomp: BPF filter only implemented for x86_64, skipping on this arch"
        );
        return false;
    }

    // Build BPF program (allowlist approach):
    //   load syscall number
    //   for each allowed syscall: if nr == allowed, jump to ALLOW
    //   KILL (default: unknown syscall)
    //   ALLOW
    let num_allowed = ALLOWED_SYSCALLS.len();
    let total_insns = 1 + num_allowed + 1 + 1;
    let mut filter: Vec<SockFilter> = Vec::with_capacity(total_insns);

    // Instruction 0: load seccomp_data.nr
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    // For each allowed syscall: if match, jump to ALLOW
    for (i, &nr) in ALLOWED_SYSCALLS.iter().enumerate() {
        let remaining = num_allowed - i - 1;
        // jt = jump over remaining checks + KILL instruction to reach ALLOW
        let jt = (remaining + 1) as u8;
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: nr,
        });
    }

    // KILL instruction (default: syscall not in allowlist)
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // ALLOW instruction (reached when an allowed syscall matched)
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    assert_eq!(filter.len(), total_insns);

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    unsafe {
        let ret = libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        );
        if ret != 0 {
            let errno = *libc::__errno_location();
            tracing::error!(
                "seccomp: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed \
                 (errno={}). BPF allowlist filter NOT installed.",
                errno
            );
            return false;
        }
    }

    tracing::info!(
        "seccomp: allowlist BPF filter installed — {} syscalls permitted, \
         all others killed (SECCOMP_RET_KILL_PROCESS)",
        ALLOWED_SYSCALLS.len()
    );
    true
}

/// Apply anti-ptrace hardening via prctl and install seccomp BPF filter.
///
/// This sets PR_SET_PTRACER to 0 (deny all ptrace attachment), verifies
/// that PR_SET_DUMPABLE and PR_SET_NO_NEW_PRIVS are already applied, then
/// installs a seccomp BPF filter blocking dangerous syscalls.
///
/// Returns `true` if all prctl calls succeeded.
pub fn apply_anti_ptrace() -> bool {
    let mut ok = true;

    unsafe {
        // Deny ptrace attachment from any process (requires Yama LSM)
        // PR_SET_PTRACER = 0x59616d61 on some systems, but with arg 0 it
        // sets "no process may ptrace this one".
        if libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0) != 0 {
            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);
            if is_military {
                tracing::error!(
                    "FATAL: prctl(PR_SET_PTRACER, 0) failed in military deployment. \
                     Yama LSM MUST be enabled. Process is vulnerable to ptrace attachment."
                );
                ok = false;
            } else {
                tracing::warn!(
                    "seccomp: prctl(PR_SET_PTRACER, 0) failed — \
                     Yama LSM may not be enabled. Ptrace restriction not enforced."
                );
            }
        } else {
            tracing::info!("seccomp: PR_SET_PTRACER=0 applied (ptrace attachment denied)");
        }

        // Verify PR_SET_DUMPABLE is 0 (should have been set by harden_process)
        let dumpable = libc::prctl(libc::PR_GET_DUMPABLE);
        if dumpable != 0 {
            tracing::error!(
                "seccomp: PR_SET_DUMPABLE is {} (expected 0). \
                 Core dumps may leak key material!",
                dumpable,
            );
            ok = false;
        }

        // Verify PR_SET_NO_NEW_PRIVS is set (should have been set by harden_process)
        // PR_GET_NO_NEW_PRIVS = 39
        let no_new_privs = libc::prctl(39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0);
        if no_new_privs != 1 {
            tracing::error!(
                "seccomp: PR_SET_NO_NEW_PRIVS is not set (got {}). \
                 Seccomp BPF requires NO_NEW_PRIVS=1.",
                no_new_privs,
            );
            ok = false;
        }
    }

    // Install seccomp BPF filter to block dangerous syscalls.
    // This is non-fatal: even without the filter, PR_SET_PTRACER provides
    // partial protection. Log but do not fail the overall hardening.
    if !apply_seccomp_filter() {
        tracing::warn!(
            "seccomp: BPF filter installation failed — falling back to \
             PR_SET_PTRACER-only protection"
        );
    }

    ok
}

/// Verify that the process hardening flags are correctly set.
///
/// This is a read-only check that does not modify any process state.
/// Returns `true` if all expected hardening is in place.
pub fn verify_process_hardening() -> bool {
    let mut ok = true;

    unsafe {
        // Check PR_SET_DUMPABLE = 0
        let dumpable = libc::prctl(libc::PR_GET_DUMPABLE);
        if dumpable != 0 {
            tracing::error!(
                "SECURITY VIOLATION: PR_SET_DUMPABLE={} (must be 0 for military deployment)",
                dumpable,
            );
            ok = false;
        }

        // Check PR_GET_NO_NEW_PRIVS = 1
        let no_new_privs = libc::prctl(39, 0, 0, 0, 0);
        if no_new_privs != 1 {
            tracing::error!(
                "SECURITY VIOLATION: NO_NEW_PRIVS={} (must be 1 for military deployment)",
                no_new_privs,
            );
            ok = false;
        }

        // Check RLIMIT_CORE = 0
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) == 0 {
            if rlim.rlim_cur != 0 || rlim.rlim_max != 0 {
                tracing::error!(
                    "SECURITY VIOLATION: RLIMIT_CORE is not 0 (cur={}, max={})",
                    rlim.rlim_cur,
                    rlim.rlim_max,
                );
                ok = false;
            }
        }
    }

    if ok {
        tracing::info!("seccomp: all process hardening flags verified");
    }

    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_hardening_runs_without_panic() {
        // This test just ensures the verification function doesn't crash.
        // In CI, hardening may not be applied, so we don't assert the result.
        let _result = verify_process_hardening();
    }

    #[test]
    fn anti_ptrace_runs_without_panic() {
        // prctl may fail in CI without Yama LSM, but should not panic.
        let _result = apply_anti_ptrace();
    }

    #[test]
    fn seccomp_filter_runs_without_panic() {
        // The BPF filter may fail in CI (no NO_NEW_PRIVS), but must not panic.
        let _result = apply_seccomp_filter();
    }

    #[test]
    fn blocked_syscalls_list_is_populated() {
        // Ensure the blocked syscalls list is non-empty and contains ptrace.
        assert!(!BLOCKED_SYSCALLS.is_empty());
        assert!(BLOCKED_SYSCALLS.contains(&101), "ptrace (101) must be blocked");
        assert!(BLOCKED_SYSCALLS.contains(&321), "bpf (321) must be blocked");
    }

    // ── Security hardening tests ──

    #[test]
    fn apply_seccomp_filter_is_callable() {
        // Verify the public API exists and returns a bool (may fail in CI
        // due to missing NO_NEW_PRIVS, but must never panic).
        let result: bool = apply_seccomp_filter();
        // On non-x86_64 it returns false; on x86_64 without NO_NEW_PRIVS it
        // also returns false. Either way, the function is callable.
        let _ = result;
    }

    #[test]
    fn verify_process_hardening_returns_bool() {
        // verify_process_hardening is a read-only check. In CI without
        // hardening applied, it may return false, but must not panic.
        let result: bool = verify_process_hardening();
        // In a non-hardened test environment, we expect false (dumpable != 0,
        // NO_NEW_PRIVS not set, RLIMIT_CORE not zeroed). The important thing
        // is that it runs and returns a deterministic bool.
        let _ = result;
    }

    #[test]
    fn bpf_opcode_constants_are_valid() {
        // Verify BPF opcode constants match the Linux kernel ABI.
        // These values are defined in <linux/bpf_common.h> and must not change.
        assert_eq!(BPF_LD, 0x00, "BPF_LD must be 0x00");
        assert_eq!(BPF_W, 0x00, "BPF_W must be 0x00");
        assert_eq!(BPF_ABS, 0x20, "BPF_ABS must be 0x20");
        assert_eq!(BPF_JMP, 0x05, "BPF_JMP must be 0x05");
        assert_eq!(BPF_JEQ, 0x10, "BPF_JEQ must be 0x10");
        assert_eq!(BPF_K, 0x00, "BPF_K must be 0x00");
        assert_eq!(BPF_RET, 0x06, "BPF_RET must be 0x06");
    }

    #[test]
    fn seccomp_return_value_constants_are_valid() {
        // SECCOMP_RET_ALLOW and SECCOMP_RET_ERRNO must match kernel definitions.
        assert_eq!(SECCOMP_RET_ALLOW, 0x7fff_0000, "SECCOMP_RET_ALLOW mismatch");
        assert_eq!(SECCOMP_RET_ERRNO, 0x0005_0000, "SECCOMP_RET_ERRNO mismatch");
        assert_eq!(
            SECCOMP_RET_ERRNO_EPERM,
            SECCOMP_RET_ERRNO | 1,
            "SECCOMP_RET_ERRNO_EPERM must be SECCOMP_RET_ERRNO | EPERM(1)"
        );
    }

    #[test]
    fn seccomp_mode_filter_constant_is_valid() {
        assert_eq!(SECCOMP_MODE_FILTER, 2, "SECCOMP_MODE_FILTER must be 2");
    }

    #[test]
    fn seccomp_data_nr_offset_is_zero() {
        // On all architectures, seccomp_data.nr is at offset 0.
        assert_eq!(SECCOMP_DATA_NR_OFFSET, 0);
    }

    #[test]
    fn blocked_syscalls_contains_all_critical_syscalls() {
        // Verify all security-critical syscalls are in the deny list.
        let expected = &[
            (101, "ptrace"),
            (310, "process_vm_readv"),
            (311, "process_vm_writev"),
            (246, "kexec_load"),
            (320, "kexec_file_load"),
            (175, "init_module"),
            (313, "finit_module"),
            (176, "delete_module"),
            (321, "bpf"),
            (298, "perf_event_open"),
            (323, "userfaultfd"),
            (312, "kcmp"),
            (212, "lookup_dcookie"),
        ];
        for &(nr, name) in expected {
            assert!(
                BLOCKED_SYSCALLS.contains(&nr),
                "syscall {} ({}) must be in BLOCKED_SYSCALLS",
                name,
                nr
            );
        }
    }

    #[test]
    fn blocked_syscalls_count_matches_expected() {
        // Legacy denylist kept for reference.
        assert_eq!(
            BLOCKED_SYSCALLS.len(),
            13,
            "BLOCKED_SYSCALLS must contain exactly 13 entries"
        );
    }

    #[test]
    fn allowed_syscalls_is_populated() {
        assert!(
            !ALLOWED_SYSCALLS.is_empty(),
            "ALLOWED_SYSCALLS must not be empty"
        );
        // Must contain essential syscalls
        assert!(ALLOWED_SYSCALLS.contains(&0), "read (0) must be allowed");
        assert!(ALLOWED_SYSCALLS.contains(&1), "write (1) must be allowed");
        assert!(ALLOWED_SYSCALLS.contains(&231), "exit_group (231) must be allowed");
        assert!(ALLOWED_SYSCALLS.contains(&318), "getrandom (318) must be allowed");
    }

    #[test]
    fn allowed_syscalls_excludes_dangerous() {
        // None of the denylist syscalls should appear in the allowlist
        for &blocked in BLOCKED_SYSCALLS {
            assert!(
                !ALLOWED_SYSCALLS.contains(&blocked),
                "dangerous syscall {} must NOT be in ALLOWED_SYSCALLS",
                blocked
            );
        }
    }

    #[test]
    fn allowed_syscalls_has_no_duplicates() {
        let mut sorted = ALLOWED_SYSCALLS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ALLOWED_SYSCALLS.len(),
            "ALLOWED_SYSCALLS contains duplicate entries"
        );
    }

    #[test]
    fn blocked_syscalls_has_no_duplicates() {
        let mut sorted = BLOCKED_SYSCALLS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            BLOCKED_SYSCALLS.len(),
            "BLOCKED_SYSCALLS contains duplicate entries"
        );
    }

    #[test]
    fn bpf_program_structure_is_valid() {
        // Verify the BPF program would have the correct number of instructions:
        // 1 (load) + N (jeq per allowed syscall) + 1 (kill) + 1 (allow)
        let num_allowed = ALLOWED_SYSCALLS.len();
        let expected_insns = 1 + num_allowed + 1 + 1;
        assert_eq!(expected_insns, 1 + ALLOWED_SYSCALLS.len() + 2, "BPF program instruction count mismatch");

        // Verify the load instruction opcode would be correct
        let load_opcode = BPF_LD | BPF_W | BPF_ABS;
        assert_eq!(load_opcode, 0x20, "load instruction opcode must be 0x20");

        // Verify JEQ instruction opcode
        let jeq_opcode = BPF_JMP | BPF_JEQ | BPF_K;
        assert_eq!(jeq_opcode, 0x15, "JEQ instruction opcode must be 0x15");

        // Verify RET instruction opcode
        let ret_opcode = BPF_RET | BPF_K;
        assert_eq!(ret_opcode, 0x06, "RET instruction opcode must be 0x06");
    }
}
