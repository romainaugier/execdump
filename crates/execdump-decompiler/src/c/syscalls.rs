/*
 * The Linux system calls by number, for the C of the code that makes them itself (assembly, static binaries without
 * libc): syscall(SYS_write, 1, "text", 4) as unistd.h writes it, the paths the calls take are strings.
 */

use execdump_core::disasm::Architecture;

/// A system call: its name, the arguments that are paths (after the number)
type Call = (u32, &'static str, &'static [usize]);

const X86_64: &[Call] = &[
    (0, "read", &[]), (1, "write", &[]), (2, "open", &[0]), (3, "close", &[]), (4, "stat", &[0]), (5, "fstat", &[]), (6, "lstat", &[0]),
    (7, "poll", &[]), (8, "lseek", &[]), (9, "mmap", &[]), (10, "mprotect", &[]), (11, "munmap", &[]), (12, "brk", &[]),
    (13, "rt_sigaction", &[]), (14, "rt_sigprocmask", &[]), (15, "rt_sigreturn", &[]), (16, "ioctl", &[]), (17, "pread64", &[]),
    (18, "pwrite64", &[]), (19, "readv", &[]), (20, "writev", &[]), (21, "access", &[0]), (22, "pipe", &[]), (23, "select", &[]),
    (24, "sched_yield", &[]), (25, "mremap", &[]), (28, "madvise", &[]), (32, "dup", &[]), (33, "dup2", &[]), (34, "pause", &[]),
    (35, "nanosleep", &[]), (37, "alarm", &[]), (39, "getpid", &[]), (40, "sendfile", &[]), (41, "socket", &[]), (42, "connect", &[]),
    (43, "accept", &[]), (44, "sendto", &[]), (45, "recvfrom", &[]), (46, "sendmsg", &[]), (47, "recvmsg", &[]), (48, "shutdown", &[]),
    (49, "bind", &[]), (50, "listen", &[]), (51, "getsockname", &[]), (52, "getpeername", &[]), (53, "socketpair", &[]),
    (54, "setsockopt", &[]), (55, "getsockopt", &[]), (56, "clone", &[]), (57, "fork", &[]), (58, "vfork", &[]), (59, "execve", &[0]),
    (60, "exit", &[]), (61, "wait4", &[]), (62, "kill", &[]), (63, "uname", &[]), (72, "fcntl", &[]), (73, "flock", &[]),
    (74, "fsync", &[]), (76, "truncate", &[0]), (77, "ftruncate", &[]), (78, "getdents", &[]), (79, "getcwd", &[]), (80, "chdir", &[0]),
    (81, "fchdir", &[]), (82, "rename", &[0, 1]), (83, "mkdir", &[0]), (84, "rmdir", &[0]), (85, "creat", &[0]), (86, "link", &[0, 1]),
    (87, "unlink", &[0]), (88, "symlink", &[0, 1]), (89, "readlink", &[0]), (90, "chmod", &[0]), (91, "fchmod", &[]), (92, "chown", &[0]),
    (95, "umask", &[]), (96, "gettimeofday", &[]), (97, "getrlimit", &[]), (99, "sysinfo", &[]), (101, "ptrace", &[]), (102, "getuid", &[]),
    (104, "getgid", &[]), (105, "setuid", &[]), (106, "setgid", &[]), (107, "geteuid", &[]), (108, "getegid", &[]), (110, "getppid", &[]),
    (112, "setsid", &[]), (157, "prctl", &[]), (158, "arch_prctl", &[]), (186, "gettid", &[]), (201, "time", &[]), (202, "futex", &[]),
    (217, "getdents64", &[]), (218, "set_tid_address", &[]), (228, "clock_gettime", &[]), (230, "clock_nanosleep", &[]),
    (231, "exit_group", &[]), (257, "openat", &[1]), (258, "mkdirat", &[1]), (262, "newfstatat", &[1]), (263, "unlinkat", &[1]),
    (267, "readlinkat", &[1]), (269, "faccessat", &[1]), (318, "getrandom", &[]), (319, "memfd_create", &[0]), (322, "execveat", &[1]),
    (332, "statx", &[1]),
];

const X86: &[Call] = &[
    (1, "exit", &[]), (2, "fork", &[]), (3, "read", &[]), (4, "write", &[]), (5, "open", &[0]), (6, "close", &[]), (7, "waitpid", &[]),
    (8, "creat", &[0]), (9, "link", &[0, 1]), (10, "unlink", &[0]), (11, "execve", &[0]), (12, "chdir", &[0]), (13, "time", &[]),
    (15, "chmod", &[0]), (19, "lseek", &[]), (20, "getpid", &[]), (23, "setuid", &[]), (24, "getuid", &[]), (26, "ptrace", &[]),
    (27, "alarm", &[]), (29, "pause", &[]), (33, "access", &[0]), (37, "kill", &[]), (38, "rename", &[0, 1]), (39, "mkdir", &[0]),
    (40, "rmdir", &[0]), (41, "dup", &[]), (42, "pipe", &[]), (45, "brk", &[]), (46, "setgid", &[]), (47, "getgid", &[]), (54, "ioctl", &[]),
    (55, "fcntl", &[]), (63, "dup2", &[]), (64, "getppid", &[]), (90, "mmap", &[]), (91, "munmap", &[]), (102, "socketcall", &[]),
    (106, "stat", &[0]), (122, "uname", &[]), (125, "mprotect", &[]), (162, "nanosleep", &[]), (192, "mmap2", &[]), (252, "exit_group", &[]),
    (295, "openat", &[1]), (355, "getrandom", &[]),
];

const AARCH64: &[Call] = &[
    (17, "getcwd", &[]), (23, "dup", &[]), (24, "dup3", &[]), (25, "fcntl", &[]), (29, "ioctl", &[]), (34, "mkdirat", &[1]),
    (35, "unlinkat", &[1]), (36, "symlinkat", &[0, 2]), (37, "linkat", &[1, 3]), (38, "renameat", &[1, 3]), (46, "ftruncate", &[]),
    (48, "faccessat", &[1]), (49, "chdir", &[0]), (52, "fchmod", &[]), (56, "openat", &[1]), (57, "close", &[]), (59, "pipe2", &[]),
    (61, "getdents64", &[]), (62, "lseek", &[]), (63, "read", &[]), (64, "write", &[]), (65, "readv", &[]), (66, "writev", &[]),
    (67, "pread64", &[]), (68, "pwrite64", &[]), (78, "readlinkat", &[1]), (79, "newfstatat", &[1]), (80, "fstat", &[]), (82, "fsync", &[]),
    (93, "exit", &[]), (94, "exit_group", &[]), (96, "set_tid_address", &[]), (98, "futex", &[]), (101, "nanosleep", &[]),
    (113, "clock_gettime", &[]), (117, "ptrace", &[]), (124, "sched_yield", &[]), (129, "kill", &[]), (131, "tgkill", &[]),
    (134, "rt_sigaction", &[]), (135, "rt_sigprocmask", &[]), (160, "uname", &[]), (172, "getpid", &[]), (173, "getppid", &[]),
    (174, "getuid", &[]), (175, "geteuid", &[]), (176, "getgid", &[]), (177, "getegid", &[]), (178, "gettid", &[]), (179, "sysinfo", &[]),
    (198, "socket", &[]), (200, "bind", &[]), (201, "listen", &[]), (202, "accept", &[]), (203, "connect", &[]), (206, "sendto", &[]),
    (207, "recvfrom", &[]), (214, "brk", &[]), (215, "munmap", &[]), (216, "mremap", &[]), (220, "clone", &[]), (221, "execve", &[0]),
    (222, "mmap", &[]), (226, "mprotect", &[]), (260, "wait4", &[]), (278, "getrandom", &[]), (279, "memfd_create", &[0]),
];

/// The name of a Linux system call and its arguments that are paths
pub fn linux(arch: Architecture, number: i128) -> Option<(&'static str, &'static [usize])> {
    let table = match arch {
        Architecture::X86_64 => X86_64,
        Architecture::X86 => X86,
        Architecture::Aarch64 => AARCH64,
        _ => return None,
    };

    let number = u32::try_from(number).ok()?;
    let index = table.binary_search_by_key(&number, |(n, ..)| *n).ok()?;
    return Some((table[index].1, table[index].2));
}

/// The number written by write(2), whose buffer has the length after it
pub fn is_write(arch: Architecture, number: i128) -> bool {
    return linux(arch, number).is_some_and(|(name, _)| name == "write");
}

/// The system calls that end the process
pub fn is_exit(arch: Architecture, number: i128) -> bool {
    return linux(arch, number).is_some_and(|(name, _)| matches!(name, "exit" | "exit_group"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_tables() {
        for table in [X86_64, X86, AARCH64] {
            assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
        }

        assert_eq!(linux(Architecture::X86_64, 2), Some(("open", &[0usize][..])));
        assert_eq!(linux(Architecture::Aarch64, 64).map(|c| c.0), Some("write"));
        assert!(is_write(Architecture::X86, 4) && !is_write(Architecture::X86_64, 4));
        assert!(is_exit(Architecture::X86, 1) && is_exit(Architecture::X86_64, 231) && is_exit(Architecture::Aarch64, 93) && !is_exit(Architecture::X86_64, 1));
    }
}
