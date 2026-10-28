// SPDX-License-Identifier: Apache-2.0
/*
 * C: the default of every hook, and the functions of the C libraries that do not return
 */

use super::Language;

use daedale_core::program::{Language as Kind, Program};

pub struct C;

impl Language for C {
    fn kind(&self) -> Kind {
        return Kind::Unknown;
    }

    fn owns(&self, _program: &Program, _addr: u64) -> bool {
        return true;
    }
}

/// The C runtime, glibc, the Microsoft CRT and Win32 (names without their leading underscores)
pub fn noreturn(name: &str) -> bool {
    return matches!(
        name,
        "exit" | "Exit" | "abort" | "stack_chk_fail" | "assert_fail" | "assert_rtn" | "libc_start_main" | "longjmp" | "siglongjmp" | "longjmp_chk"
            | "pthread_exit" | "fortify_fail" | "chk_fail" | "err" | "errx" | "verr" | "verrx" | "ExitProcess" | "ExitThread" | "FatalExit"
            | "FatalAppExitA" | "FatalAppExitW" | "RaiseFailFastException" | "invalid_parameter_noinfo_noreturn" | "report_gsfailure"
            | "report_rangecheckfailure"
    );
}
