#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

static COLORS: [&str; 3] = ["crimson", "teal", "ochre"];

#[inline(never)]
fn emit(text: &str) {
    unsafe { core::arch::asm!("syscall", in("rax") 1, in("rdi") 1, in("rsi") text.as_ptr(), in("rdx") text.len(), lateout("rcx") _, lateout("r11") _) }
}

#[inline(never)]
fn level(code: u32) -> &'static str {
    if code == 0 { "quiet" } else if code < 3 { "verbose" } else { "debug" }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let code = unsafe { core::ptr::read_volatile(&3u32) };
    emit("starting up\n");
    emit(level(code));
    emit(COLORS[code as usize % 3]);
    unsafe { core::arch::asm!("syscall", in("rax") 60, in("rdi") 0, options(noreturn)) }
}
