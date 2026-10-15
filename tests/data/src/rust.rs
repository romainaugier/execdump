#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

mod checks {
    #[inline(never)]
    pub fn scale(value: u64, factor: u64) -> u64 {
        value.wrapping_mul(factor).wrapping_add(3)
    }

    #[inline(never)]
    pub fn parse(text: &[u8]) -> Option<u32> {
        core::str::from_utf8(text).ok()?.parse::<u32>().ok()
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let text = b"1234";
    let parsed = checks::parse(text).unwrap_or(0);
    let scaled = checks::scale(parsed as u64, 7);
    unsafe { core::arch::asm!("syscall", in("rax") 60, in("rdi") scaled, options(noreturn)) }
}
