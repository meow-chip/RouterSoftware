#![no_std]
#![no_main]

mod util;

use util::*;

static BOOTMSG: &'static str = "Hello, MeowRouter!\n\r";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    hprint(BOOTMSG);

    loop {}
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    // TODO: memory-mapped rst
    loop {}
}
