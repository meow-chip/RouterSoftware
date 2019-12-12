#![feature(asm)]

#![no_std]

mod util;
mod buf;

use buf::BufState;

use util::*;

static BOOTMSG: &'static str = "Hello, MeowRouter!\n\r";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    hprint_setup();
    hprint(BOOTMSG);

    let mut buf_handle = buf::get_buf();

    // Main loop
    loop {
        // Polls recv buf

        match buf_handle.probe() {
            BufState::Incoming => {
                hprint("R");
                buf_handle.drop();
            },
            BufState::Outgoing => {
                unreachable!()
            },
            BufState::Vacant => {},
        }
    }
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
