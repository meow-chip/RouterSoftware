#![feature(asm)]

#![no_std]

mod util;
mod buf;
mod data;

use buf::*;
use data::arp::*;

use util::*;

static BOOTMSG: &'static str = "BOOT\n\rHello, MeowRouter!\n\r";

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    hprint_setup();
    hprint(BOOTMSG);

    let mut buf_handle = buf::get_buf();

    // Main loop
    loop {
        // Polls recv buf

        match buf_handle.probe() {
            BufState::Incoming => {
                match buf_handle.parse() {
                    ParsedBufHandle::ARP(ptr) => {
                        let mut arp = core::ptr::read_volatile(ptr);
                        match arp.op {
                            Oper::Reply => {
                                hprint("ARp");
                                buf_handle.drop();
                            },
                            Oper::Req => {
                                hprint("ARq");
                                arp.tpa = arp.spa;
                                arp.tha = arp.sha;
                                arp.spa = [10, 0, 1, 1];
                                arp.sha = [1,2,3,4,5,6];
                                arp.op = Oper::Reply;

                                core::ptr::write_volatile(ptr, arp);
                            },
                        }
                    },
                    ParsedBufHandle::Unknown => {
                        hprint("U");
                        buf_handle.drop();
                    }
                }
            },
            BufState::Outgoing => {
                unreachable!()
            },
            _ => {
                buf_handle.drop();
            }
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
