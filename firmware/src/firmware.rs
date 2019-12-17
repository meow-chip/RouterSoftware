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

    let mut buf_handle = buf::rst_buf();

    // Main loop
    loop {
        // Polls recv buf

        let probed = buf_handle.probe();

        match probed {
            BufState::Incoming => {
                match buf_handle.parse() {
                    ParsedBufHandle::ARP(ptr) => {
                        let mut arp = core::ptr::read_volatile(ptr);
                        match arp.op {
                            Oper::Reply => {
                                hprint("ARp\n\r");
                                buf_handle.drop();
                            },
                            Oper::Req => {
                               hprint("ARq\n\r");
                                arp.tpa = arp.spa;
                                arp.tha = arp.sha;
                                arp.spa = [10, 0, 4, 1];
                                arp.sha = [0,0,0,0,0,4];
                                arp.op = Oper::Reply;

                                core::ptr::write_volatile(ptr, arp);

                                let src = buf_handle.src();
                                buf_handle.write_dest(src);
                                buf_handle.write_src([0,0,0,0,0,4]);

                                buf_handle.send();
                            },
                        }
                    },
                    ParsedBufHandle::Unknown => {
                        // hprint("IU\n\r");
                        buf_handle.dump();
                        buf_handle.drop();
                    }
                }
            },
            BufState::Outgoing => {
                unreachable!()
            },
            BufState::Vacant => {
                // Spin
            },
            _ => {
                // hprint("U\n\r");
                buf_handle.drop();
            }
        }
    }
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    hprint("PANIC\n\r");
    loop {}
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    // TODO: memory-mapped rst
    loop {}
}
