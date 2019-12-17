#![feature(asm)]

#![no_std]

mod util;
mod buf;
mod data;
mod nc;
mod cmd;

use buf::*;
use data::arp::*;
use cmd::*;

use util::*;

static BOOTMSG: &'static str = "BOOT\n\rHello, MeowRouter!\n\r";

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    hprint_setup();
    hprint(BOOTMSG);

    let mut buf_handle = buf::rst_buf();

    let mut ncache = nc::NeighboorCache::default();

    // Initialize
    for vlan in 0..=4 {
        Cmd {
            op: Op::SetIP,
            idx: vlan,
            data: [1, vlan, 168, 192, 0, 0],
        }.send();

        Cmd {
            op: Op::SetMAC,
            idx: vlan,
            data: [vlan, 0, 0, 0, 0, 1],
        }.send();
    }

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
                                let port = buf_handle.port();
                                hprint("ARP reply: ");
                                hprint_ip(&arp.spa);
                                hprint(" @ ");
                                hprint_mac(&arp.sha);
                                hprint(" <- ");
                                hprint_dec(port as u64);
                                hprint("\n\r");

                                if ncache.lookup(&arp.spa).is_none() {
                                    ncache.put(arp.spa, arp.sha, buf_handle.port());
                                }

                                buf_handle.drop();
                            },
                            Oper::Req => {
                                hprint("ARP request");

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

                                // TODO: place src arp into cache
                            },
                        }
                    },
                    ParsedBufHandle::Unknown => {
                        hprint("Unknown Incoming Packet:\n\r");
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
            BufState::ARPMiss => {
                hprint("ARP miss packet\n\r");
            },
            BufState::ForwardMiss => {
                hprint("Forward miss packet\n\r");
                buf_handle.drop();
            }
        }
    }
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hprint("PANIC:\n\r");
    let ps = info.payload().downcast_ref::<&str>().unwrap();
    hprint(ps);

    loop {}
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    // TODO: memory-mapped rst
    loop {}
}
