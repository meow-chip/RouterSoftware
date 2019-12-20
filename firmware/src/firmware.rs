#![feature(asm)]
#![feature(const_generics)]

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

mod util;
mod buf;
mod data;
mod nc;
mod cmd;
mod routing;
mod forward;

use buf::*;
use buf::icmp::*;
use data::arp::*;
use cmd::*;

use util::*;

static BOOTMSG: &'static str = "BOOT\n\rHello, MeowRouter!\n\r";

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    hprint_setup();
    hprint(BOOTMSG);

    let mut buf_handle = buf::rst_buf();
    let mut snd_handle = buf::snd_buf();

    let mut ncache = nc::NeighboorCache::default();

    // Initialize
    for vlan in 0..=4 {
        Cmd {
            op: Op::SetIP,
            idx: vlan,
            data: [1, vlan, 0, 10, 0, 0],
        }.send();

        Cmd {
            op: Op::SetMAC,
            idx: vlan,
            data: [vlan, 0, 0, 0, 0, 0],
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
                        hprint("ARP\n\r");
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
                                // hprint("ARP request\n\r");

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
                    ParsedBufHandle::IPv4(handle, body) => {
                        hprint("IP:\n\r");

                        let proto = handle.proto();
                        hprint("PROTO: ");
                        hprint_dec(proto as u64);
                        hprint("\n\r");

                        let proto = handle.proto();

                        if proto == IPProto::ICMP {
                            hprint("> ICMP\n\r");
                            buf_handle.dump();

                            let icmp = core::mem::transmute::<_, ICMPHeader>(
                                core::ptr::read_volatile(body as *const [u8;8])
                            );

                            if icmp.r#type == ICMPType::EchoRequest {
                                hprint("---\n\r");
                                // Construct icmp reply
                                let mut reply = ICMPHeader {
                                    r#type: ICMPType::EchoReply,
                                    code: 0,
                                    rest: [0, 0],
                                    chksum: 0,
                                };
                                reply.fill_chksum();

                                let mut ipbuf = [0u8;20];
                                let (mut ip, _) = IPv4Handle::allocate(&mut ipbuf[0]);

                                ip.outgoing(IPProto::ICMP, 8, [10, 0, 4, 1], handle.src());

                                // TODO: use arp cache?
                                snd_handle.write_dest(buf_handle.src());
                                snd_handle.write_src([0,0,0,0,0,4]);
                                snd_handle.write_port(buf_handle.port());

                                let mut snd_data = snd_handle.data() as *mut u16;
                                let snd_data_origin = snd_data;

                                let ipbuf: [u16; 10] = core::mem::transmute(ipbuf);
                                let reply: [u16; 4] = core::mem::transmute(reply);

                                for i in ipbuf.iter() {
                                    core::ptr::write_volatile(snd_data, *i);
                                    snd_data = snd_data.offset(1);
                                }

                                for i in reply.iter() {
                                    core::ptr::write_volatile(snd_data, *i);
                                    snd_data = snd_data.offset(1);
                                }

                                let payload_len = ((snd_data as usize - snd_data_origin as usize) as u16);
                                hprint("Response len: ");
                                hprint_dec(payload_len as u64);
                                hprint("\n\r");

                                snd_handle.write_eth_type(EthType::ARP);
                                snd_handle.write_port(buf_handle.port());
                                snd_handle.write_payload_len(payload_len);
                                snd_handle.dump();
                                snd_handle.send();
                                hprint("Start wait\n\r");
                                snd_handle.wait_snd();
                                hprint("Sent\n\r");
                            }
                        } else if proto == IPProto::IGMP {
                            hprint("> IGMP\n\r");
                        } else if proto == IPProto::TCP {
                            hprint("> TCP\n\r");
                        } else if proto == IPProto::UDP {
                            hprint("> UDP\n\r");
                        } else {
                            hprint("> Unknown!\n\r");
                        }
                        buf_handle.drop();
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
                buf_handle.drop();
            },
            BufState::ForwardMiss => {
                hprint("Forward miss packet\n\r");
                buf_handle.drop();
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    hprint("PANIC:\n\r");
    let ps = info.payload().downcast_ref::<&str>().unwrap();
    hprint(ps);

    loop {}
}

#[no_mangle]
pub unsafe extern "C" fn _trap() -> ! {
    hprint("TRAP\n\r");

    loop {}
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    // TODO: memory-mapped rst
    loop {}
}
