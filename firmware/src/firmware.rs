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
use routing::*;
use cmd::*;

use util::*;

static BOOTMSG: &'static str = "BOOT\n\rHello, MeowRouter!\n\r";

const IPS: [[u8; 4]; 5] = [
    [10, 0, 0, 1],
    [10, 0, 1, 1],
    [10, 0, 2, 1],
    [10, 0, 3, 1],
    [10, 0, 4, 1],
];

const MACS: [[u8; 6]; 5] = [
    [0, 1, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0],
    [2, 0, 0, 0, 0, 0],
    [3, 0, 0, 0, 0, 0],
    [4, 0, 0, 0, 0, 0],
];

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    // Clear memory
    for i in 0..(4 << 20) {
        core::ptr::write_volatile(i as *mut u8, 0);
    }

    hprint_setup();
    hprint(BOOTMSG);

    let mut buf_handle = buf::rst_buf();
    let mut snd_handle = buf::snd_buf();

    let mut ncache = nc::NeighboorCache::default();

    let default_rules = [Rule {
        prefix: [0,0,0,0],
        len: 0,
        next: [255,255,255,255], // Routes to broadcast = ignore
    }];

    let routing_storage: [Trie; 16384] = [Default::default(); 16384];
    let mut routing_alloc = TrieBuf::new(routing_storage);
    let mut routing_table = Trie::from_rules(&mut routing_alloc, &default_rules);

    // Initialize
    for vlan in 0..=4 {
        Cmd {
            op: Op::SetIP,
            idx: vlan,
            data: [
                IPS[vlan as usize][3], IPS[vlan as usize][2], IPS[vlan as usize][1], IPS[vlan as usize][0],
                0, 0,
            ],
        }.send();

        Cmd {
            op: Op::SetMAC,
            idx: vlan,
            data: [
                MACS[vlan as usize][5],
                MACS[vlan as usize][4],
                MACS[vlan as usize][3],
                MACS[vlan as usize][2],
                MACS[vlan as usize][1],
                MACS[vlan as usize][0],
            ],
        }.send();
    }

    // Main loop
    loop {
        // Polls recv buf
        // hprint("PTR:");
        // hprint_dec(buf_handle.ptr as u64);
        // hprint("\n\r");

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
                                hprint("ARP request\n\r");
                                let port = buf_handle.port();

                                if ncache.lookup(&arp.tpa).is_none() {
                                    ncache.put(arp.tpa, arp.tha, buf_handle.port());
                                }

                                hprint("NCACHE put\n\r");

                                arp.tpa = arp.spa;
                                arp.tha = arp.sha;
                                arp.spa = IPS[port as usize];
                                arp.sha = MACS[port as usize];
                                arp.op = Oper::Reply;

                                core::ptr::write_volatile(ptr, arp);

                                let src = buf_handle.src();
                                buf_handle.write_dest(src);
                                buf_handle.write_src(MACS[port as usize]);

                                hprint("Sending\n\r");

                                buf_handle.send();
                                hprint("Sent\n\r");
                            },
                        }
                    },
                    ParsedBufHandle::IPv4(handle, body) => {
                        hprint("IP:\n\r");
                        buf_handle.drop();

                        let proto = handle.proto();

                        if proto == IPProto::ICMP {
                            hprint("> ICMP\n\r");
                            buf_handle.dump();

                            let tot_size = handle.payload_len();

                            hprint("SIZE: ");
                            hprint_dec(tot_size as u64);
                            hprint("\n\r");

                            let mut icmp_rd = [0; 128];
                            for i in 0..tot_size {
                                unsafe {
                                    icmp_rd[i as usize] = core::ptr::read_volatile(body.offset(i as isize));
                                }
                            }

                            let icmp: ICMPHeader::<60> = core::mem::transmute(icmp_rd);

                            if icmp.r#type == ICMPType::EchoRequest {
                                hprint("---\n\r");
                                // Construct icmp reply
                                let mut reply = ICMPHeader::<60> {
                                    r#type: ICMPType::EchoReply,
                                    code: 0,
                                    rest: icmp.rest,
                                    chksum: 0,
                                    body: icmp.body,
                                };


                                // Fill in body
                                // let tot_size = 64;
                                reply.fill_chksum(tot_size);

                                let mut ipbuf = [0u8;20];
                                let (mut ip, _) = IPv4Handle::allocate(&mut ipbuf[0]);

                                // TODO: use arp cache?
                                let port = buf_handle.port();
                                hprint("Port: ");
                                hprint_dec(port as u64);
                                snd_handle.write_dest(buf_handle.src());
                                snd_handle.write_src([0,0,0,0,0,4]);
                                snd_handle.write_port(port);
                                hprint("\n\r");

                                hprint("Outgoing\n\r");
                                ip.outgoing(IPProto::ICMP, tot_size, [10, 0, 4, 1], handle.src());


                                let mut snd_data = snd_handle.data() as *mut u8;
                                let snd_data_origin = snd_data;

                                let ipbuf: [u8; 20] = core::mem::transmute(ipbuf);
                                let reply: [u8; 128] = core::mem::transmute(reply);

                                for i in ipbuf.iter() {
                                    core::ptr::write_volatile(snd_data, *i);
                                    snd_data = snd_data.offset(1);
                                }

                                for i in 0..tot_size {
                                    core::ptr::write_volatile(snd_data, reply[i as usize]);
                                    snd_data = snd_data.offset(1);
                                }

                                let payload_len = (snd_data as usize - snd_data_origin as usize) as u16;
                                hprint("Response len: ");
                                hprint_dec(payload_len as u64);
                                hprint("\n\r");

                                snd_handle.write_eth_type(EthType::IPv4);
                                snd_handle.write_payload_len(payload_len);
                                // snd_handle.dump();
                                snd_handle.send();
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
                hprint("Spin");
            },
            BufState::Vacant => {
                // Spin
            },
            BufState::ARPMiss => {
                hprint("ARP miss packet\n\r");
                let ptr = buf_handle.data();
                let dest = unsafe { core::ptr::read(ptr.offset(16) as *const [u8; 4]) };

                if let Some(idx) = ncache.lookup(&dest) {
                    ncache.write_hardware(idx);
                    let result = ncache.get(idx);
                    buf_handle.write_dest(result.mac);
                    buf_handle.write_port(result.port);
                    buf_handle.send();
                } else {
                    for i in 1..=4 {
                        let arp = ARP {
                            htype: HType::Eth,
                            ptype: EthType::IPv4,
                            hlen: 6,
                            plen: 4,
                            op: Oper::Req,
                            sha: MACS[i],
                            spa: IPS[i],
                            tha: [0,0,0,0,0,0],
                            tpa: dest,
                        };

                        let mut snd_data = snd_handle.data() as *mut u8;
                        let snd_data_origin = snd_data;

                        let buf: [u8; core::mem::size_of::<ARP>()] = core::mem::transmute(arp);

                        for i in buf.iter() {
                            core::ptr::write_volatile(snd_data, *i);
                            snd_data = snd_data.offset(1);
                        }

                        let payload_len = (snd_data as usize - snd_data_origin as usize) as u16;
                        hprint("Sent len: ");
                        hprint_dec(payload_len as u64);
                        hprint("\n\r");

                        snd_handle.write_src(MACS[i]);
                        snd_handle.write_dest([255,255,255,255,255,255]);

                        snd_handle.write_port(i as u8);
                        snd_handle.write_eth_type(EthType::ARP);
                        snd_handle.write_payload_len(payload_len);
                        snd_handle.dump();
                        snd_handle.send();
                        hprint("Start wait\n\r");
                    }

                    buf_handle.drop();
                }
            },
            BufState::ForwardMiss => {
                hprint("Forward miss packet\n\r");

                // Asserts to be IP
                let ptr = buf_handle.data();
                let dest = unsafe { core::ptr::read(ptr.offset(16) as *const [u8; 4]) };

                match routing_table.lookup(&dest) {
                    Some(rule) => {
                        hprint("Found rule: ");
                        hprint_ip(&dest);
                        hprint(" -> ");
                        hprint_ip(&rule);
                        hprint("\n\r");

                        // TODO: apply rule
                    },
                    None => {
                        hprint("Error! Routing failed: ");
                        hprint_ip(&dest);
                        hprint(" -> !\n\r");

                        panic!("Halt");
                    },
                }

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
pub unsafe extern "C" fn _trap(mepc: u64, mcause: u64, mtval: u64) -> ! {
    hprint("TRAP\n\r");
    hprint("MEPC: ");
    hprint_hex_u64(mepc);
    hprint("\n\rMCAUSE: ");
    hprint_hex_u64(mcause);
    hprint("\n\rMTVAL: ");
    hprint_hex_u64(mtval);

    loop {}
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    // TODO: memory-mapped rst
    loop {}
}
