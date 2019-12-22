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
use forward::*;
use cmd::*;

use util::*;

static BOOTMSG: &'static str = "BOOT\n\rHello, MeowRouter!\n\r";

const IPS: [[u8; 4]; 5] = [
    [10, 0, 0, 1],
    [192, 168, 0, 1],
    [192, 168, 1, 1],
    [192, 168, 2, 1],
    [192, 168, 3, 1],
];

const MACS: [[u8; 6]; 5] = [
    [0x9c, 0xeb, 0, 0, 1, 0],
    [0x9c, 0xeb, 0, 0, 0, 1],
    [0x9c, 0xeb, 0, 0, 0, 2],
    [0x9c, 0xeb, 0, 0, 0, 3],
    [0x9c, 0xeb, 0, 0, 0, 4],
];

extern "C" {
    #[no_mangle]
    static mut _cuckoo: Cuckoo;
}

#[no_mangle]
static mut rules_ptr: *mut [Rule; 8192] = core::ptr::null_mut();
#[no_mangle]
static mut rule_count: usize = 0;
#[no_mangle]
static mut rule_updated: bool = false;

#[no_mangle]
static mut ncache_ptr: *const nc::NeighboorCache = core::ptr::null();

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    for i in ((4 << 20) / 8)..((8 << 20) / 8) {
        core::ptr::write_volatile((i*8) as *mut u64, 0);
    }

    hprint_setup();
    hprint(BOOTMSG);

    let ct = cur_time();
    hprint("Cur time: ");
    hprint_dec(ct);
    hprint("us\n\r");

    // Meow_Init(ct);

    hprint("?");

    let mut buf_handle = BufHandle {
        ptr: 1,
    };

    hprint("?");

    let mut snd_handle = BufHandle {
        ptr: 0,
    };

    hprint("?");

    let mut rules: [Rule; 8192] = core::mem::uninitialized();
    let mut ncache = nc::NeighboorCache::default();

    hprint("?");

    rules_ptr = core::mem::transmute(&rules as *const _);
    ncache_ptr = &ncache;

    rules[0] = Rule {
        prefix: [0,0,0,0],
        len: 0,
        next: [255,255,255,255], // Routes to broadcast = ignore
        metric: 0,
        if_index: 0,
    };

    for i in 0..4u8 {
        rules[i as usize+1] = Rule {
            prefix: [192,168,i,0],
            len: 24,
            next: [192,168,i,1],
            metric: 0,
            if_index: i+1,
        };
    }

    rule_count = 5;

    hprint("?");
    let routing_storage: [Trie; 4096] = [Default::default(); 4096];
    let mut routing_alloc = TrieBuf::new(routing_storage);
    let mut routing_table = Trie::from_rules(&mut routing_alloc, &rules[0..rule_count]);
    hprint("!");

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
    let mut last_cycle = 0;
    loop {
        // Meow_PerSec(ct);

        // Polls recv buf
        if buf_handle.ptr as u64 != last_cycle {
            hprint("Ptr step: ");
            hprint_dec(buf_handle.ptr as u64);
            hprint("\n\r");

            last_cycle = buf_handle.ptr as u64;
        }

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
                                let port = buf_handle.port();

                                if ncache.lookup(&arp.tpa).is_none() {
                                    hprint("ARP cache put:\n\r");
                                    hprint("  ");
                                    hprint_ip(&arp.spa);
                                    hprint(" -> ");
                                    hprint_mac(&arp.sha);
                                    hprint("\n\r");
                                    ncache.put(arp.spa, arp.sha, buf_handle.port());
                                }

                                arp.tpa = arp.spa;
                                arp.tha = arp.sha;
                                arp.spa = IPS[port as usize];
                                arp.sha = MACS[port as usize];
                                arp.op = Oper::Reply;

                                core::ptr::write_volatile(ptr, arp);

                                let src = buf_handle.src();
                                buf_handle.write_dest(src);
                                buf_handle.write_src(MACS[port as usize]);

                                buf_handle.send();
                            },
                        }
                    },
                    ParsedBufHandle::IPv4(handle, body) => {
                        hprint("IP:\n\r");

                        let proto = handle.proto();

                        if proto == IPProto::ICMP {
                            hprint("> ICMP\n\r");

                            let tot_size = handle.payload_len();

                            let mut icmp_rd = [0; 128];
                            for i in 0..tot_size {
                                unsafe {
                                    icmp_rd[i as usize] = core::ptr::read_volatile(body.offset(i as isize));
                                }
                            }

                            let icmp: ICMPHeader::<60> = core::mem::transmute(icmp_rd);

                            if icmp.r#type == ICMPType::EchoRequest {
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

                                let port = buf_handle.port();
                                snd_handle.write_dest(buf_handle.src());
                                snd_handle.write_src(MACS[port as usize]);
                                snd_handle.write_port(port);

                                ip.outgoing(IPProto::ICMP, tot_size, IPS[port as usize], handle.src());

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

                                snd_handle.write_eth_type(EthType::IPv4);
                                snd_handle.write_payload_len(payload_len);
                                snd_handle.send();
                            } else {
                                hprint("> Unsupported ICMP type\n\r");
                            }
                            buf_handle.drop();
                        } else if proto == IPProto::IGMP {
                            hprint("> IGMP, ignoring\n\r");
                            buf_handle.drop();
                        } else if proto == IPProto::TCP {
                            hprint("> TCP, ignoring\n\r");
                            buf_handle.drop();
                        } else if proto == IPProto::UDP {
                            hprint("> UDP\n\r");
                            Meow_ReceiveIPPacket(
                                buf_handle.data(),
                                buf_handle.payload_len() as usize,
                                &buf_handle.src(),
                                buf_handle.port(),
                            );

                            buf_handle.drop();
                        } else {
                            hprint("> Unknown!\n\r");
                            buf_handle.dump();
                            buf_handle.drop();
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

                        snd_handle.write_src(MACS[i]);
                        snd_handle.write_dest([255,255,255,255,255,255]);

                        snd_handle.write_port(i as u8);
                        snd_handle.write_eth_type(EthType::ARP);
                        snd_handle.write_payload_len(payload_len);
                        snd_handle.send();
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

                        unsafe {
                            if let Err(_) = _cuckoo.insert(&[
                                dest[3],
                                dest[2],
                                dest[1],
                                dest[0],
                            ], &[
                                rule[3],
                                rule[2],
                                rule[1],
                                rule[0],
                            ]) {
                                hprint("Cuckoo write failed.");
                            }
                        }
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
    // let ps = info.payload().downcast_ref::<&str>().unwrap();
    // hprint(ps);

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

#[no_mangle]
pub unsafe extern "C" fn Meow_Update(insert: bool, r: routing::Rule) -> bool {
    for idx in 0..rule_count {
        if (*rules_ptr)[idx].prefix == r.prefix && (*rules_ptr)[idx].len == r.len {
            if insert {
                if r.metric < (*rules_ptr)[idx].metric {
                    (*rules_ptr)[idx] = r;
                    rule_updated = true;
                } else {
                    return false;
                }
            } else {
                (*rules_ptr)[idx] = (*rules_ptr)[rule_count-1];
                rule_count -= 1;
                rule_updated = true;
            }
            return true;
        }
    }

    if insert {
        (*rules_ptr)[rule_count] = r;
        rule_count += 1;
        rule_updated = true;
    }
    return true;
}

#[no_mangle]
pub unsafe extern "C" fn Meow_ArpGetMacAddress(if_index: u8, ip: u32, ret: &mut [u8; 6]) -> usize {
    match (&*ncache_ptr).lookup(core::mem::transmute(&ip)) {
        Some(idx) => {
            let result = (&*ncache_ptr).get(idx);
            *ret = result.mac;
            0
        },
        None => {
            1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn Meow_SendIPPacket(buffer: *const u8, length: usize, if_index: u8, dst_mac: &[u8; 6]) -> usize {
    // Write directly into snd_buf
    let mut buf = buf::snd_buf();

    let ptr = buf.data();

    core::ptr::copy_nonoverlapping(buffer, ptr, length);
    buf.write_payload_len(length as u16);
    buf.write_src(MACS[if_index as usize]);
    buf.write_dest(*dst_mac);
    buf.write_port(if_index);
    buf.send();

    0
}

extern "C" {
    fn Meow_ReceiveIPPacket(packet: *const u8, length: usize, src_mac: &[u8; 6], if_index: u8) -> u64;
    fn Meow_Init(usec: u64) -> u64;
    fn Meow_PerSec(usec: u64) -> u64;
}