/*
 * Neighboor lookup cache
 *
 */

use crate::cmd::{Cmd, Op};
use crate::util::*;

const NC_ENT_COUNT: usize = 16;
const NC_ENT_HW_COUNT: usize = 8;

#[derive(Default)]
pub struct NCEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub port: u8,
    hardware_slot: Option<usize>,
    valid: bool,
}

#[derive(Default)]
pub struct NeighboorCache {
    entries: [NCEntry; NC_ENT_COUNT],
    nptr: usize,
    nhwptr: usize,
}

impl NeighboorCache {
    pub fn lookup(&self, ip: &[u8; 4]) -> Option<usize> {
        for i in 0..NC_ENT_COUNT {
            let ent = &self.entries[i];

            if ent.valid && ent.ip == *ip {
                return Some(i);
            }
        }

        None
    }

    pub fn get(&self, at: usize) -> &NCEntry {
        &self.entries[at]
    }

    pub fn put(&mut self, ip: [u8; 4], mac: [u8; 6], port: u8) {
        if self.entries[self.nptr].valid {
            if let Some(hwidx) = self.entries[self.nptr].hardware_slot {
                let dis_cmd = Cmd {
                    op: Op::DisableNCEnt,
                    idx: hwidx as u8,
                    data: [0; 6],
                };

                dis_cmd.send();
            }
        }

        self.entries[self.nptr] = NCEntry {
            valid: true,
            hardware_slot: None,
            ip, mac, port,
        };

        self.nptr = if self.nptr == NC_ENT_COUNT - 1 {
            0
        } else {
            self.nptr + 1
        };
    }

    pub fn write_hardware(&mut self, at: usize) {
        for ent in self.entries.iter_mut() {
            if ent.valid && ent.hardware_slot == Some(self.nhwptr) {
                ent.hardware_slot = None;
                break;
            }
        }

        hprint("| Writing IP: ");
        hprint_ip(&self.entries[at].ip);
        hprint("\n\r");

        let ip_cmd = Cmd {
            op: Op::WriteNCEntIP,
            idx: self.nhwptr as u8,
            data: [
                self.entries[at].ip[3],
                self.entries[at].ip[2],
                self.entries[at].ip[1],
                self.entries[at].ip[0],
                0,
                0,
            ],
        };

        ip_cmd.send();

        hprint("| Writing MAC: ");
        hprint_mac(&self.entries[at].mac);
        hprint("\n\r");

        let mac_cmd = Cmd {
            op: Op::WriteNCEntMAC,
            idx: self.nhwptr as u8,
            data: [
                self.entries[at].mac[5],
                self.entries[at].mac[4],
                self.entries[at].mac[3],
                self.entries[at].mac[2],
                self.entries[at].mac[1],
                self.entries[at].mac[0],
            ],
        };

        mac_cmd.send();

        hprint("| Writing port: ");
        hprint_dec(self.entries[at].port as u64);
        hprint("\n\r");

        let port_cmd = Cmd {
            op: Op::WriteNCEntPort,
            idx: self.nhwptr as u8,
            data: [
                self.entries[at].port,
                0,0,0,0,0
            ],
        };

        port_cmd.send();

        let en_cmd = Cmd {
            op: Op::EnableNCEnt,
            idx: self.nhwptr as u8,
            data: [0; 6],
        };

        en_cmd.send();

        self.entries[at].hardware_slot = Some(self.nhwptr);

        self.nhwptr = if self.nhwptr == NC_ENT_HW_COUNT-1 {
            0
        } else {
            self.nhwptr + 1
        }
    }
}
