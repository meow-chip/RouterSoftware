/*
 * Neighboor lookup cache
 *
 */

use crate::cmd::{Cmd, Op};

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

        self.nptr += 1;
    }

    pub fn write_hardware(&mut self, at: usize) {
        for ent in self.entries.iter_mut() {
            if ent.valid && ent.hardware_slot == Some(self.nhwptr) {
                ent.hardware_slot = None;
                break;
            }
        }

        let ip_cmd = Cmd {
            op: Op::WriteNCEntIP,
            idx: self.nhwptr as u8,
            data: unsafe { core::mem::transmute((self.entries[at].ip, [0u8; 2])) }
        };

        let mac_cmd = Cmd {
            op: Op::WriteNCEntMAC,
            idx: self.nhwptr as u8,
            data: self.entries[at].mac,
        };

        let port_cmd = Cmd {
            op: Op::WriteNCEntPort,
            idx: self.nhwptr as u8,
            data: unsafe { core::mem::transmute(([self.entries[at].port], [0u8; 5])) }
        };

        let en_cmd = Cmd {
            op: Op::EnableNCEnt,
            idx: self.nhwptr as u8,
            data: [0; 6],
        };

        ip_cmd.send();
        mac_cmd.send();
        port_cmd.send();
        en_cmd.send();

        self.entries[at].hardware_slot = Some(self.nhwptr);

        self.nhwptr = if self.nhwptr == NC_ENT_HW_COUNT-1 {
            0
        } else {
            self.nhwptr + 1
        }
    }
}
