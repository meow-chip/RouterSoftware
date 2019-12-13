use crate::buf::EthType;

#[repr(u16)]
pub enum HType {
    Eth = 0x0100
}

#[repr(u16)]
pub enum Oper {
    Req = 0x0100,
    Reply = 0x0200,
}

#[repr(C)]
pub struct ARP {
    pub htype: HType,
    pub ptype: EthType,
    pub hlen: u8,
    pub plen: u8,
    pub op: Oper,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}
