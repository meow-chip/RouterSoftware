use crate::data::arp::ARP;
use crate::util::*;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum BufState {
    Vacant = 0,
    Incoming = 1,
    Outgoing = 2,
    ForwardMiss = 3,
    ARPMiss = 4,
}

impl BufState {
    pub fn hprint(&self) {
        match *self {
            Self::Vacant => hprint("Vacant\n\r"),
            Self::Incoming => hprint("Incoming\n\r"),
            Self::Outgoing => hprint("Outgoing\n\r"),
            Self::ForwardMiss => hprint("ForwardMiss\n\r"),
            Self::ARPMiss => hprint("ARPMiss\n\r"),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum EthType {
    ARP = 0x0608,
    IPv4 = 0x0008,
}

const BUF_BASE: u64 = 0xFFFF30000000u64;
const BUF_CELL_SIZE: u64 = 2048;
const BUF_COUNT: u8 = 8;

#[derive(Clone, Copy)]
pub struct BufHandle {
    pub ptr: u8,
}

pub enum ParsedBufHandle {
    ARP(*mut ARP),
    Unknown,
}

impl BufHandle {
    pub fn probe(&self) -> BufState {
        let status_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::read_volatile(status_addr as *const BufState)
        }
    }

    pub fn drop(&mut self) {
        self.write_state(BufState::Vacant);
        self.step();
    }

    pub fn send(&mut self) {
        self.write_state(BufState::Outgoing);
        self.step();
    }

    pub fn dest(&self) -> [u8;6] {
        unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE) as *const [u8;6]) }
    }

    pub fn src(&self) -> [u8;6] {
        unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 6) as *const [u8;6]) }
    }

    pub fn port(&self) -> u8 {
        (unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 14) as *const u16) }) as u8
    }

    pub fn write_dest(&self, mac: [u8;6]) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE) as *mut [u8;6], mac); }
    }

    pub fn write_src(&self, mac: [u8;6]) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 6) as *mut [u8;6], mac); }
    }

    pub fn write_port(&self, port: u8) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 14) as *mut u16, port as u16); }
    }

    fn write_state(&mut self, state: BufState) {
        let status_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::write_volatile(status_addr as *mut BufState, state)
        }
    }

    fn step(&mut self) {
        self.ptr = if self.ptr == BUF_COUNT - 1 {
            1
        } else {
            self.ptr + 1
        }
    }

    pub fn parse(&self) -> ParsedBufHandle {
        let et = self.get_eth_type();
        hprint("ETHTYPE:");
        hprint_hex(unsafe {&core::intrinsics::transmute::<_, [u8; 2]>(et)});
        hprint("\n\r");

        match et {
            EthType::ARP => ParsedBufHandle::ARP((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 18) as *mut ARP),
            _ => ParsedBufHandle::Unknown,
        }
    }

    fn get_eth_type(&self) -> EthType {
        let eth_type_addr = BUF_BASE + (self.ptr as u64) * BUF_CELL_SIZE + 16;
        unsafe {
            core::ptr::read_volatile(eth_type_addr as *const EthType)
        }
    }

    pub fn dump(&self) {
        let len_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 4;
        let len = unsafe {
            core::ptr::read_volatile(len_addr as *const u16)
        };

        for i in 0..len {
            unsafe {
                hprint_hex_byte(core::ptr::read_volatile((BUF_BASE + (self.ptr as u64) * BUF_CELL_SIZE + i as u64) as *const u8));
            }
            hprint(" ");
            if i % 16 == 15 {
                hprint("\n\r");
            }
        }

        if len % 16 != 0 {
            hprint("\n\r");
        }
    }
}

pub fn rst_buf() -> BufHandle {
    /*
    for i in 0..BUF_COUNT {
        let status_addr = BUF_BASE + (i as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::write_volatile(status_addr as *mut BufState, BufState::Vacant)
        }
    }
    */

    BufHandle {
        ptr: 1,
    }
}

