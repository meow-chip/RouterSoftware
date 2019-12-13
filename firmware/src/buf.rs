use crate::data::arp::ARP;

#[repr(u8)]
pub enum BufState {
    Vacant = 0,
    Incoming = 1,
    Outgoing = 2,
    ForwardMiss = 3,
    ARPMiss = 4,
}

#[repr(u16)]
pub enum EthType {
    ARP = 0x0608,
    IPv4 = 0x0008,
}

const BUF_BASE: u64 = 0xFFFF30000000u64;
const BUF_CELL_SIZE: u64 = 2048;
const BUF_COUNT: u8 = 8;

#[derive(Clone, Copy)]
pub struct BufHandle {
    ptr: u8,
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
}

pub fn get_buf() -> BufHandle {
    BufHandle {
        ptr: 0,
    }
}
