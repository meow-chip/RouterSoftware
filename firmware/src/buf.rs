use crate::data::arp::ARP;
use crate::util::*;

const IP_OUTGOING_TTL: u8 = 64;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
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
#[derive(Clone, Copy, PartialEq)]
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
    IPv4(IPv4Handle, *mut u8),
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
        while self.probe() == BufState::Outgoing {}
        self.step();
    }

    pub fn dest(&self) -> [u8;6] {
        unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE) as *const [u8;6]) }
    }

    pub fn src(&self) -> [u8;6] {
        unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 6) as *const [u8;6]) }
    }

    pub fn port(&self) -> u8 {
        unsafe { core::ptr::read_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 15) as *const u8) }
    }

    pub fn write_dest(&self, mac: [u8;6]) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE) as *mut [u8;6], mac); }
    }

    pub fn write_src(&self, mac: [u8;6]) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 6) as *mut [u8;6], mac); }
    }

    pub fn write_port(&self, port: u8) {
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 12) as *mut u32, 0x81); }
        unsafe { core::ptr::write_volatile((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 15) as *mut u8, port); }
    }

    fn write_state(&mut self, state: BufState) {
        let status_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::write_volatile(status_addr as *mut BufState, state)
        }
    }

    fn step(&mut self) {
        if self.ptr == 0 {
            return;
        }

        self.ptr = if self.ptr == BUF_COUNT - 1 {
            1
        } else {
            self.ptr + 1
        }
    }

    pub fn parse(&self) -> ParsedBufHandle {
        let et = self.eth_type();
        // hprint("ETHTYPE:");
        // hprint_hex(unsafe {&core::intrinsics::transmute::<_, [u8; 2]>(et)});
        // hprint("\n\r");

        if et == EthType::ARP { ParsedBufHandle::ARP((BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 18) as *mut ARP) }
        else if et == EthType::IPv4 {
            ParsedBufHandle::IPv4(
                IPv4Handle {
                    ptr: (BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 18) as *mut u8,
                },
                (BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 18 + 20) as *mut u8,
            )
        } else {
            ParsedBufHandle::Unknown
        }
    }

    pub fn data(&mut self) -> *mut u8 {
        (BUF_BASE + self.ptr as u64 * BUF_CELL_SIZE + 18) as *mut u8
    }

    pub fn eth_type(&self) -> EthType {
        let eth_type_addr = BUF_BASE + (self.ptr as u64) * BUF_CELL_SIZE + 16;
        unsafe {
            core::ptr::read_volatile(eth_type_addr as *const EthType)
        }
    }

    pub fn write_eth_type(&self, t: EthType) {
        let eth_type_addr = BUF_BASE + (self.ptr as u64) * BUF_CELL_SIZE + 16;
        unsafe {
            core::ptr::write_volatile(eth_type_addr as *mut EthType, t);
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

    pub fn write_payload_len(&mut self, len: u16) {
        let len_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 4;
        let len = unsafe {
            core::ptr::write_volatile(len_addr as *mut u16, len + 18)
        };
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

pub fn snd_buf() -> BufHandle {
    BufHandle {
        ptr : 0,
    }
}

pub struct IPv4Handle {
    ptr: *mut u8,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum IPProto {
    ICMP = 0x01,
    IGMP = 0x02,
    TCP = 0x06,
    UDP = 0x11,
}

impl IPv4Handle {
    pub fn allocate(buf: *mut u8) -> (IPv4Handle, *mut u8) {
        unsafe {
            (IPv4Handle { ptr: buf }, buf.offset(20))
        }
    }

    pub fn proto(&self) -> IPProto {
        unsafe { core::ptr::read_volatile(self.ptr.offset(9) as *const IPProto) }
    }

    pub fn src(&self) -> [u8; 4] {
        let mut ret = [0; 4];

        for i in 0..4usize {
            unsafe { ret[i] = core::ptr::read_volatile(self.ptr.offset(12 + i as isize)); }
        }

        ret
    }

    pub fn dest(&self) -> [u8; 4] {
        let mut ret = [0; 4];

        for i in 0..4usize {
            unsafe { ret[i] = core::ptr::read_volatile(self.ptr.offset(16 + i as isize)); }
        }

        ret
    }

    pub fn fill_chksum(&mut self) {
        // Assume aligned
        let mut sum = 0u32;
        for i in 0..10 {
            if i == 5 { continue; }

            unsafe {
                let readout = *((self.ptr as *const u16).offset(i));
                sum += readout as u32;
            }
        }

        while (sum >> 16) > 0 {
            sum = sum & 0xFFFF + (sum >> 16)
        }

        unsafe {
            *(self.ptr as *mut u16).offset(5) = sum as u16;
        }
    }

    pub fn payload_len(&self) -> u16 {
        u16::from_be(unsafe { core::ptr::read_volatile(self.ptr.offset(2) as *const u16) }) - 20
    }

    pub fn outgoing(&mut self, proto: IPProto, payload_len: u16, src: [u8; 4], dest: [u8; 4]) {
        unsafe {
            // Assumes zero-initialized
            core::ptr::write_volatile(self.ptr, (4 << 4) | 5);
            core::ptr::write_volatile(self.ptr.offset(2) as *mut u16, u16::to_be(payload_len + 20));

            core::ptr::write_volatile(self.ptr.offset(8), IP_OUTGOING_TTL);
            core::ptr::write_volatile(self.ptr.offset(9), proto as u8);
            for i in 0..4usize {
                core::ptr::write_volatile(self.ptr.offset(12 + i as isize), src[i]);
            }

            for i in 0..4usize {
                core::ptr::write_volatile(self.ptr.offset(16 + i as isize), dest[i]);
            }
        }

        self.fill_chksum();
    }
}

pub mod icmp {
    #[repr(u8)]
    #[derive(Clone, Copy, PartialEq)]
    pub enum ICMPType {
        EchoReply = 0,
        Unreachable = 3,
        Redirect = 5,
        EchoRequest = 8,
        RouterAd = 9,
        RouterSol = 10,
        TimeExceeded = 11,
        BadIPHeader = 12,
        Timestamp = 13,
        TimestampReply = 14,
    }

    #[repr(C)]
    pub struct ICMPHeader<const U16_BODY: usize> {
        pub r#type: ICMPType,
        pub code: u8,
        pub chksum: u16,
        pub rest: [u16; 2],
        pub body: [u16; U16_BODY],
    }

    impl<const U16_BODY: usize> ICMPHeader<{U16_BODY}> {
        pub fn fill_chksum(&mut self, totlen: u16) {
            let mut sum: u32 = ((self.r#type as u32) << 8) + self.code as u32 + self.rest[0] as u32 + self.rest[1] as u32;

            for idx in 0..(totlen/2 - 4) {
                sum += self.body[idx as usize] as u32;
            }

            while (sum >> 16) > 0 {
                sum = sum & 0xFFFF + (sum >> 16)
            }

            self.chksum = sum as u16;
        }
    }
}
