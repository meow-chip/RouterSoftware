#[repr(u8)]
pub enum Op {
    Nop = 0,
    SetIP = 1,
    SetMAC = 2,
    WriteNCEntIP = 3,
    WriteNCEntMAC = 4,
    WriteNCEntPort = 5,
    EnableNCEnt = 6,
    DisableNCEnt = 7,
}

const CMD_BASE_ADDR: u64 = 0xFFFF_4000_0000;

#[repr(C)]
pub struct Cmd {
    pub op: Op,
    pub idx: u8,
    pub data: [u8;6],
}

impl Cmd {
    pub fn send(self) {
        assert_eq!(core::mem::size_of::<Cmd>(), 8);

        unsafe {
            let repr: [u32; 2] = core::mem::transmute(self);
            // Clear previous command
            core::ptr::write_volatile(CMD_BASE_ADDR as *mut u32, 0);

            // Write higher part of the command
            core::ptr::write_volatile((CMD_BASE_ADDR + 0x8u64) as *mut u32, repr[1]);

            // Write lower part of the command
            core::ptr::write_volatile(CMD_BASE_ADDR as *mut u32, repr[0]);
        }
    }
}
