// const FREQ: u64 = 50_000_000;

const SERIAL_READ: usize = 0xFFFFF0000000;
const SERIAL_WRITE: usize = SERIAL_READ+4;

pub fn hprint_char(c: u8) {
    unsafe { core::ptr::write_volatile(SERIAL_WRITE as *mut u8, c); }
    let mut i = 0;
    // TODO: use int
    while i < 100000 {
        unsafe {
            core::ptr::write_volatile(0 as *mut u8, 0);
        }
        i += 1;
    }
}

pub fn hprint_bytes(cs: &[u8]) {
    for c in cs {
        hprint_char(*c);
    }
}

pub fn hprint(s: &str) {
    hprint_bytes(s.as_bytes());
}
