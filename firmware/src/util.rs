// const FREQ: u64 = 50_000_000;

const SERIAL_BASE: usize = 0xFFFF00000000;
const SERIAL_RW: usize = SERIAL_BASE + 0x1000;

pub fn hprint_setup() {
    // Enable fifo
    unsafe { core::ptr::write_volatile((SERIAL_BASE + 8) as *mut u64, 1); }

    // TODO: enable interrupt
}

pub fn hprint_char(c: u8) {
    unsafe { core::ptr::write_volatile(SERIAL_RW as *mut u8, c); }
}

pub fn hprint_bytes(cs: &[u8]) {
    for c in cs {
        hprint_char(*c);
    }
}

pub fn hprint(s: &str) {
    hprint_bytes(s.as_bytes());
}
