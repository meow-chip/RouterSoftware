// const FREQ: u64 = 50_000_000;

const SERIAL_BASE: usize = 0xFFFF00000000;

pub fn hprint_setup() {
    // TODO: enable interrupt
}

pub unsafe fn hprint_char(c: u8) {
    core::ptr::write_volatile((SERIAL_BASE + 4) as *mut u8, c);
    // Spin until FIFO is empty
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    loop {
        let status = core::ptr::read_volatile((SERIAL_BASE + 8) as *const u8);
        let fifo_empty = (status & 0b100) != 0;
        if fifo_empty {
            return;
        }
    }
}

pub fn hprint_bytes(cs: &[u8]) {
    for c in cs {
        unsafe {
            hprint_char(*c);
        }
    }
}

pub fn hprint(s: &str) {
    hprint_bytes(s.as_bytes());
}
