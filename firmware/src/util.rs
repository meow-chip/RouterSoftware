// const FREQ: u64 = 50_000_000;

const SERIAL_BASE: usize = 0xFFFF00000000;
const CLOCK_FREQ: u64 = 50;

pub fn hprint_setup() {
    // TODO: enable interrupt
}

pub fn hprint_char(c: u8) {
    unsafe {
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
}

pub fn hprint_bytes(cs: &[u8]) {
    for c in cs {
        hprint_char(*c);
    }
}

pub fn hprint(s: &str) {
    hprint_bytes(s.as_bytes());
}

pub fn hprint_hex_digit(b: u8) {
    if b <= 9 {
        hprint_char(b + '0' as u8);
    } else {
        hprint_char(b - 10 + 'A' as u8);
    }
}

pub fn hprint_hex_byte(b: u8) {
    let hi = b >> 4;
    let lo = b & 0xF;
    hprint_hex_digit(hi);
    hprint_hex_digit(lo);
}

pub fn hprint_hex_u64(b: u64) {
    for i in 0..8 {
        hprint_hex_byte((b >> (64 - i * 8 - 8)) as u8);
        hprint(" ");
    }
}

pub fn hprint_hex(s: &[u8]) {
    for b in s {
        hprint_hex_byte(*b);
    }
}

pub fn hprint_dec(mut n: u64) {
    if n == 0 {
        hprint("0");
        return;
    }

    let mut buf = [0u8; 20];
    let mut ptr: usize = 0;
    while n != 0 {
        buf[ptr] = (n % 10) as u8 + '0' as u8;
        n /= 10;
        ptr += 1;
    }

    loop {
        ptr -= 1;
        hprint_char(buf[ptr]);

        if ptr == 0 {
            break;
        }
    }
}

pub fn hprint_mac(s: &[u8;6]) {
    for i in 0..5 {
        hprint_hex_byte(s[i]);
        hprint(":");
    }

    hprint_hex_byte(s[5]);
}

pub fn hprint_ip(s: &[u8; 4]) {
    for i in 0..3 {
        hprint_dec(s[i] as u64);
        hprint(".");
    }

    hprint_dec(s[3] as u64);
}

pub fn cur_time() -> u64 {
    riscv::register::mcycle::read64() / CLOCK_FREQ
}