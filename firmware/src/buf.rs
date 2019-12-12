#[repr(u8)]
pub enum BufState {
    Vacant = 0,
    Incoming = 1,
    Outgoing = 2,
}

const BUF_BASE: u64 = 0xFFFF30000000u64;
const BUF_CELL_SIZE: u64 = 2048;
const BUF_COUNT: u8 = 8;

pub struct BufHandle {
    ptr: u8,
}

impl BufHandle {
    pub fn probe(&self) -> BufState {
        let status_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::read_volatile(status_addr as *const BufState)
        }
    }

    pub fn drop(&mut self) {
        let status_addr = BUF_BASE + (self.ptr as u64 + 1) * BUF_CELL_SIZE - 1;
        unsafe {
            core::ptr::write_volatile(status_addr as *mut BufState, BufState::Vacant)
        }
        self.step()
    }

    fn step(&mut self) {
        self.ptr = if self.ptr == BUF_COUNT - 1 {
            1
        } else {
            self.ptr + 1
        }
    }
}

pub fn get_buf() -> BufHandle {
    BufHandle {
        ptr: 0,
    }
}
