use std::mem;
use super::routing::IPAddr;

const ROWS_NUM: u32 = 1024;
const ROWS_NUM_MASK: u32 = ROWS_NUM - 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Row {
    keys: [IPAddr; 4],
    values: [IPAddr; 4],
}

impl Row {
    fn new() -> Self {
        Row {
            keys: [[0, 0, 0, 0]; 4],
            values: [[0, 0, 0, 0]; 4],
        }
    }

    fn lookup(&self, k: &IPAddr) -> Option<IPAddr> {
        for i in 0..self.keys.len() {
            if &self.keys[i] == k {
                return Some(self.values[i]);
            }
        }

        None
    }

    fn insert(&mut self, k: &IPAddr, v: &IPAddr) -> Result<(), ()> {
        assert_ne!(k, &[0, 0, 0, 0]);
        for i in 0..self.keys.len() {
            if self.keys[i] == [0, 0, 0, 0] {
                self.keys[i] = *k;
                self.values[i] = *v;
                return Ok(());
            }
        }
        
        Err(())
    }

    fn modify(&mut self, k: &IPAddr, v: &IPAddr) -> Result<(), ()> {
        for i in 0..self.keys.len() {
            if &self.keys[i] == k {
                self.values[i] =*v;
                return Ok(());
            }
        }

        Err(())
    }

    fn remove(&mut self, k: &IPAddr) -> Result<(), ()> {
        for i in 0..self.keys.len() {
            if &self.keys[i] == k {
                self.keys[i] = [0, 0, 0, 0];
                return Ok(());
            }
        }

        Err(())
    }
}

#[test]
fn test_row() -> Result<(), ()> {
    let mut r = Row::new();
    r.insert(&[192, 168, 1, 23], &[192, 168, 1, 1])?;
    assert_eq!(r.lookup(&[192, 168, 1, 23]).unwrap(), [192, 168, 1, 1]);
    r.remove(&[192, 168, 1, 23])?;
    assert_eq!(r.lookup(&[192, 168, 1, 23]), None);

    Ok(())
}

#[repr(C)]
pub struct Cuckoo {
    rows: [Row; ROWS_NUM as usize],
}

impl Cuckoo {
    pub fn new() -> Self {
        // assert rows num is the power of 2
        assert!(ROWS_NUM & (ROWS_NUM - 1) == 0);

        Cuckoo {
            rows: [Row::new(); ROWS_NUM as usize],
        }
    }

    fn row_ids(k: &IPAddr) -> (usize, usize) {
        let h = unsafe { mem::transmute::<IPAddr, u32>(*k) }; // TODO: replace with a real hasher
        let row_id1 = h & ROWS_NUM_MASK;
        let row_id2 = (h >> 16) & ROWS_NUM_MASK;
        (row_id1 as usize, row_id2 as usize)
    }

    /// Inserts a (k, v) pair into the table.
    /// If the key is already in the table, it will replace it with the new value.
    /// The k cannot be zero ([0, 0, 0, 0]) since Cuckoo uses the zero as the invalid key internally.
    pub fn insert(&mut self, k: &IPAddr, v: &IPAddr) -> Result<(), ()> {
        assert_ne!(k, &[0, 0, 0, 0]);
        let (row_id1, row_id2) = Cuckoo::row_ids(k);

        // try to modify it in cases it's already there
        if self.rows[row_id1].modify(k, v) == Ok(()) {
            return Ok(());
        }
        if self.rows[row_id2].modify(k, v) == Ok(()) {
            return Ok(());
        }

        // try to insert into the row_id1 first. If it is failed, try to insert into the row_id2
        match self.rows[row_id1].insert(k, v) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.rows[row_id2].insert(k, v)       
            }
        }

        // TODO: shift keys to other rows to reserve a slot for current key
    }

    pub fn lookup(&self, k: &IPAddr) -> Option<IPAddr> {
        let (row_id1, row_id2) = Cuckoo::row_ids(k);
        
        match self.rows[row_id1].lookup(k) {
            Some(v) => Some(v),
            None => self.rows[row_id2].lookup(k)
        }
    }

    pub fn remove(&mut self, k: &IPAddr) -> Result<(), ()> {
        let (row_id1, row_id2) = Cuckoo::row_ids(k);
        
        match self.rows[row_id1].remove(k) {
            Ok(_) => Ok(()),
            Err(_) => self.rows[row_id2].remove(k)
        }
    }

}

#[test]
fn test_cuckoo() -> Result<(), ()> {
    let mut c = Cuckoo::new();

    let cases = [
        ([1,2,3,4], [192,168,4,1]),
        ([10,1,2,3], [192,168,4,1]),
        ([10,0,2,3], [192,168,2,1]),
        ([10,0,1,1], [192,168,1,1]),
        ([10,0,4,3], [192,168,3,1]),
        ([10,0,100,3], [192,168,3,1]),
        ([10,0,1,255], [192,168,5,1]),
        ([10,0,1,254], [192,168,5,1]),
        ([10,0,1,253], [192,168,1,1]),
    ];

    // insert them
    for (from, to) in &cases {
        c.insert(from, to)?;
    }

    // lookup them
    for (from, to) in &cases {
        assert_eq!(c.lookup(from).unwrap(), *to);
    }

    // remove them
    for (from, _) in &cases {
        c.remove(from)?;
    }

    // check the deletions
    for (from, _) in &cases {
        assert_eq!(c.lookup(from), None);
    }
    Ok(())
}

#[test]
fn test_cuckoo_modifiying() -> Result<(), ()> {
    let mut c = Cuckoo::new();

    c.insert(&[192, 168, 1, 23], &[192, 168, 1, 1])?;
    c.insert(&[192, 168, 1, 23], &[10, 1, 1, 1])?;
    assert_eq!(c.lookup(&[192, 168, 1, 23]).unwrap(), [10, 1, 1, 1]);

    Ok(())
}