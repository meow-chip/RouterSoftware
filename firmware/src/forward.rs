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

// used for cuckoo to decide which key should be kicked out
static mut KICK: u8 = 0;

impl Cuckoo {
    pub fn new() -> Self {
        // assert rows num is the power of 2
        assert!(ROWS_NUM & (ROWS_NUM - 1) == 0);

        Cuckoo {
            rows: [Row::new(); ROWS_NUM as usize],
        }
    }

    fn row_ids(k: &IPAddr) -> (usize, usize) {
        let h = unsafe { core::mem::transmute::<IPAddr, u32>(*k) }; // TODO: replace with a real hasher
        let row_id1 = h & ROWS_NUM_MASK;
        let row_id2 = (h >> 16) & ROWS_NUM_MASK;
        (row_id1 as usize, row_id2 as usize)
    }

    /// Inserts a (k, v) pair into the table.
    /// If the key is already in the table, it will replace it with the new value.
    /// The k cannot be zero ([0, 0, 0, 0]) since Cuckoo uses the zero as the invalid key internally.
    /// If setting the random_evict to true, then it will evict a random key to when there are not empty slots.
    pub fn insert(&mut self, k: &IPAddr, v: &IPAddr, random_evict: bool) -> Result<(), ()> {
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
        if self.rows[row_id1].insert(k, v) == Ok(()) {
            return Ok(());
        }
        if self.rows[row_id2].insert(k, v) == Ok(()) {
            return Ok(());
        }

        // shift keys to other rows to reserve a slot for current key
        for &rid in &[row_id1, row_id2] {
            if let Some(slot_id) = self.shift(rid, 3) {
                self.rows[rid].keys[slot_id] = *k;
                self.rows[rid].values[slot_id] = *v;
                return Ok(());
            }
        }

        if random_evict {
            // self.rows[rid].keys[slot_id] will be kicked out
            let (rid, slot_id) = unsafe {
                KICK = (KICK + 1) & 7; // (KICK + ) % 8;
                let rid = if KICK <= 3 {
                    row_id1
                } else {
                    row_id2
                };
                let slot_id = (KICK & 3) as usize;
                (rid, slot_id)
            };


            self.rows[rid].keys[slot_id] = *k;
            self.rows[rid].values[slot_id] = *v;
            return Ok(());
        }

        Err(())
    }

    fn shift(&mut self, row_id: usize, depth: i32) -> Option<usize> {
        // if there is an empty slot, we stop shifting and return the empty slot id
        for i in 0..self.rows[row_id].keys.len() {
            if self.rows[row_id].keys[i] == [0, 0, 0, 0] {
                return Some(i);
            }
        }

        if depth == 0 {
            return None;
        }

        for i in 0..self.rows[row_id].keys.len() {
            let ref k = self.rows[row_id].keys[i];
            let (mut row_id1, mut row_id2) = Cuckoo::row_ids(k);

            // we cannot do anything if a key only has one candidate row
            if row_id1 == row_id2 {
                continue;
            }

            // swap to make sure row_id1 == row_id
            if row_id2 == row_id {
                core::mem::swap(&mut row_id1, &mut row_id2);
            }

            if let Some(slot_id) = self.shift(row_id2, depth - 1) {
                // move the currnt key to new row, and return the empty slot
                self.rows[row_id2].keys[slot_id] = self.rows[row_id].keys[i];
                self.rows[row_id2].values[slot_id] = self.rows[row_id].values[i];
                return Some(i);
            }
        }

        None
    }

    pub fn lookup(&self, k: &IPAddr) -> Option<IPAddr> {
        let (row_id1, row_id2) = Cuckoo::row_ids(k);
        
        self.rows[row_id1].lookup(k)
            .or(self.rows[row_id2].lookup(k))
    }

    pub fn remove(&mut self, k: &IPAddr) -> Result<(), ()> {
        let (row_id1, row_id2) = Cuckoo::row_ids(k);
        
        self.rows[row_id1].remove(k)
            .or(self.rows[row_id2].remove(k))
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
        c.insert(from, to, false)?;
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

#[cfg(test)]
mod tests {
    extern crate rand;
    use std::vec::Vec;
    use std::collections::HashSet;
    use rand::prelude::*;
    use super::*;

    #[test]
    fn test_cuckoo_modifiying() -> Result<(), ()> {
        let mut c = Cuckoo::new();
    
        c.insert(&[192, 168, 1, 23], &[192, 168, 1, 1], false)?;
        c.insert(&[192, 168, 1, 23], &[10, 1, 1, 1], false)?;
        assert_eq!(c.lookup(&[192, 168, 1, 23]).unwrap(), [10, 1, 1, 1]);
    
        Ok(())
    }

    fn gen_ipaddr() -> IPAddr {
        let mut rng = rand::thread_rng();
        [rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()]
    }

    #[test]
    fn test_utlizaiont_rate() -> Result<(), ()> {
        // the table can store 0.8 * ROWS_NUM * 4 keys
        // i.e., the utilization rate is 0.8
        let key_cnt = (0.8 * ROWS_NUM as f32 * 4 as f32) as usize;
    
        let mut c = Cuckoo::new();
        let mut kvs = Vec::<(IPAddr, IPAddr)>::with_capacity(key_cnt);
        let mut keys = HashSet::<IPAddr>::new();
    
        // insert to check if the Cuckoo can achieve 80% utilization rate 
        for _ in 0..key_cnt {
            loop {
                let k = gen_ipaddr();
                let v = gen_ipaddr();
                // to ensure there are not duplicate keys
                if !keys.contains(&k) && k != [0, 0, 0, 0] {
                    c.insert(&k, &v, false)?;
                    keys.insert(k);
                    kvs.push((k, v));
                    break;
                }
            }
        }
        for (from, to) in &kvs {
            assert_eq!(c.lookup(from).unwrap(), *to);
        }

        // check if keep inserting, will the random_evict works
        for _ in 0..key_cnt {
            loop {
                let k = gen_ipaddr();
                let v = gen_ipaddr();
                // to ensure there are not duplicate keys
                if !keys.contains(&k) && k != [0, 0, 0, 0] {
                    c.insert(&k, &v, true)?;
                    keys.insert(k);
                    assert_eq!(c.lookup(&k).unwrap(), v);
                    kvs.push((k, v));
                    break;
                }
            }
        }
        let keys_in_cuckoo: usize = kvs.iter().map(|(k, _)| {
            c.lookup(&k).is_some() as usize
        }).sum();
        assert!(keys_in_cuckoo > key_cnt + 10);
    
        Ok(())
    }
}