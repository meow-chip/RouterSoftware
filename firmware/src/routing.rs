use core::ptr::NonNull;

pub type IPAddr = [u8; 4];

const TRIE_BITLEN: u8 = 4;

fn ip_to_u32(ip: &IPAddr) -> u32 {
    (ip[0] as u32) << 24 |
    (ip[1] as u32) << 16 |
    (ip[2] as u32) << 8 |
    (ip[3] as u32)
}

pub struct NAT {
    addr: IPAddr,
    port: u16,
}

pub enum RoutingLookup {
    Forward {
        next: Option<IPAddr>,
        snat: Option<NAT>,
        dnat: Option<NAT>,
    },
    Local,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub prefix: IPAddr,
    pub next: IPAddr,
    pub len: u8,
    pub metric: u8,
    pub if_index: u8,
}

#[derive(Default, Clone, Copy)]
pub struct Trie {
    next: [Option<NonNull<Trie>>; 1 << TRIE_BITLEN],
    value: Option<IPAddr>,
}

impl Trie {
    /**
     * Rules should be sorted based on their length
     */

    pub fn from_rules<'a, const LEN: usize>(store: &'a mut TrieBuf<{LEN}>, rules: &[Rule]) -> &'a Trie {
        let mut root = store.alloc();
        let root_ref = unsafe { root.as_mut() };

        for rule in rules {
            root_ref.apply_rule(store, rule, 0);
        }

        unsafe { &*root.as_ptr() }
    }

    fn apply_rule<const LEN: usize>(&mut self, store: &mut TrieBuf<{LEN}>, rule: &Rule, depth: u8) {
        if depth >= rule.len {
            self.value = Some(rule.next);
        } else {
            let bitmask = (ip_to_u32(&rule.prefix) >> (32 - TRIE_BITLEN - depth)) & ((1 << TRIE_BITLEN) - 1);
            let left = rule.len - depth;

            if left >= TRIE_BITLEN as u8 {
                let mut n = if let Some(n) = self.next[bitmask as usize] {
                    n
                } else {
                    let ptr = store.alloc();
                    self.next[bitmask as usize] = Some(ptr);
                    ptr
                };

                unsafe { n.as_mut() }.apply_rule(store, rule, depth + TRIE_BITLEN);
            } else {
                let filled = TRIE_BITLEN - left;
                for i in 0..(1 << filled) {
                    let idx = ((bitmask >> filled) << filled) | i;
                    // println!("IDX: {}", idx);
                    let mut n = if let Some(n) = self.next[idx as usize] {
                        n
                    } else {
                        let ptr = store.alloc();
                        self.next[idx as usize] = Some(ptr);
                        ptr
                    };

                    unsafe { n.as_mut() }.apply_rule(store, rule, depth + TRIE_BITLEN);
                }
            }
        }
    }

    pub fn lookup(&self, addr: &IPAddr) -> Option<IPAddr> {
        self.inner_lookup(addr, 0)
    }

    fn inner_lookup(&self, addr: &IPAddr, depth: u8) -> Option<IPAddr> {
        if depth == 32 {
            return self.value;
        }

        let idx = (ip_to_u32(addr) >> (32 - TRIE_BITLEN - depth)) & ((1 << TRIE_BITLEN) - 1);
        // println!("IDX: {}", idx);
        let result = self.next[idx as usize]
            .and_then(|n| unsafe { n.as_ref() }.inner_lookup(addr, depth+TRIE_BITLEN))
            .or(self.value.clone());
        result
    }
}

pub struct TrieBuf<const LEN: usize> {
    store: [Trie; LEN],
    ptr: usize,
}

impl<const LEN: usize> TrieBuf<{LEN}> {
    pub fn new(store: [Trie; LEN]) -> Self {
        Self {
            store,
            ptr: 0,
        }
    }

    fn reset(&mut self) {
        self.ptr = 0;
    }

    fn alloc(&mut self) -> NonNull<Trie> {
        let ret = &mut self.store[self.ptr];
        ret.value = None;
        ret.next = [None; 1 << TRIE_BITLEN];
        self.ptr += 1;
        NonNull::new(ret).unwrap()
    }
}

#[test]
fn test_routing() {
    let mut rules = [
        Rule {
            prefix: [10,0,1,0],
            len: 24,
            next: [192,168,1,1],
        },
        Rule {
            prefix: [10,0,2,0],
            len: 24,
            next: [192,168,2,1],
        },
        Rule {
            prefix: [10,0,0,0],
            len: 16,
            next: [192,168,3,1],
        },
        Rule {
            prefix: [0,0,0,0],
            len: 0,
            next: [192,168,4,1],
        },
        Rule {
            prefix: [10,0,1,255],
            len: 31,
            next: [192,168,5,1],
        },
    ];

    rules.sort_by(|a, b| a.len.cmp(&b.len));

    for i in rules.iter() {
        println!("len: {}", i.len);
    }

    let buf = [Default::default(); 1024];
    let mut trie_buf = TrieBuf::from(buf);
    let trie = Trie::from_rules(&mut trie_buf, &rules);

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

    for (from, to) in cases.iter() {
        println!("Testing from {:?}", from);
        assert_eq!(trie.lookup(from).as_ref(), Some(to));
    }
}
