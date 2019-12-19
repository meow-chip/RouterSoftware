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

pub struct Rule {
    prefix: IPAddr,
    len: u8,
    next: IPAddr,
}

#[derive(Default)]
pub struct Trie<'a> {
    next: [Option<&'a mut Trie<'a>>; 1 << TRIE_BITLEN],
    value: Option<IPAddr>,
}

impl<'a> Trie<'a> {
    /**
     * Rules should be sorted based on their length
     */

    fn from_rules<const LEN: usize>(store: &'a mut TrieBuf<'a, LEN>, rules: &[Rule]) -> &'a Trie<'a> {
        let root = store.alloc();
        root.value = None;
        root.next = [None; 1 << TRIE_BITLEN];

        for rule in rules {
            root.apply_rule(store, rule, 0);
        }

        root
    }

    fn apply_rule<const LEN: usize>(&mut self, store: &'a mut TrieBuf<'a, LEN>, rule: &Rule, depth: u8) {

        if depth >= rule.len {
            self.value = Some(rule.next);
        } else {
            let bitmask = (ip_to_u32(&rule.prefix) >> depth) & ((1 << TRIE_BITLEN) - 1);
            let left = rule.len - depth;

            if left >= TRIE_BITLEN as u8 {
                let n = if let Some(n) = self.next[bitmask as usize] {
                    n
                } else {
                    let ptr = store.alloc();
                    self.next[bitmask as usize] = Some(ptr);
                    ptr
                };

                n.apply_rule(store, rule, depth + TRIE_BITLEN);
            } else {
                let filled = TRIE_BITLEN - left;
                for i in 0..(1 << filled) {
                    let idx = ((bitmask >> filled) << filled) & i;
                    let n = if let Some(n) = self.next[idx as usize] {
                        n
                    } else {
                        let ptr = store.alloc();
                        self.next[idx as usize] = Some(ptr);
                        ptr
                    };
                }
            }
        }
    }

    fn lookup(&self, addr: &IPAddr, depth: u8) -> Option<IPAddr> {
        if depth == 32 {
            return self.value;
        }

        let idx = (ip_to_u32(addr) >> depth) & ((1 << TRIE_BITLEN) - 1);
        self.next[idx as usize]
            .and_then(|n| n.lookup(addr, depth+TRIE_BITLEN))
            .or(self.value.clone())
    }
}

pub struct TrieBuf<'a, const LEN: usize> {
    store: [Trie<'a>; LEN],
    ptr: usize,
}

impl<'a, const LEN: usize> TrieBuf<'a, LEN> {
    fn reset(&mut self) {
        self.ptr = 0;
    }

    fn alloc(&'a mut self) -> &'a mut Trie<'a> {
        let ret = &mut self.store[self.ptr];
        self.ptr += 1;
        ret
    }
}