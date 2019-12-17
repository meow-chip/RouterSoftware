#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t in_addr_t;
typedef uint8_t macaddr_t[6];

/**
 * @brief 从 ARP 表中查询 IPv4 对应的 MAC 地址
 *
 * 如果是表中不存在的IP，系统将自动发送 ARP
 * 报文进行查询，待对方主机回应后可重新调用本接口从表中查询 部分后端会限制发送的
 * ARP 报文数量，如每秒向同一个主机最多发送一个 ARP 报文
 *
 * @param if_index IN，接口索引号，[0, N_IFACE_ON_BOARD-1]
 * @param ip IN，要查询的 IP 地址
 * @param o_mac OUT，查询结果 MAC 地址
 * @return int 0 表示成功，非 0 为失败
 */
int Meow_ArpGetMacAddress(int if_index, in_addr_t ip, macaddr_t o_mac);

/**
 * @brief 接收一个 IP 报文
 *
 * @param packet 实际接收的报文
 * @param length 实际接收的报文长度
 * @param src_mac IPv4 报文下层的来源 MAC 地址
 * @param if_index 实际接收到的报文来源的接口号
 * @return int 0 表示成功，非 0 为失败
 */
int Meow_ReceiveIPPacket(uint8_t *packet, size_t length, macaddr_t src_mac, int if_index);

/**
 * @brief 发送一个 IP 报文
 *
 * @param buffer 发送缓冲区
 * @param length 待发送报文的长度
 * @param if_index 实际发送报文的接口号
 * @param dst_mac IPv4 报文下层的目的 MAC 地址
 * @return int 0 表示成功，非 0 为失败
 */
int Meow_SendIPPacket(uint8_t *buffer, size_t length, int if_index, macaddr_t dst_mac);

/**
 * @brief 定时器过期时触发
 *
 * @param usec IN，当前时刻
 * @return int 0 表示成功，非 0 为失败
 */
int Meow_PerSec(uint64_t usec);

/**
 * @brief 初始化
 * 
 * @param mem IN，内存池地址
 * @param usec IN，当前时刻
 * @return int 0 表示成功，非 0 为失败
 */
int Meow_Init(void *mem, uint64_t usec);

in_addr_t multicasting_ip = 0x090000e0;
macaddr_t multicasting_mac = {0x01, 0, 0x5e, 0, 0, 0x09};

#define RIP_MAX_ENTRY 25
#define TABLE_MAX_ITEM 1000
#define PACKET_MAX_LENGTH 2048

in_addr_t* addrs; // should know this
uint32_t N_IFACE_ON_BOARD; // should know this

typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
} RipEntry;

typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command;
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
} RipPacket;

typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t if_index;
    uint32_t nexthop;
    uint32_t metric;
} RoutingTableEntry;

RoutingTableEntry table[TABLE_MAX_ITEM];
uint32_t table_num = 0;

inline uint16_t change_endian_16(uint16_t a) {
    return ((a & 0xff00) >> 8) + ((a & 0xff) << 8);
}

inline uint16_t HeaderChecksum(uint16_t *packet, int len) {
    uint32_t checksum = 0;
    for (int i = 0; i < len; i++)
        checksum += packet[i];
    while (checksum >= (1 << 16))
        checksum = checksum % (1 << 16) + checksum / (1 << 16);
    return ~(checksum % (1 << 16));
}

uint16_t identification = 0x4c80;

inline void IPHeaderAssemble(uint8_t *packet, uint32_t &len, uint32_t src, uint32_t dst) {
    packet[0] = 0x45; // Version & Header length
    packet[1] = 0xc0; // ToS
    *(uint16_t *)(packet+2) = change_endian_16(len += 20);
    *(uint16_t *)(packet+4) = (identification += len); // ID
    // *(uint16_t *)(packet+4) = 0x22e7; // ID
    *(uint16_t *)(packet+6) = 0; // Flagment
    packet[8] = 1; // TTL
    packet[9] = 0x11; // Protocol: UDP:0x11 TCP:0x06 ICMP:0x01
    *(uint16_t *)(packet+10) = 0; // checksum
    *(uint32_t *)(packet+12) = src; // src ip
    *(uint32_t *)(packet+16) = dst; // dst ip
    *(uint16_t *)(packet+10) = HeaderChecksum((uint16_t *)packet, 20 / 2);
}

inline void UDPHeaderAssemble(uint8_t *packet, uint32_t &len, uint16_t sport, uint16_t dport) { // 520, 520
    *(uint16_t *)(packet+0) = change_endian_16(sport); // src port
    *(uint16_t *)(packet+2) = change_endian_16(dport); // dst port
    *(uint16_t *)(packet+4) = change_endian_16(len += 8);
    *(uint16_t *)(packet+6) = 0;
}

inline void RIPAssemble(uint8_t *packet, uint32_t &len, const RipPacket *rip) {
    packet[0] = rip->command; // command: request:1 response:2
    packet[1] = 0x02; // version
    packet[2] = packet[3] = 0; // unused
    len = 4;
    if (rip->command == 0x1) {
        *(packet + len + 19) = 16;
        len += 20;
    } else if (rip->command == 0x2) {
        for (int i = 0; i < rip->numEntries; i++) {
            *(uint16_t *)(packet + len + 0) = change_endian_16(2); // address family: IP:0x02
            *(uint16_t *)(packet + len + 2) = change_endian_16(0); // route rag
            *(uint32_t *)(packet + len + 4) = rip->entries[i].addr; // ip address
            *(uint32_t *)(packet + len + 8) = rip->entries[i].mask; // mask
            *(uint32_t *)(packet + len + 12) = rip->entries[i].nexthop; // nexthop
            *(uint32_t *)(packet + len + 16) = rip->entries[i].metric << 24; // metric
            len += 20;
        }
    }
}

int mask_to_len(uint32_t mask) {
    int len = 0;
    for (int i = 4; i >= 0; i--) {
        if ((mask & ((1 << (1 << i)) - 1)) == ((1 << (1 << i)) - 1)) {
            len += (1 << i); 
        }
        mask >>= (1 << i);
    }
    return mask + len;
}

RoutingTableEntry toRoutingTableEntry(RipEntry *p, int if_index) {
    RoutingTableEntry entry = {
        .addr = p->addr,
        .len = (uint32_t)mask_to_len(p->mask),
        .if_index = (uint32_t)if_index,
        .nexthop = p->nexthop,
        .metric = p->metric
    };
    return entry;
}

inline bool update(bool insert, RoutingTableEntry entry) {
    for (int i = 0; i < table_num; i++) {
        if (table[i].addr == entry.addr && table[i].len == entry.len) {
            if (insert) {
                if (entry.metric < table[i].metric) {
                    table[i] = entry;
                } else return false;
            } else {
                table[i--] = table[--table_num];
            }
            return true;
        }
    }
    if (insert) {
        table[table_num++] = entry;
    }
    return true;
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    RoutingTableEntry entry;
    entry.len = 0;
    bool fg = false;
    for (int i = 0; i < table_num; i++) {
        if ((table[i].addr << (32 - table[i].len)) == (addr << (32 - table[i].len))) {
        if (table[i].len > entry.len) {
            entry = table[i];
            fg = true;
        }
        }
    }
    *nexthop = entry.nexthop;
    *if_index = entry.if_index;
    return fg;
}

bool forward(uint8_t *packet, size_t len) {
    if (HeaderChecksum((uint16_t *)packet, len) == false)
        return false;
    packet[8] -= 1;
    uint32_t checksum = 0;
    for (int i = 0; i < (packet[0] & 0xF) * 2; i++) if (i != 5)
        checksum += ((uint16_t *)packet)[i];
    while (checksum >= (1 << 16))
        checksum = checksum % (1 << 16) + checksum / (1 << 16);
    ((uint16_t *)packet)[5] = (1 << 16) - 1 - checksum;
    return true;
}

inline uint32_t len_to_mask(int len) {
  return (uint32_t)(((uint64_t)(1) << len) - 1);
}

inline void broadtable(RipPacket *p, int if_index) {
    p->command = 0x2;
    p->numEntries = table_num;
    for (int i = 0; i < table_num; i++) {
        p->entries[i] = {
            .addr = table[i].addr,
            .mask = len_to_mask(table[i].len),
            .nexthop = table[i].nexthop,
            .metric = (if_index != table[i].if_index ? table[i].metric + 1 : 16)
        };
    }
}

inline uint32_t count_bit(uint32_t a) {
    a = (a & 0x55555555) + ((a & 0xaaaaaaaa) >> 1);
    a = (a & 0x33333333) + ((a & 0xcccccccc) >> 2);
    a = (a & 0x0f0f0f0f) + ((a & 0xf0f0f0f0) >> 4);
    a = (a & 0x00ff00ff) + ((a & 0xff00ff00) >> 8);
    a = (a & 0x0000ffff) + ((a & 0xffff0000) >> 16);
    return a;
}

inline bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    if ((len - 32) % 20 != 0) return false;
    output->numEntries = (len - 32) / 20;
    if (packet[28] != 1 && packet[28] != 2) return false;
    if (packet[29] != 2) return false;
    for (int i = 0; i < (len - 32) / 20; i++) {
        output->entries[i].addr = *(uint32_t *)(packet + 32 + i * 20 + 4);
        output->entries[i].mask = *(uint32_t *)(packet + 32 + i * 20 + 8);
        if (count_bit(output->entries[i].mask + 1) > 1) return false;
        output->entries[i].nexthop = *(uint32_t *)(packet + 32 + i * 20 + 12);
        output->entries[i].metric = *(uint32_t *)(packet + 32 + i * 20 + 16);
        if (output->entries[i].metric & 0xffffff) return false;
        if ((output->entries[i].metric >> 24) < 0x01 ||
            (output->entries[i].metric >> 24) > 0x10) return false;
        output->entries[i].metric >>= 24;
    }
    output->command = packet[28];
    return true;
}

inline void require(RipPacket *p) {
    p->command = 0x1;
    p->numEntries = 1;
    p->entries[0] = {
        .addr = 0,
        .mask = 0,
        .nexthop = 0,
        .metric = 16
    };
}

uint64_t now; // clock
uint8_t output[PACKET_MAX_LENGTH];
uint32_t out_len;
void *mem;

int Meow_Init(void *pool, uint64_t usec) {
    // TODO: get IFACE addrs, N_IFACE_ON_BOARD
    mem = pool;
    for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
            .addr = addrs[i], // big endian
            .len = 24,        // small endian
            .if_index = i,    // small endian
            .nexthop = 0,     // big endian, means direct
            .metric = 0
        };
        update(true, entry);
    }
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        RipPacket p;
        require(&p);
        RIPAssemble(output + 20 + 8, out_len = 0, &p);
        UDPHeaderAssemble(output + 20, out_len, 520, 520);
        IPHeaderAssemble(output, out_len, addrs[i], multicasting_ip);
        Meow_SendIPPacket(output, out_len, i, multicasting_mac);
    }
    now = usec;
    return 0;
}

int Meow_PerSec(uint64_t usec) {
    if (now > usec + 5 * 1000) { // timeout
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            RipPacket p;
            broadtable(&p, i);
            RIPAssemble(output + 20 + 8, out_len = 0, &p);
            UDPHeaderAssemble(output + 20, out_len, 520, 520);
            IPHeaderAssemble(output, out_len, addrs[i], multicasting_ip);
            Meow_SendIPPacket(output, out_len, i, multicasting_mac);
        }
        now = usec;
    }
    return 0;
}
int Meow_ReceiveIPPacket(uint8_t *packet, size_t length, macaddr_t src_mac, int if_index) { // legal
    // FIXME: IP checksum
    in_addr_t src_addr = *(in_addr_t *)(packet + 12);
    in_addr_t dst_addr = *(in_addr_t *)(packet + 16);

    RipPacket rip;
    if (disassemble((uint8_t *)packet, length, &rip)) {
        if (rip.command == 1) { // receive a request packet
            RipPacket p;
            broadtable(&p, if_index);
            RIPAssemble(output + 20 + 8, out_len = 0, &p);
            UDPHeaderAssemble(output + 20, out_len, 520, 520);
            IPHeaderAssemble(output, out_len, addrs[if_index], src_addr);
            Meow_SendIPPacket(output, out_len, if_index, src_mac);
            // TODO: set a flag, wait for response
        } else {  // receive a response packet
            RipPacket p;
            p.command = 0x2;
            p.numEntries = 0;
            for (int i = 0; i < rip.numEntries; i++) if (rip.entries[i].metric < 16) { // TODO: Poison
                RoutingTableEntry record = toRoutingTableEntry(&rip.entries[i], if_index);
                if (update(true, record)) {
                    p.entries[p.numEntries++] = {
                        .addr = record.addr & len_to_mask(record.len),
                        .mask = len_to_mask(record.len),
                        .nexthop = record.nexthop,
                        .metric = 16
                    };
                }
            }
            if (p.numEntries > 0) {
                RIPAssemble(output + 20 + 8, out_len = 0, &p);
                UDPHeaderAssemble(output + 20, out_len, 520, 520);
                IPHeaderAssemble(output, out_len, addrs[if_index], src_addr);
                Meow_SendIPPacket(output, out_len, if_index, src_mac);
            }
        }
    } else {
        // wrong packet, ignore
    }
    return 0;
}