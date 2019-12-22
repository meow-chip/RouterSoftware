#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t in_addr_t;
typedef uint8_t macaddr_t[6];

const in_addr_t multicasting_ip = 0x090000e0;
macaddr_t multicasting_mac;

#define RIP_MAX_ENTRY 25
#define TABLE_MAX_ITEM 1000
#define PACKET_MAX_LENGTH 2048

uint32_t addrs[4]; // should know this
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
    uint8_t addr[4];
    uint8_t nexthop[4];
    uint8_t len;
    uint8_t metric;
    uint8_t if_index;
} RoutingTableEntry;

#define min(a, b) ((a) < (b) ? a : b)

void hprint_char(char c) {
    volatile uint8_t * SERIAL_BASE = (uint8_t *) 0xFFFF00000000llu;
    *(SERIAL_BASE + 0x4) = c;
    while(true) {
        uint8_t status = *(SERIAL_BASE + 8);
        bool fifo_empty = (status & 0b100) != 0;

        if(fifo_empty) {
            return;
        }
    }
}

void hprint_dec(uint64_t input) {
    if(input == 0) {
        hprint_char('0');
        return;
    }

    char buf[20];
    int ptr = 0;
    while(input) {
        buf[ptr] = '0' + (input % 10);
        input /= 10;
        ++ptr;
    }

    for(int i = ptr-1; i >= 0; --i) hprint_char(buf[i]);
}

void hprint(const char *str) {
    while(*str) hprint_char(*str++);
}

void write_u32(uint8_t *ptr, uint32_t data) {
    *ptr = data;
    *(ptr + 1) = data >> 8;
    *(ptr + 2) = data >> 16;
    *(ptr + 3) = data >> 24;
}

uint32_t read_u32(const uint8_t *ptr) {
    return *ptr
        | (*(ptr+1)) << 8
        | (*(ptr+2)) << 16
        | (*(ptr+3)) << 24;
}

extern "C" {
    /**
     * @brief 接收一个 IP 报文
     *
     * @param packet 实际接收的报文
     * @param length 实际接收的报文长度
     * @param src_mac IPv4 报文下层的来源 MAC 地址
     * @param if_index 实际接收到的报文来源的接口号
     * @return int 0 表示成功，非 0 为失败
     */
    uint64_t Meow_ReceiveIPPacket(uint8_t *packet, size_t length, macaddr_t src_mac, int if_index, RoutingTableEntry *tbl, uint64_t tblsize);

    /**
     * @brief 发送一个 IP 报文
     *
     * @param buffer 发送缓冲区
     * @param length 待发送报文的长度
     * @param if_index 实际发送报文的接口号
     * @param dst_mac IPv4 报文下层的目的 MAC 地址
     * @return int 0 表示成功，非 0 为失败
     */
    uint64_t Meow_SendIPPacket(uint8_t *buffer, size_t length, uint8_t if_index, macaddr_t dst_mac);

    /**
     * @brief 定时器过期时触发
     *
     * @param usec IN，当前时刻
     * @return int 0 表示成功，非 0 为失败
     */
    uint64_t Meow_PerSec(uint64_t usec, RoutingTableEntry *tbl, uint64_t tblsize);

    /**
     * @brief 初始化
     * 
     * @param mem IN，内存池地址
     * @param usec IN，当前时刻
     * @return int 0 表示成功，非 0 为失败
     */
    int Meow_Init(uint64_t usec);

    bool Meow_Update(bool insert, RoutingTableEntry *entry);

    inline uint32_t ip_serialize(uint8_t ip[4]) {
        return ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
    } 
    
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

    uint16_t identification;

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
        write_u32(packet+12, src); // src ip
        write_u32(packet+16, dst); // dst ip
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
                write_u32(packet + len + 4, rip->entries[i].addr); // ip address
                write_u32(packet + len + 8, rip->entries[i].mask); // mask
                write_u32(packet + len + 12, rip->entries[i].nexthop); // nexthop
                write_u32(packet + len + 16, rip->entries[i].metric << 24); // metric
                len += 20;
            }
        }
    }

    uint8_t mask_to_len(uint32_t mask) {
        uint8_t len = 0;
        for (int i = 4; i >= 0; i--) {
            if ((mask & ((1 << (1 << i)) - 1)) == ((1 << (1 << i)) - 1)) {
                len += (1 << i); 
            }
            mask >>= (1 << i);
        }
        return len + (uint8_t)mask;
    }

    RoutingTableEntry toRoutingTableEntry(RipEntry *p, int if_index) {
        RoutingTableEntry entry = {
            .len = mask_to_len(p->mask),
            .metric = (uint8_t)p->metric,
            .if_index = (uint8_t)if_index,
        };

        for(int i = 0; i< 4; ++i) {
            entry.addr[i] = p->addr >> (i * 8);
        }

        for(int i = 0; i< 4; ++i) {
            entry.nexthop[i] = p->nexthop >> (i * 8);
        }

        return entry;
    }

    inline uint32_t len_to_mask(int len) {
        return (uint32_t)(((uint64_t)(1) << len) - 1);
    }

    inline void broadtable(RipPacket *p, uint8_t if_index, uint32_t &res, RoutingTableEntry* tbl, uint64_t tblsize) {
        p->command = 0x2;
        p->numEntries = min(tblsize- res, RIP_MAX_ENTRY);
        for (uint32_t i = res; i < res + p->numEntries; i++) {
            p->entries[i - res] = {
                .addr = ip_serialize(tbl[i].addr),
                .mask = len_to_mask(tbl[i].len),
                .nexthop = ip_serialize(tbl[i].nexthop),
                .metric = (uint32_t)(if_index != tbl[i].if_index ? tbl[i].metric + 1 : 16)
            };
        }
        res += p->numEntries;
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
        if (output->numEntries > RIP_MAX_ENTRY) return false;
        if (packet[28] != 1 && packet[28] != 2) return false;
        if (packet[29] != 2) return false;
        for (int i = 0; i < (len - 32) / 20; i++) {
            output->entries[i].addr = read_u32(packet + 32 + i * 20 + 4);
            output->entries[i].mask = read_u32(packet + 32 + i * 20 + 8);
            if (count_bit(output->entries[i].mask + 1) > 1) return false;
            output->entries[i].nexthop = read_u32(packet + 32 + i * 20 + 12);
            output->entries[i].metric = read_u32(packet + 32 + i * 20 + 16);
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

    void Meow_AddInterface(uint32_t addr) {
        addrs[N_IFACE_ON_BOARD] = addr;

        RipPacket p;
        require(&p);
        RIPAssemble(output + 20 + 8, out_len = 0, &p);
        UDPHeaderAssemble(output + 20, out_len, 520, 520);
        IPHeaderAssemble(output, out_len, addrs[N_IFACE_ON_BOARD], multicasting_ip);
        Meow_SendIPPacket(output, out_len, N_IFACE_ON_BOARD, multicasting_mac);

        N_IFACE_ON_BOARD++;
    }

    int Meow_Init(uint64_t usec) {
        now = usec;

        multicasting_mac[0] = 0x01;
        multicasting_mac[1] = 0x00;
        multicasting_mac[2] = 0x5e;
        multicasting_mac[3] = 0x00;
        multicasting_mac[4] = 0x00;
        multicasting_mac[5] = 0x09;
        identification = 0x4c80;
        N_IFACE_ON_BOARD = 0;
        return 0;
    }

    uint64_t Meow_PerSec(uint64_t usec, RoutingTableEntry *tbl, uint64_t tblsize) {
        if (now + 5 * 1000 * 1000 < usec) { // timeout
            hprint_char('B');
            hprint_char('\n');
            hprint_char('\r');

            for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
                RipPacket p;
                uint32_t res = 0;
                while (res < tblsize) {
                    broadtable(&p, i, res, tbl, tblsize);
                    RIPAssemble(output + 20 + 8, out_len = 0, &p);
                    UDPHeaderAssemble(output + 20, out_len, 520, 520);
                    IPHeaderAssemble(output, out_len, addrs[i], multicasting_ip);
                    Meow_SendIPPacket(output, out_len, i, multicasting_mac);
                }
            }
            now = usec;
        }
        return 0;
    }

    uint64_t Meow_ReceiveIPPacket(uint8_t *packet, size_t length, macaddr_t src_mac, int if_index, RoutingTableEntry *tbl, uint64_t tblsize) { // legal
        // FIXME: IP checksum
        in_addr_t src_addr = read_u32(packet + 12);
        in_addr_t dst_addr = read_u32(packet + 16);

        RipPacket rip;
        if (disassemble((uint8_t *)packet, length, &rip)) {
            if (rip.command == 1) { // receive a request packet
                RipPacket p;
                uint32_t res = 0;
                while (res < tblsize) {

                    broadtable(&p, if_index, res, tbl, tblsize);
                    RIPAssemble(output + 20 + 8, out_len = 0, &p);
                    UDPHeaderAssemble(output + 20, out_len, 520, 520);
                    IPHeaderAssemble(output, out_len, addrs[if_index], src_addr);
                    Meow_SendIPPacket(output, out_len, if_index, src_mac);
                }
                // TODO: set a flag, wait for response
            } else {  // receive a response packet
                RipPacket p;
                p.command = 0x2;
                p.numEntries = 0;
                for (int i = 0; i < rip.numEntries; i++) if (rip.entries[i].metric < 16) { // TODO: Poison
                    RoutingTableEntry record = toRoutingTableEntry(&rip.entries[i], if_index);
                    if (Meow_Update(true, &record)) {
                        p.entries[p.numEntries++] = {
                            .addr = ip_serialize(record.addr) & len_to_mask(record.len),
                            .mask = len_to_mask(record.len),
                            .nexthop = ip_serialize(record.nexthop),
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
}