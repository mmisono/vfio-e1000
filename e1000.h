#pragma once

#include <sys/types.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#define CTRL_ 0x00
#define CTRL_FD 1
#define CTRL_LRST 1 << 3  // reserved
#define CTRL_ASDE 1 << 5
#define CTRL_SLU 1 << 6
#define CTRL_ILOS 1 << 7  // reserved
#define CTRL_RST 1 << 26
#define CTRL_VME 1 << 30
#define CTRL_PHY_RST 1 << 31

#define STATUS 0x08

// Flow Control Address
#define FCAL 0x28
#define FCAH 0x2C
// Flow Control Type
#define FCT 0x30
// Flow Control Transmit Timer Value
#define FCTTV 0x170

// Interrupt Cause Read Regisetr
#define ICR 0xC0

// Interrupt Mask Set/Read Regisetr
#define IMS 0xD0
#define IMS_TXDW 1
#define IMS_TXQE 1 << 1
#define IMS_LSC 1 << 2
#define IMS_RXSEQ 1 << 3
#define IMS_RXDMT 1 << 4
#define IMS_RXO 1 << 6
#define IMS_RXT 1 << 7
#define IMS_RXQ0 1 << 20
#define IMS_RXQ1 1 << 21
#define IMS_TXQ0 1 << 22
#define IMS_TXQ1 1 << 23
#define IMS_OTHER 1 << 24

// Interrupt Mask Clear Register
#define IMC 0xD8

// Interrupt Vector Allocation Registers (for MSI-X)
#define IVAR 0x000E4
#define IVAR_RXQ0_VEC_SHIFT 0
#define IVAR_EN_RXQ0 1 << 3
#define IVAR_RXQ1_VEC_SHIFT 4
#define IVAR_EN_RXQ1 1 << 7
#define IVAR_TXQ0_VEC_SHIFT 8
#define IVAR_EN_TXQ0 1 << 11
#define IVAR_TXQ1_VEC_SHIFT 12
#define IVAR_EN_TXQ1 1 << 15
#define IVAR_OTHER_VEC_SHIFT 16
#define IVAR_EN_OTHER 1 << 19

// 3GIO Control Register
#define GCR 0x05B00

// Receive control
#define RCTL 0x100
#define RCTL_EN 1 << 1
#define RCTL_UPE 1 << 3
#define RCTL_MPE 1 << 4
#define RCTL_LPE 1 << 5
#define RCTL_LBM 1 << 6 | 1 << 7
#define RCTL_BAM 1 << 15
#define RCTL_BSIZE1 1 << 16
#define RCTL_BSIZE2 1 << 17
#define RCTL_BSEX 1 << 25
#define RCTL_SECRC 1 << 26

// Receive Descriptor Control
#define RXDCTL 0x02828

// Transmit Control
#define TCTL 0x400
#define TCTL_EN 1 << 1
#define TCTL_PSP 1 << 3

// Receive Descriptor Base Address
#define RDBAL 0x2800
#define RDBAH 0x2804
// Receive Descriptor Length
#define RDLEN 0x2808
#define RDH 0x2810
#define RDT 0x2818

// Transmit Descriptor Base Address
#define TDBAL 0x3800
#define TDBAH 0x3804
// Transmit Descriptor Length
#define TDLEN 0x3808
#define TDH 0x3810
#define TDT 0x3818

// Transmit Interrupt Delay Value
#define TIDV 0x3820

// Receive Address (MAC address)
#define RAL0 0x5400
#define RAH0 0x5404

// some statistics register
#define MPC 0x4010    // Missed Packets Count
#define GPRC 0x4074   // Good Packets Received Counts
#define GPTC 0x4080   // Good Packets Transmitted Count
#define GORCL 0x4088  // Good Octets Received Count
#define GORCH 0x408C
#define GOTCL 0x4088  // Good Octets Transmitted Count
#define GOTCH 0x408C
#define RXERRC 0x400C

// legacy descriptor
struct rdesc {
    u64 buffer;  // buffer address
    u16 length;
    u16 checksum;
    union {
        u8 status;
        struct {
            u8 dd : 1;     // descriptor done
            u8 eop : 1;    // end of packet
            u8 ixsm : 1;   //  ignore checksum indication
            u8 vp : 1;     // 802.1Q
            u8 udpcs : 1;  // UDP checksum calculated
            u8 tcpcs : 1;  // TCP checksum calculated
            u8 ipcs : 1;   // IPv4 checksum calculated
            u8 pif : 1;    // passed in-exact filter
        };
    };
    union {
        u8 error;
        struct {
            u8 ce : 1;    // CRC error
            u8 se : 1;    // symbol error
            u8 seq : 1;   // sequence error
            u8 rcv : 2;   // reserved
            u8 tcpe : 1;  // TCP/UDP checksum error
            u8 ipe : 1;   // IPv4 checksum error
            u8 rxe : 1;   // RX data error
        };
    };
    u16 vlantag;  // VLAN tag
} __attribute__((packed));

struct tdesc {
    u64 buffer;  // buffer address
    u16 length;
    u8 cso;  // checksum offset
    union {
        u8 command;
        struct {
            u8 eop : 1;   // end of packet
            u8 ifcs : 1;  // insert FCS
            u8 ic : 1;    // insert checksum
            u8 rs : 1;    // report status
            u8 rsv : 1;   // reserved
            u8 dext : 1;  // extension
            u8 vle : 1;   // VLAN packet enable
            u8 ide : 1;   // interrupt delay enable
        };
    };
    union {
        u8 status;
        struct {
            u8 dd : 1;    // descriptor done
            u8 ec : 1;    // excess collisions
            u8 lc : 1;    // late collisions
            u8 rsv2 : 5;  // reserved
        };
    };
    u8 css;       // checksum start
    u16 special;  // special field
} __attribute__((packed));

#define MAX_MSIX_VECTOR_NUM 5
