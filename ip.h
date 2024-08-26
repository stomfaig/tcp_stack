#include <stdint.h>

#ifndef IP
#define IP

#define MTU 50

#define MAX_MESSAGE_POOL 100
#define TUN_DEV "/dev/tun0"

#define MAX_CONSECUTIVE_READ    20
#define MAX_CONSECUTIVE_WRITE   20

#define MAX_OUT_POOL_OCCUPY_CYCLES = 30

/* Types of service */

// Precedence 
#define PR_NETWORK_CONTROL  0b11100000
#define PR_INETWORK_CONTROL 0b11000000
#define PR_CRITIC_ECP       0b10100000
#define PR_FLASH_OVERRIDE   0b10000000
#define PR_FLASH            0b00100000
#define PR_IMMEDIATE        0b01000000
#define PR_PRIORITY         0b00100000
#define PR_ROUTINE          0b00000000

// Delay
#define D_NORMAL            0
#define D_LOW               0b00010000

// Throughput
#define T_NORMAL            0
#define T_HIGH              0b00001000

// Reliability
#define R_NORMAL            0
#define R_HIGH              0b00000100

/* Flags */

// Fragmentation
#define DF_MAY_FRAGMENT     0
#define DF_DO_NOT_FRAGMENT  0b010

// Last fragment?
#define MF_LAST_FRAGMENT    0
#define MF_MORE_FRAGMENTS   0b001

#define SET_LAST_FRAGMENT(hdr) ((hdr)->flags &= ~MF_MORE_FRAGMENTS)
#define SET_MORE_FRAGMENTS(hdr) ((hdr)->flags |= MF_MORE_FRAGMENTS)

// IP Error messages
#define IP_SEND_OK          0
#define IP_CANT_OPEN_UTUN   1

int check_ipv4(char* buff);
int check_ipv6(char* buff);

typedef struct __attribute__((__packed__))
{
    uint8_t ver : 4;                // ip version
    uint8_t ihl : 4;                // header length in 32bit words
    uint8_t tos;                    // type of service
    uint16_t len;                   // total length (header + data) in octets
    uint16_t id;                    // 
    uint16_t flags : 3;             //
    uint16_t frag_offset : 13;      //
    uint8_t ttl;                    //
    uint8_t proto;                  //
    uint16_t csum;                  //
    uint32_t saddr;                 //
    uint32_t daddr;                 //
} iphdr;

typedef struct {
    iphdr iphdr;
    char payload[MTU-sizeof(iphdr)];
} ippckt;

int ip_init();
void* traffic_manager();
void ip_kill();
int queue_for_sending(iphdr* hdr, char* payload_start);

#ifdef DEBUG_INFO_ENABLED

void release();
void print_packet(iphdr* hdr, char* data);
void out_pool_pop();

#endif
#endif