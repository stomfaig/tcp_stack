#include <stdint.h>

int check_ipv4(char* buff);
int check_ipv6(char* buff);

#define MTU 2048

#define MAX_MESSAGE_POOL 100
#define TUN_DEV "/dev/tun0"

#define MAX_CONSECUTIVE_READ    20
#define MAX_CONSECUTIVE_WRITE   20

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


typedef struct //need to make this dense...
{
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
} iphdr __attribute__((packed));

typedef struct {
    iphdr iphdr;
    char payload[MTU-sizeof(iphdr)];
} ippckt;

int ip_init();