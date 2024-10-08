#include <stdint.h>

#include "ip.h"

typedef enum {
    TCP_SUCCESS,
    TCP_ERR,                        // General error
    TCP_ERR_UNKWN_COMMAND,          // A TCP state machine command was received that is not recognized.
    TCP_ERR_PORT_CLOSED,            // A packet was received, but there associated port is closed.
    TCP_ERR_UNEXPECTED_MESSAGE,     // The state machine received an unexpected message.
    TCP_ERR_ACK_FAILED,             
} TcpStatus;

typedef enum {
    TCP_PASSIVE_OPEN,
    TCP_ACTIVE_OPEN,
    TCP_SEND,
    TCP_RECEIVE,
    TCP_CLOSE,
    TCP_ABORT,
    TCP_STATUS,
} TcpCommand;

typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_SYN_SENT,
    TCP_ESTAB,
    TCP_FINWAIT_1,
    TCP_FINWAIT_2,
    TCP_CLOSING,
    TCP_TIMEWAIT,
} TcpState

#define TCP_URG 0b100000
#define TCP_ACK 0b010000
#define TCP_PSH 0b001000
#define TCP_RST 0b000100
#define TCP_SYN 0b000010
#define TCP_FIN 0b000001

#define SET_FLAG(hdr, flag) ((hdr)->flags |= flag)
#define UNSET_FLAG(hdr, flag) ((hdr)->flags &= ~flag)

#define CHECK_FLAG(hdr, flag) ((hdr)->flags & flag)


typedef struct __attribute__((__packed__))
{
    uint16_t s_port;                // source port
    uint16_t d_port;                // destination port
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset : 4;
    uint8_t reserved : 6;
    uint8_t flags : 6;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    // options // padding
    // 
} TcpHeader;

void store_packet(IpHeader* hdr, char* data);

