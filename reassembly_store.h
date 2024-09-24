#ifndef RAS
#define RAS

#include "ip.h"

#define MIN_PACKET_SIZE 100 // Allows storing 100 octets of data.

typedef enum {
    RAS_ERROR,                      // Generic error value
    RAS_MEM_ERR,                    // Error related to allocating memory
    RAS_ERR_PACKET_NOT_COMPLETE,    // Error reported when ras_get_packet called on a not complete packet
    RAS_ERR_PACKET_NOT_FOUND,       // Error reported when ras_get_packet is called with a header that doesn't match any streams
    RAS_SUCCESS,                    // Returned if the operation was successful
    RAS_SUCCESS_RE_COMPLETE,        // Returned when the packet with which ras_log was called completed the packet
    
} RasStatus;

void ras_error_message(RasStatus s);

RasStatus ras_init();
void ras_kill();
RasStatus ras_log(char* packet);
RasStatus ras_get_packet(IpHeader* hdr, char* data);

#ifdef DEBUG_INFO_ENABLED

#endif

#endif