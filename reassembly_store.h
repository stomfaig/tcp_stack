#ifndef RAS
#define RAS

#include "ip.h"

#define MIN_PACKET_SIZE 100 // Allows storing 100 octets of data.

typedef enum {
    MEM_ERR,
    SUCCESS,
    SUCCESS_RE_COMPLETE,
} ras_status;

char* ras_error(ras_status s);

ras_status ras_init();
void ras_kill();
ras_status ras_log(char* packet);
ras_status ras_get_packet(iphdr* hdr);

#endif