#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <stdatomic.h>

#include "ip.h"
#include "reassembly_store.h"

#define FRAGMENTED(hdr) (((hdr)->flags & MF_MORE_FRAGMENTS) | (hdr)->frag_offset)


/**
 * Given an IpStatus, prints the associated error message.
 * @param s: IpStatus to be decoded.
 */
void ip_error_message(IpStatus s) {
    switch (s) {
        case IP_ERROR: printf("IP: Unspecified error."); break;
        case IP_ERR_INIT: printf("IP: Initialization failed"); break;
        case IP_ERR_TOO_LARGE: printf("IP: Message too large for sending"); break;
        case IP_ERR_OUT_POOL_FULL: printf("IP: Out pool is full - message discarded."); break;
        case IP_MEM_ERR: printf("IP: Memory error"); break;
        case IP_SUCCESS: break;
    }
}

struct {
    atomic_int killed;
    atomic_int kill_confirmed;
    int fd;
} ip;

typedef struct __attribute__((__packed__))
{
    uint32_t saddr;                 // source address
    uint32_t daddr;                 // target address
    uint8_t proto;                  // protocol
} BufId;

typedef struct {
    char data[MTU];
    size_t len;
} ip_packet;

struct {
    pthread_mutex_t lck;
    uint8_t s; //  
    uint8_t e; // points to the
    ip_packet pckts[MAX_MESSAGE_POOL];
} in_pool;

struct {
    pthread_mutex_t lck;
    uint8_t s; //  
    uint8_t e; // points to the
    ip_packet pckts[MAX_MESSAGE_POOL];
} out_pool;

int in_pool_init() {
    int s = 0;
    if ((s = pthread_mutex_init(&in_pool.lck, NULL)) != 0) return s;
    in_pool.s = 0;
    in_pool.e = 0;
    return 0;
}

int out_pool_init() { 
    int s = 0;
    if ((s = pthread_mutex_init(&out_pool.lck, NULL)) != 0) return s;
    out_pool.s = 0;
    out_pool.e = 0;
    return 0;
}

int in_pool_full() {
    return (in_pool.e + 1) % MAX_MESSAGE_POOL == in_pool.s;
}

int in_pool_empty() {
    return in_pool.e == in_pool.s;
}

int out_pool_full() {
    return (out_pool.e + 1) % MAX_MESSAGE_POOL == out_pool.s;
}

int out_pool_empty() {
    return out_pool.e == out_pool.s;
}

/**
 * Add new message to the out_pool. Should only be called by the owner of the out_pool.lock
 * @param IpHeader reference to header of package to be sent
 * @param data reference to the data to be attached to the message.
*/
IpStatus out_pool_append(IpHeader *IpHeader, char *data) {
    if (out_pool_full()) return IP_ERR_OUT_POOL_FULL;
    // get checksum
    char* addr = out_pool.pckts[out_pool.e].data;
    memcpy(addr, (void*)IpHeader, IpHeader->ihl * 4);
    memcpy(addr + IpHeader->ihl * 4, data, IpHeader->len - IpHeader->ihl * 4);

    out_pool.e++; 
    return IP_SUCCESS;
}

/**
 * Pops an element of the out_pool, and prints it on std out. This method should only be used for 
 * testing, as it does not provide any error handling.
 * @param hdr address to which copy the IpHeader data
 * @param data address to which copy the data
*/
void out_pool_pop(IpHeader* hdr, char* data) {
    IpHeader* pckt_hdr = (IpHeader *) out_pool.pckts[out_pool.s].data;
    char* pckt_data = ((char *) out_pool.pckts[out_pool.s].data) + (pckt_hdr->ihl * 4);
    out_pool.s++;

    u_int8_t l = pckt_hdr->len - pckt_hdr->ihl * 4;

    memcpy(hdr, pckt_hdr, pckt_hdr->ihl * 4);
    memcpy(data, pckt_data, l);
}


IpStatus ip_init() {
    atomic_store(&ip.killed, 0);
    atomic_store(&ip.kill_confirmed, 0);

    /*ip.fd = open(TUN_DEV, O_RDWR);
    if (ip.fd < 0) {
        perror("open");
        return IP_CANT_OPEN_UTUN;
    }*/

    if(
           in_pool_init() < 0
        || out_pool_init() < 0
        || ras_init() < 0
    ) { 
        close(ip.fd); 
        atomic_store(&ip.killed, 1);
        return IP_ERR_INIT;
    }
    return IP_SUCCESS;
}

void ip_kill() {
    atomic_store(&ip.killed, 1);
    while(!atomic_load(&ip.kill_confirmed)) usleep(100);
    printf("ip killed");
}

void release() {
    ras_kill();
    atomic_store(&ip.kill_confirmed, 1);
    close(ip.fd);
}

void* traffic_manager() {
    int r_ctr, w_ctr;
    while(!atomic_load(&ip.killed)) {
        r_ctr = 0;
        while(r_ctr < MAX_CONSECUTIVE_READ) {
            if (in_pool_full()) break;
            char* dstn = in_pool.pckts[in_pool.e].data;
            in_pool.e++;
            read(ip.fd, dstn, MTU);
        }

        w_ctr = 0;
        while(w_ctr < MAX_CONSECUTIVE_WRITE) {
            if (out_pool_empty()) break;
            write(ip.fd, out_pool.pckts[out_pool.s].data, out_pool.pckts[out_pool.s].len);
            out_pool.s++;
        }

        usleep(100);
    }

    release();
    return NULL;
}

int check_ipv4(char* buff) {
    if (buff[0] >> 4 == 4) return 1;
    else return 0;
}

int check_ipv6(char* buff) {
    if (buff[0] >> 4 == 6) return 1;
    else return 0;
}

void get_buff_id(IpHeader* hdr, BufId* id) {
    id->saddr = hdr->saddr;
    id->daddr = hdr->daddr;
    id->proto = hdr->proto;
}


/** 
 * This method takes incoming packets form in_pool, logs them in the reassembly store,
 * and if a packet is complete, passes it to the next level. 
 */
void in_traffic_manager() {
    while(!ip.killed) {
        while(!in_pool_empty()) {
            char* packet;

            if (!check_ipv4(packet) && !(check_ipv6(packet))) continue;

            IpHeader* hdr = (IpHeader *)packet;

            // check checksum.

            if (!FRAGMENTED(hdr)) {
                // pass to ip packet queue
                continue;
            }
            RasStatus s;
            if ((s = ras_log(packet)) == RAS_SUCCESS_RE_COMPLETE) {
                IpHeader* cmplt_hdr;                   // These need allocated space...
                char* data;
                ras_get_packet(cmplt_hdr, data);
                // pass to ip packet queue
            } else if (s != RAS_SUCCESS) {
                // report error 
            }
        }
        usleep(100);
    }
}

/**
 * Given a header and data pointer, fragments the packet into smaller packets that have smaller size then
 * the MTU.
 * @param hdr header containing all 'routing information'.
 * @param payload_start pointer to the data chunk associated with the header.
 */
IpStatus queue_for_sending(IpHeader* hdr, char* payload_start) {

    IpStatus s;

    if (hdr->len < MTU) {
        pthread_mutex_lock(&out_pool.lck);
        if ((s = out_pool_append(hdr, payload_start)) != IP_SUCCESS)
            return s;
        pthread_mutex_unlock(&out_pool.lck);
        return IP_SUCCESS;
    }

    if ((hdr->flags & DF_DO_NOT_FRAGMENT) != 0) return IP_ERR_TOO_LARGE; // packet too large but can't be fragmented.

    int data_len = hdr->len - hdr->ihl * 4;     // total number of octets of data
    int nfb = (MTU - hdr->ihl * 4) / 8;         // number of 8 octet blocks per fragment
    int total_fragments = data_len / (nfb * 8); // total number of fragments
    int leftover = data_len % (nfb * 8);        // number of octets in the last fragment

    hdr->len = (hdr->ihl * 4) + (nfb * 8);      // new fragment size.
    SET_MORE_FRAGMENTS(hdr);                    // set more_fragments flag to true

    int i; 
    pthread_mutex_lock(&out_pool.lck);
    for (i = 0; i < total_fragments; i++) {
        hdr->frag_offset = i * nfb;
        if ((s = out_pool_append(hdr, payload_start + i * nfb * 8)) != IP_SUCCESS)
            return s;
    }
        
    hdr->len = (hdr->ihl * 4) + data_len % (nfb * 8);
    SET_LAST_FRAGMENT(hdr);
    hdr->frag_offset = i * nfb;
    if ((s = out_pool_append(hdr, payload_start + i * nfb * 8)) != IP_SUCCESS)
        return s;
    pthread_mutex_unlock(&out_pool.lck);

    return IP_SUCCESS;
}

/**
 * Given a header and data block, prints the content of the packet in human readable form.
 * @param hdr header of the packet
 * @param data pointer to the data associated to the header.
 */
void print_packet(IpHeader* hdr, char* data) {
    printf("---Packet start---\n");
    printf("version             : %i\n", hdr->ver);
    printf("inet header length  : %i\n", hdr->ihl);
    printf("Type of service     : %i\n", hdr->tos);
    printf("Total length        : %i\n", hdr->len);
    printf("Identification      : %i\n", hdr->id);
    printf("Flags               : 0%i%i\n", hdr->flags & DF_DO_NOT_FRAGMENT, hdr->flags & MF_MORE_FRAGMENTS);
    printf("Fragment offset     : %i\n", hdr->frag_offset);
    printf("Time to Live        : %i\n", hdr->ttl);
    printf("Protocol            : %i\n", hdr->proto);
    printf("Header cheksum      : %i\n", hdr->csum);
    printf("Source addr:        : %i\n", hdr->saddr);
    printf("Target addr:        : %i\n", hdr->daddr);
    printf("Payload:\n");
    int payload_len = hdr->len - hdr->ihl * 4;
    for (int i = 0; i < payload_len; i++) {
        printf("%c", data[i]);
        if ((i+1) % 8 == 0) printf("\n");
    }
    printf("---Packet end---\n");
}