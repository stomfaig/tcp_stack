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
} buf_id;

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
    pthread_mutex_init(&in_pool.lck, NULL);
    in_pool.s = 0;
    in_pool.e = 0;
}

int out_pool_init() { 
    pthread_mutex_init(&out_pool.lck, NULL);
    out_pool.s = 0;
    out_pool.e = 0;
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
 * @param iphdr reference to header of package to be sent
 * @param data reference to the data to be attached to the message.
*/
int out_pool_append(iphdr *iphdr, char *data) {
    if (out_pool_full()) return -1;
    // get checksum
    char* addr = out_pool.pckts[out_pool.e].data;
    memcpy(addr, (void*)iphdr, iphdr->ihl * 4);
    memcpy(addr + iphdr->ihl * 4, data, iphdr->len - iphdr->ihl * 4);

    out_pool.e++;  // confirm the new entry.
}

/**
 * Pops an element of the out_pool, and prints it on std out. This method should only be used for 
 * testing, as it does not provide any error handling.
 * @param hdr address to which copy the iphdr data
 * @param data address to which copy the data
*/
void out_pool_pop(iphdr* hdr, char* data) {
    iphdr* pckt_hdr = (iphdr *) out_pool.pckts[out_pool.s].data;
    char* pckt_data = ((char *) out_pool.pckts[out_pool.s].data) + (pckt_hdr->ihl * 4);
    out_pool.s++;

    u_int8_t l = pckt_hdr->len - pckt_hdr->ihl * 4;

    memcpy(hdr, pckt_hdr, pckt_hdr->ihl * 4);
    memcpy(data, pckt_data, l);
}


int ip_init() {
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
    }
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

int get_buff_id(iphdr* hdr, buf_id* id) {
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

            iphdr* hdr = (iphdr *)packet;
            if (!FRAGMENTED(hdr)) {
                // pass to ip packet queue
                continue;
            }
            ras_status s;
            if ((s = ras_log(packet)) == SUCCESS_RE_COMPLETE) {
                // pass to ip packet queue
            } else if (s != SUCCESS) {
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
IpStatus queue_for_sending(iphdr* hdr, char* payload_start) {

// Fragments are counted in units of 8 octets.
int queue_for_sending(iphdr* hdr, char* payload_start) {

    if (hdr->len < MTU) {
        pthread_mutex_lock(&out_pool.lck);
        out_pool_append(hdr, payload_start);
        pthread_mutex_unlock(&out_pool.lck);
        return IP_SEND_OK;
    }

    if ((hdr->flags & DF_DO_NOT_FRAGMENT) != 0) return -1; // packet too large but can't be fragmented.

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
        out_pool_append(hdr, payload_start + i * nfb * 8);
    }
        
    hdr->len = (hdr->ihl * 4) + data_len % (nfb * 8);
    SET_LAST_FRAGMENT(hdr);
    hdr->frag_offset = i * nfb;
    out_pool_append(hdr, payload_start + i * nfb * 8);
    pthread_mutex_unlock(&out_pool.lck);

    return IP_SEND_OK;
}

/**
 * Given a header and data block, prints the content of the packet in human readable form.
 * @param hdr header of the packet
 * @param data pointer to the data associated to the header.
 */
void print_packet(iphdr* hdr, char* data) {
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