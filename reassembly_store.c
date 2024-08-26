#include <stdint.h>

#include "reassembly_store.h"
#include "ip.h"

typedef struct __attribute__((__packed__))
{
    uint32_t saddr;                 // source address
    uint32_t daddr;                 // target address
    uint8_t proto;                  // protocol
} buf_id;


typedef struct {
    re* next;           
    iphdr* hdr;                     // original packet header
    buf_id* id;                     // buffer id:
    char* data;                     // data
    char* bt;                       // bit table
    uint16_t tdl;                   // total data length
    unit8_t ttl;                    // time to live
    uint16_t tam;                   // total available memory
} re;

struct {
    buf_id temp;                    // used to store buf_id's temporarily
    uint8_t entries;                // number of entries in reassembly store
    re* h;                          // head of the linked list
} ras;

buf_id* temp_id;


ras_status ras_init() {
    temp_id = (buf_id*)malloc(sizeof(buf_id));
    if (temp_id < 0) return MEM_ERR;
    ras.entries = 0;

    return SUCCESS;
}

void free_re(re* entry) {
    free(entry->next);
    free(entry->data);
    free(entry->bt);
    free(entry);
}

void ras_kill() {
    re* current = (re *) ras.h;
    while (current != NULL) {
        re* next = (re *) current->next;
        free_re(current);
        current = next;
    }
}

int reassembly_store_empty() {
    return ras.entries == 0;
}

/**
 * Given an iphdr constructs a buf_id.
 * @param hdr: ip header to be summarized
 * @param id: buffer id to be written the result into
 */

int get_buf_id(iphdr* hdr, buf_id* id) {
    id->saddr = hdr->saddr;
    id->daddr = hdr->daddr;
    id->proto = hdr->proto;
}

/**
 * Organize a received packet in the Reassembly Store.
 * @param packet: packet to be stored
 */
int ras_log(char* packet) {
    iphdr* hdr = (iphdr *) packet;
    get_buf_id(hdr, temp_id);

    re* current = ras.h;
    while (!strcmp(temp_id, current->id, 72)) 
        current = current->next;

    if (current == NULL) ras_new_datagram(temp_id);

    ras_store_packet(current, packet);
}

/**
 * Allocate a new reassembly entry. Upon receiving a packet that has no 
 * resources assigned to it, allocated sufficient memory for storing a 
 * packet of pre-defined size; with provided buffer id.
 * @param id: buffer id of the datagram to be reassembled.
 */
int ras_new_datagram(buf_id* id) {
    buf_id *local_id = (buf_id*) malloc(sizeof(buf_id));                // Make a local copy of the buffer id.
    memcpy(local_id, id, 72);
    
    (re *) new_re = (re *) malloc(sizeof(re));                          // Allocate a new reassembly entry.

    new_re->next = ras.h;
    new_re->hdr = (iphdr *) malloc(sizeof(iphdr));
    new_re->id = local_id;
    new_re->data = (char *) malloc(sizeof(char) * 8 * MIN_PACKET_SIZE);
    new_re->bt = (char *) malloc(sizeof(char) * MIN_PACKET_SIZE);       // Allocate the minimum requirement
    new_re->tdl = 0;
    // ttl
    new_re->tam = MIN_PACKET_SIZE;                                      // Set total data 
    
    ras.h = new_re;
}

/**
 * Stores the given packet in the given entry. Copies the contents of
 * packet into the memory allocated for the reassembly of a packet.
 * @param entry: Reassembly entry to store the packet in
 * @param packet: packet to be stored in the reassemble entry
 */
int ras_store_packet(re* entry, char* packet) {
    iphdr* hdr = (iphdr *) packet;
    
    size_t frag_offset = hdr->frag_offset;

    if (frag_offset == 0) {
        memcpy(re->hdr, hdr, sizeof(iphdr));
    }

    size_t data_start = packet + hdr->ihl * 4;
    size_t data_length = hdr->ttl - hdr->ihl * 4;

    if (frag_offset * 8 + data_length > re->tdl)
        re->tdl = frag_offset * 8 + data_length;

    if (re->tdl > re->tam) {
        //
    }

    memcpy(re->data, packet + data_start, data_length);

    // log in bit table
}

/**
 * Extend the data memory of a given reassembly entry.
 * @param entry: Entry to be extended
 * @param size: new size in 8 octet blocks
 */
int ras_extend_re(re* entry, size_t size) {

}

