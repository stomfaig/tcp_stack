#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "reassembly_store.h"

typedef struct __attribute__((__packed__))
{
    uint32_t saddr;                 // source address
    uint32_t daddr;                 // target address
    uint8_t proto;                  // protocol
} buf_id;


typedef struct {
    void* next;           
    iphdr* hdr;                     // original packet header
    buf_id* id;                     // buffer id:
    char* data;                     // data
    char* bt;                       // bit table
    uint16_t tdl;                   // total data length in 1 byte blocks
    uint8_t ttl;                    // time to live
    uint16_t tam;                   // total available memory in 1 byte blocks
    uint8_t got_last : 1;           // 1 if got a package with more packets flag not set.
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

void print_ras_entires() {
    re* current = (re *) ras.h;
    while (current != NULL) {
        re* next = (re *) current->next;
        
    }
}

/**
 * Given an iphdr constructs a buf_id.
 * @param hdr: ip header to be summarized
 * @param id: buffer id to be written the result into
 */

void get_buf_id(iphdr* hdr, buf_id* id) {
    id->saddr = hdr->saddr;
    id->daddr = hdr->daddr;
    id->proto = hdr->proto;
}

/**
 * Allocate a new reassembly entry. Upon receiving a packet that has no 
 * resources assigned to it, allocated sufficient memory for storing a 
 * packet of pre-defined size; with provided buffer id.
 * @param id: buffer id of the datagram to be reassembled.
 */
ras_status ras_new_datagram(buf_id* id) {
    buf_id *local_id = (buf_id*) malloc(sizeof(buf_id));                // Make a local copy of the buffer id.
    memcpy(local_id, id, 72);
    
    re* new_re = (re *) malloc(sizeof(re));                             // Allocate a new reassembly entry.
    if (new_re == NULL) return MEM_ERR;

    new_re->next = ras.h;

    new_re->hdr = (iphdr *) malloc(sizeof(iphdr));                      // Allocate header
    if (new_re->hdr == NULL) return MEM_ERR;

    new_re->id = local_id;

    new_re->data = (char *) malloc(sizeof(char) * 8 * MIN_PACKET_SIZE); // Allocate minimum requirement
    if (new_re->data == NULL) return MEM_ERR;

    new_re->bt = (char *) malloc(sizeof(char) * MIN_PACKET_SIZE);       // Allocate bit table
    if (new_re->bt == NULL) return MEM_ERR;

    new_re->tdl = 0;
    // todo: time to live
    new_re->tam = MIN_PACKET_SIZE;                                      // Set total data 
    
    ras.h = new_re;

    return SUCCESS;
}

/**
 * Extend the data memory of a given reassembly entry, to size total_data_length.
 * @param entry: Entry to be extended
 */
ras_status ras_extend_re(re* entry) {
    char* new_data_store = malloc(entry->tdl * sizeof(char));
    if (new_data_store == NULL) return MEM_ERR;

    memcpy(new_data_store, entry->data, entry->tam);
    free(entry->data);
    entry->data = new_data_store;    
    entry->tam = entry->tdl;

    // extend bit table

    return SUCCESS;
}

/**
 * Log the received octets in the bit table
 * @param entry entry to set the bit table of
 * @param start id of starting octet
 * @param len number of octets to register as received
 */
void log_bit_table(re* entry, int start, int len) {
    for (int i = 0; i < len; i++) {
        *(entry->bt + (start + i) / 8) |= 1 << (7 - (start + i) % 8);
    }
}

/**
 * Checks whether the bit table of a re entry is complete.
 * @param entry entry to check the bit table of
 */
int re_complete(re* entry) {
    for (int i = 0; i < entry->tdl; i++) {
        if ((*(entry->bt + i / 8) & (1 << (7- i % 8))) == 0) return 0;
    }
    return 1;
}

/**
 * Stores the given packet in the given entry. Copies the contents of
 * packet into the memory allocated for the reassembly of a packet.
 * @param entry Reassembly entry to store the packet in
 * @param packet packet to be stored in the reassemble entry
 * @return SUCCESS_RE_COMPLETE if the assembled unit is complete, SUCCESS the storage ope-
 * eration was successful, but the package is not yet complete. If an error occured, then the
 * appropriate error code is returned.
 */
ras_status ras_store_packet(re* entry, char* packet) { // double check the units here
    iphdr* hdr = (iphdr *) packet;
    
    size_t frag_offset = hdr->frag_offset;

    if (frag_offset == 0) {
        memcpy(entry->hdr, hdr, sizeof(iphdr));
    }

    char* data_start = packet + hdr->ihl * 4;                           // Both of these are in octets 
    size_t dl8 = hdr->len - hdr->ihl * 4;                               // data length in 1 byte block

    if (frag_offset * 8 + dl8 > entry->tdl)                             // 
        entry->tdl = frag_offset * 8 + dl8;

    if (entry->tdl > entry->tam)                                        // Check if there is enough memory in re
        ras_extend_re(entry);

    memcpy(entry->data + frag_offset * 8, data_start, dl8);             // Copy data into re

    uint8_t dl64 = dl8 / 8 + ( dl8 % 8 != 0);                            // data length in 8 byte blocks
    memset(entry->bt + frag_offset, 1, dl64);                           // log octets received

    if (!GET_MORE_FRAGMENTS(hdr)) entry->got_last = 1;
    
    if (entry->got_last && re_complete(entry)) return SUCCESS_RE_COMPLETE;
    return SUCCESS;
}


/**
 * Organize a received packet in the Reassembly Store.
 * @param packet: raw packet to be stored
 */
ras_status ras_log(char* packet) {
    iphdr* hdr = (iphdr *) packet;
    get_buf_id(hdr, temp_id);

    re* current = ras.h;
    while (current != NULL && !memcmp(temp_id, current->id, sizeof(buf_id))) 
        current = current->next;

    ras_status result;
    if (current == NULL) {
        result = ras_new_datagram(temp_id);
        current = ras.h;
    }
    if (result == ERROR) return result;

    return ras_store_packet(current, packet);
}

