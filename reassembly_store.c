#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "reassembly_store.h"

/**
 * Prints the error message associated with a RasStatus code
 * @param s: RasStatus to be decoded.
 */
void ras_error_message(RasStatus s) {
    switch (s) {
        case RAS_ERROR: printf("RAS: Unspecified error."); break;
        case RAS_MEM_ERR: printf("RAS: Memory error."); break;
        case RAS_ERR_PACKET_NOT_COMPLETE: printf("RAS: Stream exists but not complete."); break;
        case RAS_ERR_PACKET_NOT_FOUND: printf("RAS: Stream not found."); break;
        case RAS_SUCCESS: break;
        case RAS_SUCCESS_RE_COMPLETE: break;
    }
}

typedef struct __attribute__((__packed__))
{
    uint32_t saddr;                 // source address
    uint32_t daddr;                 // target address
    uint8_t proto;                  // protocol
} BufId;

typedef struct {
    void* next;           
    IpHeader* hdr;                     // original packet header
    BufId* id;                     // buffer id:
    char* data;                     // data
    uint8_t bt_len;                 // length of the bit table
    char* bt;                       // bit table
    uint16_t tdl;                   // total data length in 1 byte blocks
    uint8_t ttl;                    // time to live
    uint16_t tam;                   // total available memory in 1 byte blocks
    uint8_t got_last : 1;           // 1 if got a package with more packets flag not set.
} re;

struct {
    BufId temp;                    // used to store BufId's temporarily
    uint8_t entries;                // number of entries in reassembly store
    re* h;                          // head of the linked list
} ras;

BufId* temp_id;


RasStatus ras_init() {
    temp_id = (BufId*)malloc(sizeof(BufId));
    if (temp_id < 0) return RAS_MEM_ERR;
    ras.entries = 0;

    return RAS_SUCCESS;
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
 * Given an IpHeader constructs a BufId.
 * @param hdr: ip header to be summarized
 * @param id: buffer id to be written the result into
 */

void get_BufId(IpHeader* hdr, BufId* id) {
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
RasStatus ras_new_datagram(BufId* id) {
    BufId *local_id = (BufId*) malloc(sizeof(BufId));                // Make a local copy of the buffer id.
    memcpy(local_id, id, 72);
    
    re* new_re = (re *) malloc(sizeof(re));                             // Allocate a new reassembly entry.
    if (new_re == NULL) return RAS_MEM_ERR;

    new_re->next = ras.h;

    new_re->hdr = (IpHeader *) malloc(sizeof(IpHeader));                      // Allocate header
    if (new_re->hdr == NULL) return RAS_MEM_ERR;

    new_re->id = local_id;

    new_re->data = (char *) malloc(sizeof(char) * 8 * MIN_PACKET_SIZE); // Allocate minimum requirement
    if (new_re->data == NULL) return RAS_MEM_ERR;

    new_re->bt_len = (MIN_PACKET_SIZE / 8 + (MIN_PACKET_SIZE % 8) != 0);
    new_re->bt = (char *) malloc(sizeof(char) * new_re->bt_len);       // Allocate bit table
    if (new_re->bt == NULL) return RAS_MEM_ERR;

    new_re->tdl = 0;
    // todo: time to live
    new_re->tam = MIN_PACKET_SIZE;                                      // Set total data 
    
    ras.h = new_re;

    return RAS_SUCCESS;
}

/**
 * Extend the data memory of a given reassembly entry, to size total_data_length.
 * @param entry: Entry to be extended
 */
RasStatus ras_extend_re(re* entry) {
    char* new_data_store = malloc(entry->tdl * sizeof(char));
    if (new_data_store == NULL) return RAS_MEM_ERR;

    memcpy(new_data_store, entry->data, entry->tam);
    free(entry->data);
    entry->data = new_data_store;    
    entry->tam = entry->tdl;

    // extend bit table
    uint8_t new_bt_len = entry->tdl / 8 + (entry->tdl % 8 != 0);
    char* new_bt = malloc(new_bt_len * sizeof(char));
    if (new_bt == NULL) return RAS_MEM_ERR;
    memcpy(new_bt, entry->bt, entry->bt_len);
    char* old_bt = entry->bt;
    entry->bt = new_bt;
    free(old_bt);

    return RAS_SUCCESS;
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
    uint8_t chunks = entry->tdl / 8 + (entry->tdl % 8 != 0);
    for (int i = 0; i < chunks; i++) {
        if ((*(entry->bt + i / 8) & (1 << (7- i % 8))) == 0) return 0;
    }
    return 1;
}

/**
 * Upon a provided hdr, the function *completes the header from the fully re-
 * covered header that is stored, and load the associated data into data.
 * @param hdr IpHeader specifying which message stream the caller is asking for
 * @param data location where the stored data is going to be copied.
 */
RasStatus ras_get_packet(IpHeader* hdr, char* data) {
    BufId* id  = malloc(sizeof(BufId));
    if (id == NULL) return RAS_MEM_ERR;
    get_BufId(hdr, id);

    re* current = ras.h;
    while (current != NULL && memcmp(id, current->id, sizeof(BufId)))
        current = current->next;

    if (current == NULL) return RAS_ERR_PACKET_NOT_FOUND;
    if (!re_complete(current)) return RAS_ERR_PACKET_NOT_COMPLETE;

    current->hdr->len = current->hdr->ihl * 4 +current->tdl;                // Fix flags that could have changed.
    current->hdr->frag_offset = 0;
    current->hdr->flags = 0b000;

    memcpy(hdr, current->hdr, sizeof(IpHeader));                               // Here we rather need to pass the ownership of these on...                         
    memcpy(data, current->data, current->tdl);

    return RAS_SUCCESS;
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
RasStatus ras_store_packet(re* entry, char* packet) { // double check the units here
    IpHeader* hdr = (IpHeader *) packet;
    
    size_t frag_offset = hdr->frag_offset;

    if (frag_offset == 0) {
        memcpy(entry->hdr, hdr, sizeof(IpHeader));
    }

    char* data_start = packet + hdr->ihl * 4;                           // Both of these are in octets 
    size_t dl8 = hdr->len - hdr->ihl * 4;                               // data length in 1 byte block

    if (frag_offset * 8 + dl8 > entry->tdl)                             // 
        entry->tdl = frag_offset * 8 + dl8;

    if (entry->tdl > entry->tam)                                        // Check if there is enough memory in re
        ras_extend_re(entry);                                           // TODO error handling

    memcpy(entry->data + frag_offset * 8, data_start, dl8);             // Copy data into re

    log_bit_table(entry, frag_offset, dl8/8 + (entry->tdl % 8 != 0));

    if (!GET_MORE_FRAGMENTS(hdr)) entry->got_last = 1;
    
    if (entry->got_last && re_complete(entry)) return RAS_SUCCESS_RE_COMPLETE;
    return RAS_SUCCESS;
}


/**
 * Organize a received packet in the Reassembly Store.
 * @param packet: raw packet to be stored
 */
RasStatus ras_log(char* packet) {
    IpHeader* hdr = (IpHeader *) packet;
    get_BufId(hdr, temp_id);

    re* current = ras.h;
    while (current != NULL && memcmp(temp_id, current->id, sizeof(BufId))) {
        current = current->next;
    }

    RasStatus result;
    if (current == NULL) {
        if ((result = ras_new_datagram(temp_id)) != RAS_SUCCESS) return result;
        current = ras.h;
    }
    
    return ras_store_packet(current, packet);
}

