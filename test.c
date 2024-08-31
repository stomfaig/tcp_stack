#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ip.h"
#include "reassembly_store.h"

typedef enum {
    PASS,
    FAIL
} TestResult;

/**
 * Write a packet directly into out_pool, and then read it out, check for consistency.
 * 
 */
TestResult test_out_pool() {
    TestResult result = PASS;

    printf("Testing out pool...\t");

    iphdr* hdr = (iphdr *) malloc(sizeof(iphdr));
    char payload[8] = "abcdefg!";

    hdr->ihl = 5;   
    hdr->len = hdr->ihl * 4 + 8;
    hdr->saddr = 1234;

    out_pool_append(hdr, payload);
    iphdr* new_hdr = (iphdr *) malloc(sizeof(iphdr));
    char* new_payload = malloc(100 * sizeof(char));
    out_pool_pop(new_hdr, new_payload);
    
    if (memcmp(hdr, new_hdr, hdr->ihl * 4) != 0) result = FAIL;
    else if (memcmp(payload, new_payload, 8) != 0) result = FAIL;

    free(hdr);
    free(new_hdr);
    free(new_payload);

    printf(result == PASS ? "PASS\n" : "FAIL\n");

    return result;
}

/**
 * Submit a large packet for sending. Reassemble the message 
 */
TestResult test_fragmentation() {
    TestResult result = PASS;
    printf("Testing fragmentation...\t");

    iphdr* hdr = (iphdr *)malloc(sizeof(iphdr));
    char* payload = malloc(100 * sizeof(char));
    for (int i = 0; i < 100; i++) {
        payload[i] = 33 + i;
    }
    hdr->ihl = 5;
    hdr->len = hdr->ihl * 4 + 100;

    queue_for_sending(hdr, payload);

    char* recovered_message = (char *) malloc(100 * sizeof(char));
    iphdr* new_hdr = (iphdr *) malloc(sizeof(iphdr));
    char* new_payload = (char *) malloc(8 * sizeof(char)); // this is 8 for testing purposes...

    while (!out_pool_empty()) {
        out_pool_pop(new_hdr, new_payload);
        memcpy(recovered_message + new_hdr->frag_offset * 8, new_payload, (new_hdr->len - new_hdr->ihl * 4) * sizeof(char));
    }

    if (memcmp(payload, recovered_message, 100) != 0) result = FAIL;

    free(hdr);
    free(payload);

    printf(result == PASS ? "PASS\n" : "FAIL\n");

    return result;
}

TestResult test_ras() {
    TestResult result = PASS;

    char* packet = (char *) malloc(28 * sizeof(char));
    iphdr* hdr = (iphdr *) packet;

    hdr->ihl = 5;
    hdr->len = 28;
    hdr->proto = 1;
    hdr->saddr = 2;
    hdr->daddr = 3;

    char* data = packet + hdr->ihl * 4;

    for (int i = 0; i < 8; i++) data[i] = 40 + i;

    ras_log(hdr);
    hdr->frag_offset = 1;
    ras_log(hdr);

    return result;
}

int main() {
    ip_init();
    //test_out_pool();
    //test_fragmentation();
    test_ras();
    release();
}

