#include "ip.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void test_out_pool() {
    iphdr* hdr = (iphdr *) malloc(sizeof(iphdr));
    char payload[100] = "Packet information services!";

    hdr->ihl = 5;   
    hdr->len = hdr->ihl * 4 + 28;
    hdr->saddr = 1234;

    queue_for_sending(hdr, payload);
    free(hdr);

    out_pool_pop();
}

int main() {
    ip_init();
    test_out_pool();
    release();
}

