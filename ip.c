#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "ip.h"

struct {
    int killed;
    int fd;
} ip;

typedef struct {
    char *data;
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


int ip_init() {
    ip.killed = 0;

    ip.fd = open(TUN_DEV, 0); // O_RDWR 
    if (ip.fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // error handling, or make void
    if( in_pool_init() < 0) { close(ip.fd); }
    if( out_pool_init() < 0) { close(ip.fd); }
}


void traffic_manager() {
    int read, write;
    while(!ip.killed) {
        read = 0;
        while(read < MAX_CONSECUTIVE_READ) {
            if (in_pool_full()) break;
            // otherwise read packets and load them into in_pool
        }

        write = 0;
        while(write < MAX_CONSECUTIVE_WRITE) {
            if (out_pool_empty()) break;
            // otherwise send packets from out_pool
        }

        usleep(100);
    }

    close(ip.fd);
}


int queue_for_sending(iphdr* iphdr, char* payload_start) {
    pthread_mutex_lock(&out_pool.lck);

    if (out_pool_full()) return -1; // discarding packet, potentially more informative return value needed.

    // packet processing logic. make sure that a packet is only made available (i.e. out_pool.e increased when )
    
    pthread_mutex_unlock(&out_pool.lck);
}



int check_ipv4(char* buff) {
    if (buff[0] >> 4 == 4) return 1;
    else return 0;
}

int check_ipv6(char* buff) {
    if (buff[0] >> 4 == 6) return 1;
    else return 0;
}
