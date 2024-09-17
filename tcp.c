#include <pthread.h>

#include "ip.h"
#include "tcp.h"


typedef enum {
    IP_PACKET_IN,
    IP_PACKET_OUT,
    USER_COMMAND,
} EventType;

typedef struct {
    TcpCommand c;
    char* data;
} CommandWithData;

typedef struct {
    iphdr* hdr;
    char* data;
} IpPacket;

typedef struct { // If its a command, we might also need to store extra information.
    EventType type;
    union
    {
        CommandWithData c;
        IpPacket p;
    };
    Event* next;
} Event;

struct {
    pthread_mutex_t lck;
    char[10] name;
    TcpState state;
} TCB;


struct {
    pthread_mutex_t lck;
    Event* events;
} tcp_server;

/**
 * This method registers an event on the TCP queue for an IP packet.
 * @param hdr: pointer to the iphdr of the incoming packet.
 * @param data: pointer to the data of the incoming packet.
 */
void add_packet_event(iphdr* hdr, char* data) {

    Event* e = (Event *) malloc(sizeof(Event));
    e->type = TCP_PACKET;
    (e->p).hdr = hdr;
    (e->p).data = data;
    
    pthread_mutex_lock(&tcp_server.lck);
    Event* current = tcp_server.events;

    if (current == NULL) {
        tcp_server.events = e;
    } else {
        while(tcp_server.events != NULL)
            current = current.next_event;
    
        current.next_event = e;
    }
    pthread_mutex_unlock(&tcp_server.lck);
}

/**
 * This method registers an event on the TCP queue for an user command.
 * @param hdr: pointer to the iphdr of the incoming packet.
 * @param data: pointer to the data of the incoming packet.
 */
void send_command(TcpCommand command, char* data) {
    
    Event* e = (Event *) malloc(sizeof(Event));
    e->type = USER_COMMAND;
    e->c = command;
    
    pthread_mutex_lock(&tcp_server.lck);
    Event* current = tcp_server.events;

    if (current == NULL) {
        tcp_server->next_event = e;
    } else {
        while(tcp_server.events != NULL)
            current = current.next_event;
    
        current.next_event = e;
    }
    pthread_mutex_unlock(&tcp_server.lck);
}

int event_queue_empty() {
    return tcp_server.events == NULL;
}

TcpStatus tcp_init(
    char* (*get_packet)(),
    IpStatus (*send_packet)(char*),
) {
    

}

int OPEN(int local_port, int foreign_ip, int foreign_port) {
    if (foreign_port == 0 && foreign_port == 0) 
        CommandWithData*
    else
        //active open
}


void process_tcp_packet() {

}

TcpStatus change_state(TcpCommand c) {
    
}

void* tcp_manager() {

    while(true) { // need to be changed later

        // get an event
        if (event_queue_empty())
            sleep();

        Event* e;

        pthread_mutex_lock(&tcp_server.lck);
        e = tcp_server.events;
        tcp_server.events = e.next;
        pthread_mutex_unlock(&tcp_server.lck);

        if (e.type == TCP_PACKET) 
        else change_state(e.c);



    }
}