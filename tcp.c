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
    IpHeader* hdr;
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

typedef struct {
    pthread_mutex_t lck;
    char[10] name;
    uint16_t local_port;
    uint16_t foreign_ip;
    uint32_t foreign_port;

    uint32_t snd_una;           // send side unacknowledged
    uint32_t snd_nxt;           // send side next
    uint32_t snd_wnd;           // send window
    unit32_t snd_up;            // send urgent pointer
    unit32_t snd_wl1;
    unit32_t snd_wl2;
    unit32_t iss;               // initial send sequence number

    unit32_t rcv_nxt;           // receive next
    unit32_t rcv_wnd;           // receive window
    unit32_t snd_up;            // send urgent pointer
    unit32_t irs;               // initial receive sequence number

    TcpState state;
} Tcb;


// How are TCB's stored?
struct {
    pthread_mutex_t lck;
    char[100] err;
    Event* events;
    Tcb* tc_blocks;
} tcp_server;

void add_event(Event* e) {
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

/**
 * This method registers an event on the TCP queue for an IP packet.
 * @param hdr: pointer to the IpHeader of the incoming packet.
 * @param data: pointer to the data of the incoming packet.
 */
void add_packet_event(IpHeader* hdr, char* data) {

    Event* e = (Event *) malloc(sizeof(Event));
    e->type = TCP_PACKET;
    (e->p).hdr = hdr;
    (e->p).data = data;

    add_event(e);
}

/**
 * This method registers an event on the TCP queue for an user command.
 * @param hdr: pointer to the IpHeader of the incoming packet.
 * @param data: pointer to the data of the incoming packet.
 */
void add_command_event(TcpCommand command, char* data) {
    
    Event* e = (Event *) malloc(sizeof(Event));
    e->type = USER_COMMAND;
    e->c = command;
    
    add_event(e);
}
/**
 * Method for generating initial seq numbers.
 */
uint32_t get_initial_seq_number() {

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
        // open passive
    else
        // open active
}

/**
 * Main function handling the processing of a TCP packet
 * @param e : pointer to the tcp event storing the packet received.
 */
TcpStatus process_tcp_packet(Event* e) {

    IpPacket p = e.p;
    IpHeader* ip_hdr = p.hdr;
    TcpHeader* tcp_hdr = (TcpHeader *) p.data;

    Tcb* current = tcp_server.tc_blocks;
    while ((current != NULL) && !((current->local_port == hdr->d_port) && (current->foreign_ip == ip_hdr->saddr) && (current->foreign_port == hdr->s_port)))
        current = current.next;
    
    if (current == NULL) {
        // set error message.
        return TCP_ERR_PORT_CLOSED;
    }

    switch (current.state) {
        case TCP_LISTEN:
            if (CHECK_FLAG(tcp_hdr, TCP_SYN)) {
                
                current->irs = tcp_hdr->seq_number;

                TcpHeader* ans_tcp_hdr = (TcpHeader *) malloc(sizeof(TcpHeader));

                SET_FLAG(ans_tcp_hdr, TCP_ACK);
                ans_tcp_hdr->ack_number = current->irs+1;            // potentially mod something...
                SET_FLAG(ans_tcp_hdr, TCP_SYN);
                ans_tcp_hdr->seq_number = current->iss;

                // load port, ip etc arguments and send.

                current.state = TCP_SYN_RCVD;

            } else {
                // set error message
                return TCP_ERR_UNEXPECTED_MESSAGE;
            }
            break;
        case TCP_SYN_RCVD:
            if (CHECK_FLAG(tcp_hdr, TCP_ACK)) {
                if (tcp_hdr->ack_number == current.iss+1) {
                    current.state = TCP_ESTAB;
                } else {
                    // set error message
                    return TCP_ERR_ACK_FAILED;
                }
            } else {
                // set error message
                return TCP_ERR_UNEXPECTED_MESSAGE;
            }
            break;
        case TCP_SYN_SENT:
            if (CHECK_FLAG(tcp_hdr, TCP_SYN) && !CHECK_FLAG(tcp_hdr, TCP_ACK)) {
                // send ack

                TcpHeader* ans_tcp_hdr = (TcpHeader *) malloc(sizeof(TcpHeader));

                current->irs = tcp_hdr->seq_number;
                SET_FLAG(ans_tcp_hdr, TCP_ACK);
                ans_tcp_hdr->ack_number = current->irs+1;

                // load port, ip and send answer.

                current.state = TCP_SYN_RCVD;
                
            } else if (CHECK_FLAG(tcp_hdr, TCP_SYN) && CHECK_FLAG(tcp_hdr, TCP_ACK)) {

                // check if ack is correct,
                if (tcp_hdr->ack_number != current.irs+1) {
                    // set error message
                    return TCP_ERR_ACK_FAILED;
                }

                TcpHeader* ans_tcp_hdr = (TcpHeader *) malloc(sizeof(TcpHeader));

                // send ack
                current->irs = tcp_hdr->seq_number;
                SET_FLAG(ans_tcp_hdr, TCP_ACK);
                ans_tcp_hdr->ack_number = current->irs+1;

                // load port, ip and send answer.

                current.state = TCP_ESTAB;

            } else {
                // set error message
                return TCP_ERR_UNEXPECTED_MESSAGE;
            }

            break;
        case TCP_ESTAB:
            // Not yet implemented.
            break;
    }

    return TCP_SUCCESS;
}

/**
 * This method handles user command
 */
TcpStatus tcp_process_command(Event* e) {
    IpPacket p = e.p;
    IpHeader* ip_hdr = p.hdr;
    TcpHeader* tcp_hdr = (TcpHeader *) p.data;

    if (e.type != USER_COMMAND) {
        // set error message
        return TCP_ERR;
    }
    
    // find the right block.

    // OPEN: create a new TCB.

    return TCP_SUCCESS;
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

        if (e.type == TCP_PACKET) {
            process_tcp_packet(e);
        }
        else tcp_process_command(e);
    }
}