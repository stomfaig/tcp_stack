

#define MIN_PACKET_SIZE 100 // Allows storing 100 octets of data.
typedef enum {
    MEM_ERR,
    SUCCESS,
    SUCCESS_RE_COMPLETE,
} ras_status;

char* ras_error(ras_status s);
