#include "ip.h"
#include <pthread.h>
#include <unistd.h>

int main() {

    ip_init();

    pthread_t t;
    pthread_create(&t, NULL, traffic_manager, NULL);

    usleep(1000);

    ip_kill();
    usleep(100);

    return 0;
}