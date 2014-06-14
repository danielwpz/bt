#include <stdlib.h>

#ifndef TRANSPORT_H
#define TRANSPORT_H

/**
 * Error numbers
 */
#define TE_OK 0
#define TE_INVAL -1

/**
 * timer interval
 */
#define SELECT_TICK 2
#define SECOND_TICK 20

/**
 * function prototypes
 */
int send_init(int peer_num, short port);
int send_data(int IP, short port, void *buf, size_t size);
int send_whohas(int IP, short port, void *buf, size_t size);
int send_ihave(int IP, short port, void *buf, size_t size);
int send_get(int IP, short port, void *buf, size_t size);

#endif
