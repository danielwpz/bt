#include <stdlib.h>
#include <netinet/in.h>

#ifndef TRANSPORT_H
#define TRANSPORT_H

/**
 * Error numbers
 */
#define TE_OK 0
#define TE_INVAL -1
#define TE_SIZE -2
#define TE_SOCK -3	/* establish socket error (bind or socket) */
#define TE_PKT  -4	/* packet magic or version or hdr_len is invalid */
#define TE_MEM	-5	/* malloc or other memory error */
#define TE_ALREADY	-6	/* duplicated connections via send_data */
#define TE_FULL	-7	/* no empty state to use */
#define TE_WIN	-8	/* window size error */
#define TE_NOSTATE	-9	/* get ack or data but not find its state */
#define TE_OLDACK	-10	/* received ack is older than laf */

/**
 * timer interval
 */
#define SELECT_TICK 10
#define SECOND_TICK 1000

/**
 * function prototypes
 */
int send_init(int peer_num, short port);
int send_data(in_addr_t IP, short port, void *buf, size_t size);
int send_whohas(in_addr_t IP, short port, void *buf, size_t size);
int send_ihave(in_addr_t IP, short port, void *buf, size_t size);
int send_get(in_addr_t IP, short port, void *buf, size_t size);

void process_udp(int fd);
void process_timer(int interval);

#endif
