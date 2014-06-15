#include <stdlib.h>
#include <netinet/in.h>

#ifndef HANDLER_H
#define HANDLER_H

/**
 * Error numbers
 */
#define HE_OK 0
#define HE_INVAL -1

/**
 * function prototypes
 */
int handle_cmd(char *cmd);
int handle_whohas(in_addr_t IP, short port, void *buf, size_t size);
int handle_ihave(in_addr_t IP, short port, void *buf, size_t size);
int handle_get(in_addr_t IP, short port, void *buf, size_t size);
int handle_recv(in_addr_t IP, short port, void *buf, size_t size);
int handle_timer(int interval);

#endif
