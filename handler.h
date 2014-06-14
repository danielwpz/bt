#include <stdlib.h>

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
int handle_whohas(int IP, short port, void *buf, size_t size);
int handle_ihave(int IP, short port, void *buf, size_t size);
int handle_get(int IP, short port, void *buf, size_t size);
int handle_recv(int IP, short port, void *buf, size_t size);
int handle_timer(int interval);

#endif
