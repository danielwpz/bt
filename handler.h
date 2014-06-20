#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#ifndef HANDLER_H
#define HANDLER_H

/**
 * Error numbers
 */
#define HE_OK 0
#define HE_INVAL -1

/**
 * Command Length
 */
#define BUF_LEN 256


typedef struct available_peer {
  in_addr_t IP;
  short port;
  int valid;
  struct available_peer *next;
} a_peer;


/**
 * function prototypes
 */
int handle_cmd(char *cmd);
int handle_whohas(in_addr_t IP, short port, void *buf, size_t size);
int handle_ihave(in_addr_t IP, short port, void *buf, size_t size);
int handle_get(in_addr_t IP, short port, void *buf, size_t size);
int handle_recv(in_addr_t IP, short port, void *buf, size_t size);
int handle_timer(int interval);
int handle_failure(in_addr_t IP, short port);
unsigned long get_file_size(const char *path);
int read_chunks(FILE *f, uint8_t *hash_list);
int count_peers();
int compare_hash(uint8_t *a, uint8_t *b);

#endif
