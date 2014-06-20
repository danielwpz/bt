/*
 * peer.c
 *
 * Authors: Daniel
 *			Florrie
 *
 * Date:	2014-6
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "handler.h"
#include "transport.h"

#define BUF_SIZE 1024

extern int kfd;

void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
	bt_config_t config;

	bt_init(&config, argc, argv);
	
	debug = DEBUG_ALL;
	DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
	config.identity = 4; // your group number here
	strcpy(config.chunk_file, "chunkfile");
	strcpy(config.has_chunk_file, "haschunks");
#endif

	bt_parse_command_line(&config);

#ifdef DEBUG
	if (debug & DEBUG_INIT) {
		bt_dump_config(&config);
	}
#endif

	/* TODO: fill in peers num and local port */

	int q = 0;
	bt_peer_t *temp = config.peers;
	while (temp!=NULL) {
		temp = temp->next;
		q++;
	}
	Debug("count_peers: %d\n", q-1);
	Debug("myport:%d\n", config.myport);
	send_init(q-1, config.myport);

	peer_run(&config);
	return 0;
}


void process_inbound_udp(int sock) {
#define BUFLEN 1500
	struct sockaddr_in from;
	socklen_t fromlen;
	char buf[BUFLEN];

	fromlen = sizeof(from);
	spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

	printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
			"Incoming message from %s:%d\n%s\n\n", 
			inet_ntoa(from.sin_addr),
			ntohs(from.sin_port),
			buf);
}


void peer_run(bt_config_t *config) {
	int n;
	struct sockaddr_in myaddr;
	fd_set readfds;
	struct user_iobuf *userbuf;
	char buf[BUF_SIZE];

	if ((userbuf = create_userbuf()) == NULL) {
		perror("peer_run could not allocate userbuf");
		exit(-1);
	}

	// init spiffy
	bzero(&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(config->myport);
	//spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

	hd_init(config, htonl(INADDR_ANY));
	while (1) {
		int nfds;
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(kfd, &readfds);

		nfds = select(kfd+1, &readfds, NULL, NULL, NULL);

		if (nfds > 0) {
			if (FD_ISSET(kfd, &readfds)) {
				process_udp(kfd);
			}

			if (FD_ISSET(STDIN_FILENO, &readfds)) {
				n = read(STDIN_FILENO, buf, BUF_SIZE);
				if (n > 0) {
					buf[n] = '\0';
					handle_cmd(buf);
				}
			}
		}
	}
}
