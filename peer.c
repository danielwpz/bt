/*
 * peer.c
 *
 * Authors: Daniel
 *			Florrie
 *
 * THIS IS A TEST FILE.
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

/* for test */
int cmdType = 0;

void peer_run(bt_config_t *config);

/* TEST DRIVER */
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
	int port;
	int ret;
	scanf("%d", &port);
	ret = send_init(1, (short)port);
	if (ret < 0) {
		Debug("send_init error %d\n", ret);
	}
	Debug("start!\n");

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

void anounce_timeout(int interval) {
	process_timer(interval);
}

void peer_run(bt_config_t *config) {
	int n;
	struct sockaddr_in myaddr;
	fd_set readfds;
	struct timeval tv;
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

	while (1) {
		int nfds;
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(kfd, &readfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		nfds = select(kfd+1, &readfds, NULL, NULL, &tv);

		if (nfds > 0) {

			if (FD_ISSET(kfd, &readfds)) {
				process_udp(kfd);
			}

			if (FD_ISSET(STDIN_FILENO, &readfds)) {
				int i, ret;
				in_addr_t dIP = inet_addr("127.0.0.1");
				short dport;
				char buf[1024];
				char data[1024];
				ret = read(STDIN_FILENO, data, 1024);
				data[ret] = '\0';
				sscanf(data, "%d %s", &dport, buf);
				char *tmpbuf = malloc(512 * 1024);

				for (i = 0; i < strlen(buf); i++) {
					tmpbuf[i] = buf[i];
				}
				for (i = 0; i < 512 * 1024; i++) {
					tmpbuf[i] = i % 32;
				}

				ret = send_data(dIP, dport, tmpbuf, 512 * 1024);

				/*
				cmdType = (cmdType + 1) % 4;

				if (cmdType == 1) {
					ret = send_whohas(dIP, dport, buf, strlen(buf));
				}else if (cmdType == 2) {
					ret = send_ihave(dIP, dport, buf, strlen(buf));
				}else if (cmdType == 3) {
					ret = send_get(dIP, dport, buf, strlen(buf));
				}else if (cmdType == 0) {
					ret = send_data(dIP, dport, buf, strlen(buf));
				}
				*/

				if (ret < 0) {
					printf("error %d\n", ret);
				}
			}
			anounce_timeout(SELECT_TICK);
		}else if (nfds == 0) {
			anounce_timeout(SECOND_TICK);
		}
	}
}
