#include "transport.h"
#include "debug.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DATA_SIZE 1000
#define MAGIC_NUM 15441

/********************
 *  Data Structure  *
 ********************/
struct _HEADER {
	short	magic;
	char	version;
	char	type;
	short	hdr_len;
	short	pkt_len;
	u_int	seq_num;
	u_int	ack_num;
};	
typedef struct _HEADER header_t;

struct _PACKET {
	header_t header;
	char data[DATA_SIZE];
};
typedef struct _PACKET packet_t;


/********************
 * Global Variables *
 ********************/
short kPort;	// local server port
int kPeerNum;	// number of known peers
int kfd;		// udp socket fd

/**
 * functions to handle packet
 */
static int make_packet(packet_t *pkt, short type, 
		u_int seq, u_int ack, 
		void *buf, int len)
{
	if (len > DATA_SIZE) {
		return TE_SIZE;
	}

	pkt->header.magic = MAGIC_NUM;
	pkt->header.version = 1;
	pkt->header.hdr_len = sizeof(header_t);
	pkt->header.pkt_len = sizeof(header_t) + len;
	pkt->header.type = type;
	pkt->header.seq_num = seq;
	pkt->header.ack_num = ack;

	memcpy(pkt->data, buf, len);
	// after this point, buf could be freed

	return TE_OK;
}

static int send_packet(in_addr_t IP, short port, packet_t *pkt)
{
	int n;
	packet_t tmpp;
	memcpy(&tmpp, pkt, sizeof(packet_t));

	// convert byte ordering in header fields
	tmpp.header.magic = htons(pkt->header.magic);
	tmpp.header.hdr_len = htons(pkt->header.hdr_len);
	tmpp.header.pkt_len = htons(pkt->header.pkt_len);
	tmpp.header.seq_num = htonl(pkt->header.seq_num);
	tmpp.header.ack_num = htonl(pkt->header.ack_num);

	// construct dest addr
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = IP;

	n = sendto(kfd, &tmpp, pkt->header.pkt_len,
			0, (struct sockaddr *)&addr, sizeof(addr));

	return n;
}

/**
 * Interface function of transport layer
 */
int send_init(int peer_num, short port)
{
	kPort = port;
	kPeerNum = peer_num;

	// init udp socket
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((kfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		Debug("Make socket on %d port failed.", port);
		return TE_SOCK;
	}

	if (bind(kfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		Debug("bind socket failed.");
		return TE_SOCK;
	}

	return TE_OK;
}

int send_data(in_addr_t IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_whohas(in_addr_t IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_ihave(in_addr_t IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_get(in_addr_t IP, short port, void *buf, size_t size)
{
	return TE_OK;
}
