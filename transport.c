#include "transport.h"
#include "handler.h"
#include "chunk.h"
#include "debug.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DATA_SIZE 1000
#define MAGIC_NUM 15441

#define TYPE_WHOHAS	0
#define TYPE_IHAVE	1
#define TYPE_GET	2
#define TYPE_DATA	3
#define TYPE_ACK	4
#define TYPE_DENIED	5

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

static int recv_packet(packet_t *pkt, void *buf)
{
	packet_t *tmpp = (packet_t *)buf;

	// parse header
	pkt->header.magic = ntohs(tmpp->header.magic);
	pkt->header.version = tmpp->header.version;
	pkt->header.type = tmpp->header.type;
	pkt->header.hdr_len = ntohs(tmpp->header.hdr_len);
	pkt->header.pkt_len = ntohs(tmpp->header.pkt_len);
	pkt->header.seq_num = ntohl(tmpp->header.seq_num);
	pkt->header.ack_num = ntohl(tmpp->header.ack_num);

	// check valid
	if (pkt->header.magic != MAGIC_NUM ||
		pkt->header.version != 1 ||
		pkt->header.hdr_len != sizeof(packet_t)) {
		return TE_PKT;
	}	

	// copy data
	size_t datalen = pkt->header.pkt_len - pkt->header.hdr_len;
	memcpy(pkt->data, tmpp->data, datalen);

	return pkt->header.pkt_len;
}

/**
 * Interface function of transport layer
 * used by upper layer
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

	if ((kfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
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
	int ret;
	char *desc = "[send_data]";
	/* Test mode
	if (size != BT_CHUNK_SIZE) {
		Debug("data size invalid %d\n", size);
		return TE_SIZE;
	}
	*/
	
	// make packet
	packet_t pkt;
	ret = make_packet(&pkt, TYPE_DATA, 0, 0, buf, size);
	if (ret < 0) {
		Debug("%smake_packet error %d\n",desc, ret);
		return ret;
	}

	// send packet
	ret = send_packet(IP, port, &pkt);
	if (ret < 0) {
		Debug("%ssend_packet error %d\n",desc, ret);
		return ret;
	}	

	return TE_OK;
}

int send_whohas(in_addr_t IP, short port, void *buf, size_t size)
{
	int ret;
	char *desc = "[send_whohas]";

	// make packet
	packet_t pkt;
	ret = make_packet(&pkt, TYPE_WHOHAS, 0, 0, buf, size);
	if (ret < 0) {
		Debug("%smake_packet error %d\n", desc, ret);
		return ret;
	}

	// send packet
	ret = send_packet(IP, port, &pkt);
	if (ret < 0) {
		Debug("%ssend_packet error %d\n", desc, ret);
		return ret;
	}

	return TE_OK;
}

int send_ihave(in_addr_t IP, short port, void *buf, size_t size)
{
	int ret;
	char *desc = "[send_ihave]";

	// make packet
	packet_t pkt;
	ret = make_packet(&pkt, TYPE_IHAVE, 0, 0, buf, size);
	if (ret < 0) {
		Debug("%smake_packet error %d\n", desc, ret);
		return ret;
	}

	// send packet
	ret = send_packet(IP, port, &pkt);
	if (ret < 0) {
		Debug("%ssend_packet error %d\n", desc, ret);
		return ret;
	}

	return TE_OK;
}

int send_get(in_addr_t IP, short port, void *buf, size_t size)
{
	int ret;
	char *desc = "[send_get]";

	// make packet
	packet_t pkt;
	ret = make_packet(&pkt, TYPE_GET, 0, 0, buf, size);
	if (ret < 0) {
		Debug("%smake_packet error %d\n", desc, ret);
		return ret;
	}

	// send packet
	ret = send_packet(IP, port, &pkt);
	if (ret < 0) {
		Debug("%ssend_packet error %d\n", desc, ret);
		return ret;
	}

	return TE_OK;
}

/**
 * Interfaces to under layer
 */
void process_udp(int fd)
{
#define BUFLEN 1500
	int n, ret;
	struct sockaddr_in fromaddr;
	socklen_t fromlen;
	char buf[BUFLEN];

	if (fd != kfd) {
		Debug("fd(%d) != kfd(%d)\n", fd, kfd);

		return;
	}

	fromlen = sizeof(fromaddr);
	n = recvfrom(fd, buf, BUFLEN, 0,
			(struct sockaddr *)&fromaddr, &fromlen);
	if (n < 0) {
		Debug("recvfrom error %d\n", n);
	}

	// handle packet
	packet_t pkt;
	int pkt_len = recv_packet(&pkt, buf);

	if (pkt_len > 0) {
		int data_len = pkt_len - pkt.header.hdr_len;
		short from_port = ntohs(fromaddr.sin_port);
		in_addr_t from_IP = fromaddr.sin_addr.s_addr;
		char type = pkt.header.type;

		if (type == TYPE_WHOHAS) {
			ret = handle_whohas(from_IP, from_port,
					pkt.data, data_len);
			if (ret < 0) {
				Debug("handle_whohas error %d\n", ret);
			}
		}else if (type == TYPE_IHAVE) {
			ret = handle_ihave(from_IP, from_port,
					pkt.data, data_len);
			if (ret < 0) {
				Debug("handle_ihave error %d\n", ret);
			}
		}else if (type == TYPE_GET) {
			ret = handle_get(from_IP, from_port,
					pkt.data, data_len);
			if (ret < 0) {
				Debug("handle_get error %d\n", ret);
			}
		}else if (type == TYPE_DATA) {
		}else if (type == TYPE_ACK) {
		}else {
		}

	}else {
		Debug("recv_packet error %d\n", pkt_len);
	}
}
