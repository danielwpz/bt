#include "transport.h"
#include "handler.h"
#include "chunk.h"
#include "debug.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define DATA_SIZE 1000

#define INIT_SWS  4

#define RESEND_TIME	(2 * SECOND_TICK)
#define REACK_TIME	(2 * SECOND_TICK)

#define MAX_ERR_CNT 7

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

struct _STATE {
	// general info
	in_addr_t IP;
	short port;
	int id;			/* Positive for sender, negative for receiver */
	// general data
	void *data;		/* SHOULD be chunk size (512 * 1024) */
	int max_seq;	/* Maximum sequence number */
	int err_cnt;	/* Count for error times */
	// sender
	int sws;		/* Send Window Size */
	int laf;		/* Last ACK	Frame */
	int lfs;		/* Last Frame Sent */
	int lack_cnt;	/* Count for lack */
	int *timeout_list;
	// receiver
	int lrf;		/* Last Received Frame */
	int ack_timeout;
};
typedef struct _STATE state_t;
	

/********************
 * Global Variables *
 ********************/
short kPort;	// local server port
int kfd;		// udp socket fd
int kpeer_num;	// number of all other peers
state_t *kstates_list;	// list of all state structures
int kid = 1;	// id for state

#define MIN(x, y) ((x) > (y)? (y) : (x))

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

	if (buf) {
		memcpy(pkt->data, buf, len);
	}
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
		pkt->header.hdr_len != sizeof(header_t)) {
		Debug("magic:%d, ver:%d, hdr_len:%d\n",
				pkt->header.magic,
				pkt->header.version,
				pkt->header.hdr_len);
		return TE_PKT;
	}	

	// copy data
	size_t datalen = pkt->header.pkt_len - pkt->header.hdr_len;
	memcpy(pkt->data, tmpp->data, datalen);

	return pkt->header.pkt_len;
}

/**
 * state functions
 */
static state_t *search_state(in_addr_t IP, short port)
{
	int i;
	state_t *result = NULL;

	for (i = 0; i < kpeer_num; i++) {
		if (kstates_list[i].IP == IP 
				&& kstates_list[i].port == port) {
			result = &kstates_list[i];
			break;
		}
	}

	return result;
}

static state_t *find_free_state()
{
	int i;
	state_t *result = NULL;

	for (i = 0; i < kpeer_num; i++) {
		if (kstates_list[i].IP == 0
				&& kstates_list[i].port == 0) {
			result = &kstates_list[i];
			break;
		}
	}

	return result;
}

static void init_send_state(state_t *state, 
		in_addr_t IP, 
		short port, 
		void *buf, 
		size_t size)
{
	// set up general info
	state->IP = IP;
	state->port = port;
	state->id = kid++;
	state->err_cnt = 0;

	// set up max seq
	state->max_seq = size / DATA_SIZE;
	if (size % DATA_SIZE) {
		state->max_seq++;
	}
	state->max_seq--;	// actual seq begins from 0

	// set up send field
	state->sws = INIT_SWS;
	state->laf = -1;
	state->lfs = -1;
	state->lack_cnt = 0;
	state->timeout_list = (int *)malloc(state->max_seq * sizeof(int));

	// set up data
	state->data = malloc(size);
	if (state->data == NULL) {
		Debug("[init_send_state]malloc data failed\n");
		return;
	}
	memcpy(state->data, buf, size);
}

static void init_recv_state(state_t *state,
		in_addr_t IP,
		short port,
		size_t size)
{
	// set up general info
	state->IP = IP;
	state->port = port;
	state->id = -kid++;
	state->err_cnt = 0;

	// set up max seq
	state->max_seq = size / DATA_SIZE;
	if (size % DATA_SIZE) {
		state->max_seq++;
	}
	state->max_seq--;	// actual seq begins from 0

	// set up receiver field
	state->lrf = -1;
	state->ack_timeout = 999999;

	// set up data
	state->data = malloc(size);
	if (state->data == NULL) {
		Debug("[init_recv_state]malloc data failed\n");
		return;
	}
}

static void deinit_state(state_t *state)
{
	state->IP = 0;
	state->port = 0;

	if (state->id > 0) {
		free(state->timeout_list);
	}

	free(state->data);

	state->id = 0;
}

/**
 * sender side functions
 */
static void reset_timer(state_t *state, int i)
{
	state->timeout_list[i] = RESEND_TIME;
}

static int send_frag(state_t *state, int i)
{
	int len;
	int ret;

	// calculate length to send
	if ((i + 1) * DATA_SIZE < BT_CHUNK_SIZE) {
		len = DATA_SIZE;
	}else {
		len = BT_CHUNK_SIZE - (i * DATA_SIZE);
	}

	// make packet
	packet_t pkt;
	ret = make_packet(&pkt, TYPE_DATA, i, 0,
		state->data + (i * DATA_SIZE), len);
	if (ret < 0) {
		Debug("[send_frag]make_packet error %d\n", ret);
		return ret;
	}

	// send packet
	ret = send_packet(state->IP, state->port, &pkt);
	if (ret < 0) {
		Debug("[send_frag]send_packet error %d\n", ret);
		return ret;
	}

	reset_timer(state, i);

	return TE_OK;
}	

static int send_to_up(state_t *state)
{
	int i, ret;
	int lower = state->lfs + 1;
	int upper = MIN(state->max_seq, (state->laf + state->sws));

	if (upper < lower && (lower <= state->max_seq)) {
		// TODO: dump_state(state);
		return TE_WIN;
	}

	for (i = lower; i <= upper; i++) {
		ret = send_frag(state, i);
		if (ret < 0) {
			Debug("[send_to_up]send_frag error %d\n", ret);
			return ret;
		}
	}

	state->lfs = upper;

	return TE_OK;
}

static int reply_ack(in_addr_t IP, 
		short port, 
		int ack_num, 
		state_t *state)
{
	char *desc = "[reply_ack]";
	int ret;

	packet_t pkt;
	ret = make_packet(&pkt, TYPE_ACK, -1, ack_num, NULL, 0);
	if (ret < 0) {
		Debug("%smake_packet error %d\n", desc, ret);
		return ret;
	}

	ret = send_packet(IP, port, &pkt);
	if (ret < 0) {
		Debug("%ssend ack packet error %d\n", desc, ret);
		return ret;
	}

	// reset ack timeout
	state->ack_timeout = REACK_TIME;

	return TE_OK;
}


/**
 * Interface function of transport layer
 * used by upper layer
 */
int send_init(int peer_num, short port)
{
	int i;
	kPort = port;
	kpeer_num = peer_num;

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

	// init states_list
	kstates_list = (state_t *)malloc(peer_num * sizeof(state_t));
	if (kstates_list == NULL) {
		Debug("malloc kstates_list failed.\n");
		return TE_MEM;
	}
	
	for (i = 0; i < peer_num; i++) {
		kstates_list[i].IP = 0;
		kstates_list[i].port = 0;
		kstates_list[i].id = 0;
	}

	return TE_OK;
}

int send_data(in_addr_t IP, short port, void *buf, size_t size)
{
	int ret;
	char *desc = "[send_data]";
	state_t *state;

	/* Test mode
	if (size != BT_CHUNK_SIZE) {
		Debug("data size invalid %d\n", size);
		return TE_SIZE;
	}
	*/
	
	// check whether there is come connections with
	// given peer
	state = search_state(IP, port);
	if (state) {
		Debug("%salready connect with %d:%d\n",desc, IP, port);
		return TE_ALREADY;
	}

	// use a new state
	state = find_free_state();
	if (state == NULL) {
		Debug("%sNO empty state\n", desc);
		return TE_FULL;
	}

	init_send_state(state, IP, port, buf, size);

	ret = send_to_up(state);
	if (ret < 0) {
		Debug("%ssend_to_up error %d\n", desc, ret);
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
 * inter-communication handler
 */
static int on_ack(in_addr_t IP, short port, packet_t *pkt)
{
	int ret;
	int ack_num = pkt->header.ack_num;

	state_t *state = search_state(IP, port);
	if (state == NULL) {
		return TE_NOSTATE;
	}

	// since the receiver is still alive,
	// we reset err_cnt
	state->err_cnt = 0;

	if (ack_num < state->laf) {
		return TE_OLDACK;
	}

	if (ack_num == state->max_seq) {
		// TODO finish send
		Debug("[on_ack]send finish!(%d:%d)\n", IP, port);
		deinit_state(state);
		return TE_OK;
	}

	// check last ack
	if (state->laf == ack_num) {
		state->lack_cnt++;

		// fast resend
		if (state->lack_cnt >= 2) {
			// reset lfs to resend
			// TEST
			Debug("[on_ack]resend data %d\n", ack_num);
			state->lfs = ack_num;
		}else {
			// duplicate ACKs but no need to resend
			return TE_OK;
		}
	}else {
		state->laf = ack_num;
		state->lack_cnt = 0;
	}

	ret = send_to_up(state);
	if (ret < 0) {
		Debug("[on_ack]send_to_up error %d\n", ret);
		return ret;
	}

	return TE_OK;
}

static int on_data(in_addr_t IP, short port, packet_t *pkt)
{
	int ret;
	char *desc = "[on_data]";
	int seq_num = pkt->header.seq_num;
	state_t *state = search_state(IP, port);

	if (seq_num > 0 && state == NULL) {
		return TE_NOSTATE;
	}

	// first data pkt
	if (seq_num == 0 && state == NULL) {
		state = find_free_state();
		if (state == NULL) {
			Debug("%son free state\n", desc);
			return TE_FULL;
		}

		init_recv_state(state, IP, port, BT_CHUNK_SIZE);
	}

	// since the sender is still alive,
	// we reset the err_cnt
	state->err_cnt = 0;

	// receive expected
	if (seq_num == state->lrf + 1) {
		// TEST
		// no reply ack
		static int a = 0;
		if (seq_num % 64 == 2 && a == 0) {
			a++;
			return 0;
		}else {
			a = 0;
		}

		// record data
		memcpy((state->data + (seq_num * DATA_SIZE)),
				pkt->data,
				(pkt->header.pkt_len - pkt->header.hdr_len));

		// reply ack
		ret = reply_ack(IP, port, seq_num, state);
		if (ret < 0) {
			Debug("%sreply_ack error %d\n", desc, ret);
			return ret;
		}

		// update lrf
		state->lrf = seq_num;

		// check finish
		if (seq_num == state->max_seq) {
			// TODO finish
			// deinit state after upper level get data
			ret = handle_recv(IP, port, state->data, BT_CHUNK_SIZE);
			if (ret < 0) {
				Debug("%shandle_recv error %d\n", desc, ret);
				return ret;
			}
			deinit_state(state);
		}
	}

	return TE_OK;
}


/**
 * General failure check here.
 * Change the congestion state or up-call user
 */
static void check_error(state_t *state)
{
	state->err_cnt++;
	if (state->err_cnt > MAX_ERR_CNT) {
		Debug("[check_error] %d:%d fail.\n", state->IP, state->port);
		handle_failure(state->IP, state->port);
		// TODO tear down state
		deinit_state(state);
	}
}

/**
 * Interfaces to under layer
 */
void process_timer(int interval)
{
	int i, j, ret;
	int from, to;
	char *desc = "[process_timer]";

	// tranverse states list, update timer
	for (i = 0; i < kpeer_num; i++) {
		// check if state[i] is valid
		if (kstates_list[i].IP && kstates_list[i].port) {
			int has_error = 0;

			if (kstates_list[i].id > 0) {	// sender
				from = kstates_list[i].laf + 1;
				to = kstates_list[i].lfs;

				for (j = from; j <= to; j++) {
					// update timer for jth frame
					kstates_list[i].timeout_list[j] -= interval;
					if (kstates_list[i].timeout_list[j] <= 0) {
						// resend frame
						// TEST
						Debug("%sresend data %d\n", desc, j);

						has_error = 1;
						ret = send_frag(&kstates_list[i], j);
						if (ret < 0) {
							Debug("%ssend_frag error %d\n", desc, ret);
							return;
						}
					}
				}

			}else if (kstates_list[i].id < 0) {	// receiver
				kstates_list[i].ack_timeout -= interval;

				if (kstates_list[i].ack_timeout <= 0) {
					has_error = 1;
					// resend ack
					in_addr_t IP = kstates_list[i].IP;
					short port = kstates_list[i].port;
					int ack_num = kstates_list[i].lrf;
					// TEST
					Debug("%sresend ack %d\n", desc, ack_num);

					ret = reply_ack(IP, port, ack_num, 
							&kstates_list[i]);
					if (ret < 0) {
						Debug("%sreply_ack error %d\n", desc, ret);
						return;
					}
				}

			}else {
				// valid state but id == 0
				Debug("%sid == 0\n", desc);
				return;
			}

			if (has_error) {
				check_error(&kstates_list[i]);
			}
		}
	}

	// up call
	handle_timer(interval);
}

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
			ret = on_data(from_IP, from_port, &pkt);
			if (ret < 0) {
				Debug("on_data error %d\n", ret);
			}
		}else if (type == TYPE_ACK) {
			ret = on_ack(from_IP, from_port, &pkt);
			if (ret < 0) {
				int ack_num = pkt.header.ack_num;
				Debug("on_ack %d error %d\n", ack_num, ret);
			}
		}else {
			Debug("unknown TYPE:%d\n", type);
		}

	}else {
		Debug("recv_packet error %d\n", pkt_len);
	}
}
