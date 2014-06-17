#include "handler.h"
#include "transport.h"
#include "debug.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Handle command from user. aka 'GET ....'
 *
 * cmd: command string
 */
int handle_cmd(char *cmd)
{
	char *desc = "[hdl_cmd]";

	Debug("%s%s\n", desc, cmd);

	return HE_OK;
}

/**
 * This is called when you received a 'whohas' query.
 *
 * IP: the address who sent 'whohas'
 * buf: the content of 'whohas'
 * size: the size of buf
 */
int handle_whohas(in_addr_t IP, short port, void *buf, size_t size)
{
	char *desc = "[hdl_whohas]";
	struct in_addr addr = {IP};
	char *IPStr = inet_ntoa(addr);

	Debug("%s(%s, %d, %d)\n", desc, IPStr, port, (int)size);
	Debug("%s\n", (char *)buf);

	return HE_OK;
}

/**
 * This is called when you received a 'ihave' response.
 *
 * IP: the address who sent this
 * buf: content
 * size: size of buf
 */
int handle_ihave(in_addr_t IP, short port, void *buf, size_t size)
{
	char *desc = "[hdl_ihave]";
	struct in_addr addr = {IP};
	char *IPStr = inet_ntoa(addr);

	Debug("%s(%s, %d, %d)\n", desc, IPStr, port, (int)size);
	Debug("%s\n", (char *)buf);

	return HE_OK;
}


/**
 * This is called when you received a 'get' request.
 *
 * IP: the address of sender
 * buf: content
 * size: size of buf
 */
int handle_get(in_addr_t IP, short port, void *buf, size_t size)
{
	char *desc = "[hdl_get]";
	struct in_addr addr = {IP};
	char *IPStr = inet_ntoa(addr);

	Debug("%s(%s, %d, %d)\n", desc, IPStr, port, (int)size);
	Debug("%s\n", (char *)buf);

	return HE_OK;
}

/**
 * This is called when you've successfully received
 * a chunk from one peer.
 *
 * IP:	the address who sent it
 * buf: content
 * size: size of buf
 */
int handle_recv(in_addr_t IP, short port, void *buf, size_t size)
{
	char *desc = "[hdl_recv]";
	struct in_addr addr = {IP};
	char *IPStr = inet_ntoa(addr);

	Debug("%s(%s, %d, %d)\n", desc, IPStr, port, (int)size);
	Debug("%s\n", (char *)buf);

	return HE_OK;
}

/**
 * This is called every certain seconds,
 * use this function to do some timer job.
 *
 * interval: number of seconds passed since last call
 */
int handle_timer(int interval)
{
	return HE_OK;
}

/**
 * This is called when a peer, either you send data
 * to it or it receives data from you, has crushed.
 *
 * IP: the address of who has failed to connect
 */
int handle_failure(in_addr_t IP, short port)
{
	char *desc = "[hdl_failure]";
	struct in_addr addr = {IP};
	char *IPStr = inet_ntoa(addr);

	Debug("%s(%s, %d)\n", desc, IPStr, port);

	return HE_OK;
}
