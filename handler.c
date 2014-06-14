#include "handler.h"
#include "transport.h"

/**
 * Handle command from user. aka 'GET ....'
 *
 * cmd: command string
 */
int handle_cmd(char *cmd)
{
	return HE_OK;
}

/**
 * This is called when you received a 'whohas' query.
 *
 * IP: the address who sent 'whohas'
 * buf: the content of 'whohas'
 * size: the size of buf
 */
int handle_whohas(int IP, short port, void *buf, size_t size)
{
	return HE_OK;
}

/**
 * This is called when you received a 'ihave' response.
 *
 * IP: the address who sent this
 * buf: content
 * size: size of buf
 */
int handle_ihave(int IP, short port, void *buf, size_t size)
{
	return HE_OK;
}


/**
 * This is called when you received a 'get' request.
 *
 * IP: the address of sender
 * buf: content
 * size: size of buf
 */
int handle_get(int IP, short port, void *buf, size_t size)
{
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
int handle_recv(int IP, short port, void *buf, size_t size)
{
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
