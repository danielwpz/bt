#include "transport.h"

int send_init(int peer_num, short port)
{
	return TE_OK;
}

int send_data(int IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_whohas(int IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_ihave(int IP, short port, void *buf, size_t size)
{
	return TE_OK;
}

int send_get(int IP, short port, void *buf, size_t size)
{
	return TE_OK;
}
