#include "handler.h"
#include "chunk.h"
#include "transport.h"
#include "debug.h"
#include "sha.h"
#include "bt_parse.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

uint8_t *target_hash;
bt_config_t *config;
in_addr_t myIP;
uint8_t *i_have_hash;
uint8_t *master_hash;
a_peer *target_peer;

int recv_result[BUF_LEN];

char i_have_filename[BT_FILENAME_LEN];

void hd_init(bt_config_t* config_ptr, in_addr_t IP) {
	config = (bt_config_t *) malloc(sizeof(bt_config_t));
	memcpy(config->chunk_file, config_ptr->chunk_file, BT_FILENAME_LEN);
	memcpy(config->has_chunk_file, config_ptr->has_chunk_file, BT_FILENAME_LEN);
	memcpy(config->output_file, config_ptr->output_file, BT_FILENAME_LEN);
	memcpy(config->peer_list_file, config_ptr->peer_list_file, BT_FILENAME_LEN);
	config->max_conn = config_ptr->max_conn;
	config->identity = config_ptr->identity;
	config->myport = config_ptr->myport;
	config->argc = config_ptr->argc;
	config->peers = config_ptr->peers;

	myIP = IP;

	target_hash = (uint8_t *) malloc(BUF_LEN*SHA1_HASH_SIZE+4);
	i_have_hash = (uint8_t *) malloc(BUF_LEN*SHA1_HASH_SIZE+4);
	master_hash = (uint8_t *) malloc(BUF_LEN*SHA1_HASH_SIZE+4);
	target_peer = (a_peer *) malloc(sizeof(a_peer)*BUF_LEN);
	bzero(target_hash, BUF_LEN*SHA1_HASH_SIZE+4);
	bzero(i_have_hash, BUF_LEN*SHA1_HASH_SIZE+4);
	bzero(master_hash, BUF_LEN*SHA1_HASH_SIZE+4);
	bzero(target_peer, sizeof(a_peer)*BUF_LEN);
	

	

	FILE *f;

	if ((f = fopen(config->output_file, "wb+")) == NULL)
		Debug("config->output_file create failed\n");
	fclose(f);

	if ((f = fopen(config->has_chunk_file, "r")) == NULL) 
		Debug("config->has_chunk_file doesn't exist\n");
	read_chunks(f, i_have_hash);
	fclose(f);
	if ((f = fopen(config->chunk_file, "r")) == NULL) 
		Debug("config->chunk_file doesn't exist\n");
	read_chunks(f, master_hash);
	fclose(f);

	char *temp;
	temp = config->has_chunk_file;
	int j = 0;
	while (!(*(temp+j)=='.'&&*(temp+j+1)=='c')) {
		i_have_filename[j] = temp[j];
		j++;
	}
	i_have_filename[j]='.';
	i_have_filename[j+1]='t';
	i_have_filename[j+2]='a';
	i_have_filename[j+3]='r';
	i_have_filename[j+4]='\0';
}




/**
 * Handle command from user. aka 'GET ....'
 *
 * cmd: command string
 */
int handle_cmd(char *cmd)
{
	char *desc = "[hdl_cmd]";

	FILE *f;
	unsigned long file_length;
	
	char command[BUF_LEN];
	char target_file[BT_FILENAME_LEN];
	char rename_file[BT_FILENAME_LEN];
	bzero(target_file, BT_FILENAME_LEN*sizeof(char));
	bzero(rename_file, BT_FILENAME_LEN*sizeof(char));
	

	int index;
	

	int count = 0;

	if (sscanf(cmd, "%s %s %s", command, target_file, rename_file) == 0)
		Debug("Can't read command GET <target-file>\n");
	

	if (strcasecmp(command, "get") == 0) {
		if (rename_file[0]!='\0') {
		if (target_file[0]!='\0') {
			if ((f = fopen(target_file, "r")) == NULL) {
				Debug("%s doesn't exist\n", target_file);
				
			}
			read_chunks(f, target_hash);
			if (memcpy(config->output_file, rename_file, strlen(rename_file)) < 0)
				Debug("rename_file copy fail\n");
			
		} else {
			Debug("second command argument error\n");
		}
		} else {
			Debug("third command argument error\n");
		}
	} else {
		Debug("first command argument error\n");
	}

	bt_peer_t *temp = config->peers;
	bzero(recv_result, sizeof(int)*BUF_LEN);
	while (temp!=NULL) {
		Debug("id:%d\n", temp->id);
		if (temp->id!=config->identity) {
			send_whohas(temp->addr.sin_addr.s_addr, ntohs(temp->addr.sin_port), target_hash, (*target_hash) * SHA1_HASH_SIZE+4);
			
		}
		temp  = temp->next;
	}

	
	
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
	//Debug("%s\n", (char *)buf);

	
	uint8_t *i_have;
	i_have = (uint8_t *) malloc(BUF_LEN*SHA1_HASH_SIZE+4);
	*i_have = 0;
	print_packet((uint8_t *)buf, (int)size);
	uint8_t j;
	j = *(uint8_t *)buf;
	int i,k;
	int have = 0;
	for (i = 0; i < j; i++) {
		for (k = 0; k < *i_have_hash; k++) {
			if (compare_hash(i_have_hash+4+SHA1_HASH_SIZE*k, (uint8_t *)buf+4+SHA1_HASH_SIZE*i)) {
				memcpy(i_have+4+SHA1_HASH_SIZE*(*i_have), i_have_hash+4+SHA1_HASH_SIZE*k, SHA1_HASH_SIZE);
				(*i_have)++;
				have = 1;
				break;
			}
		}
	}
	Debug("I have:\n");
	print_packet(i_have, 4+i_have[0]*SHA1_HASH_SIZE);

	if (have) 
		send_ihave(IP, port, i_have, 4+i_have[0]*SHA1_HASH_SIZE);
	else
		Debug("Have no required chunks\n");
	free(i_have);
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
	print_packet((uint8_t *)buf, (int)size);

	int lock = 0;

	int i,j;
	for(i = 0; i < *target_hash; i++) {
		for (j = 0; j < *(uint8_t *)buf; j++) {
			if (compare_hash(target_hash+4+i*SHA1_HASH_SIZE, (uint8_t *)buf+4+j*SHA1_HASH_SIZE) && (!recv_result[i])) {
				
				if (!target_peer[i].valid) {
					target_peer[i].IP = IP;
					target_peer[i].port = port;
					target_peer[i].valid = 1;
					target_peer[i].next = NULL;
					if (!lock) {
						target_peer[i].sending = 1;
						send_get(IP, port, target_hash+4+i*SHA1_HASH_SIZE,
							SHA1_HASH_SIZE);
						lock = 1;  //连续的下一次不能再发送
					} else {
						target_peer[i].sending = 0;
					}
				} else {
					int send = 1; //排序不是第一个，但也有可能成为发送者
					a_peer *more_peer = (a_peer *) malloc(sizeof(a_peer));
					more_peer->IP = IP;
					more_peer->port = port;
					more_peer->valid = 1;
					more_peer->next = NULL;
					a_peer *temp = target_peer+i*sizeof(a_peer);
					while (temp->next!=NULL) {
						if (temp->sending==1) {
							send = 0; //前方有人正在发送，则不再发送
						}
						temp = temp->next;
					}
					if (send && !lock) {
						more_peer->sending = 1;
						send_get(IP, port, target_hash+4+i*SHA1_HASH_SIZE,
							SHA1_HASH_SIZE);
						lock = 1;
					} else {
						more_peer->sending = 0;
					}
					temp->next = more_peer;
				}
			}
		}
	}

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
	print_packet((uint8_t *)buf, (int)size);

	FILE *f;
	char *sendbuf;
	int index = 0;
	int i;
	for(i = 0; i < *i_have_hash; i++) {
		if (compare_hash(i_have_hash+4+i*SHA1_HASH_SIZE, (uint8_t *)buf)) {
			if ((f = fopen(i_have_filename, "r")) == NULL) {
				Debug("I_have_filename:%s doesn't exist\n",i_have_filename);
				return HE_NOFILE;
			}
			if ((sendbuf=mmap(NULL, (*i_have_hash)*BT_CHUNK_SIZE , PROT_READ|PROT_WRITE, MAP_SHARED , f, 0))<0)
				Debug("mmap error in %s",desc);
			index = i;
			break;
		}
	}

	if ((send_data(IP, port, sendbuf+index*BT_CHUNK_SIZE, BT_CHUNK_SIZE))<0)
		Debug("send_data failed");

	if ((munmap(sendbuf, (*i_have_hash)*BT_CHUNK_SIZE))<0)
		Debug("munmap failed");
	fclose(f);
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
	//Debug("%s\n", (char *)buf);

	FILE *f;
	uint8_t *temp;
	shahash(temp, (int)size, (uint8_t *)buf);

	print_packet(temp, SHA1_HASH_SIZE);
	int i;
	for(i = 0; i < *target_hash; i++) {
		if (compare_hash(target_hash+4+i*SHA1_HASH_SIZE, temp)) {
			recv_result[i] = 1;
			target_peer[i].valid = 0;
			target_peer[i].sending = 0;
			freelinkedlist(target_peer[i].next);
			
			
			//写文件
			void *ptr;
			if ((f = fopen(config->output_file, "rw")) == NULL)
				Debug("config->output_file OPEN failed\n");
			if ((ptr=mmap(NULL, (*target_hash)*BT_CHUNK_SIZE , PROT_READ|PROT_WRITE,
					MAP_SHARED , f, 0))<0)
				Debug("mmap error in %s\n",desc);
			if (memcpy(ptr+i*BT_CHUNK_SIZE, buf, size)<0)
				Debug("Write file failed\n");
			munmap(ptr, (*target_hash)*BT_CHUNK_SIZE);
			fclose(f);

			break;
		}
	}




	for(i = 0; i < *target_hash; i++) {
		if (!recv_result[i]) {
			int send = 0;
			a_peer *temp2 = target_hash + i * sizeof(a_peer);
			a_peer *temp3;
			while (temp2!=NULL) {
				if (temp2->IP==IP&&temp2->port==port&&(temp2->valid)) {
					send = 1;
					temp3 = temp2;
				}
				if (temp2->sending == 1)
					send = 0;
				temp2 = temp2->next;
			}
			if(send) {
				send_get(IP, port, target_hash+4+i*SHA1_HASH_SIZE,
							SHA1_HASH_SIZE);
				temp3->sending = 1;
			}

		}
	}

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


int read_chunks(FILE *f, uint8_t *hash_list) {
	char line[BUF_LEN];
	char hash_string[BUF_LEN];
	int index;
	int start = 0;
	while (fgets(line, BUF_LEN, f) != NULL) {
		if (line[0] == '0') start = 1;
		if (start) {
    		if (sscanf(line, "%d %s", &index, hash_string) == 0) 
				Debug("read index & hash_string error\n");
			hex2binary(hash_string, strlen(hash_string),
					hash_list+index*SHA1_HASH_SIZE+4);
		}
	}
	
	*hash_list = index+1;
	int i;
	for (i = 0; i < (index+1)*SHA1_HASH_SIZE+4;i++) {
		Debug("%x",*(hash_list+i));
	}
	Debug("\n");
	return 0;
}



int compare_hash(uint8_t *a, uint8_t *b) {
	int same = 1;
	int i;
	for (i = 0; i < SHA1_HASH_SIZE; i++) {
		//Debug("a:%x b:%x\n",*(a+i),*(b+i));
		if (*(a+i)!=*(b+i)) {
			same = 0;
			break;
		}
	}
	Debug("Comparing hash: %d\n", same);
	return same;
}

void print_packet(uint8_t *buf, int size) {
	int i;
	Debug("printpacket:");
	for (i = 0; i < size;i++) {
		Debug("%x",*(buf+i));
	}
	Debug("\n");
}

void freelinkedlist(a_peer *head) {
	if (head == NULL)
		return;
	freelinkedlist(head->next);
	
	if (head->next==NULL) {
		free(head);
		head = NULL;
	}
	return;
}
