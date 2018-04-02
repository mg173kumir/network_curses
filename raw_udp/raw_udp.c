#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFLEN 100

struct _udp_header {
	unsigned short src_port;
	unsigned short dest_port;
	unsigned short len;
	unsigned short chk_summ;
};

struct _ip_header {
	// version
	unsigned char vhl;
	// service type
	unsigned char tos;
	// total len
	unsigned short len;
	// id
	unsigned short id;
	// offset
	unsigned short offset;
	// time to live
	unsigned char ttl;
	// protocol
	unsigned char protocol;
	// check sum
	unsigned short checksum;
	// source and destination address
	struct in_addr src, dst;
};

unsigned int _crc16_ip(char *buf) {
	unsigned int sum = 0;
	unsigned short *word = (unsigned short *) buf;
	for (int i = 0; i < 10; ++i, ++word) {
		sum += word;
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum;
	return sum;
}

void _udp_wrapper (char *buf, int offset, char *port, int msg_len) {
	struct _udp_header *uh;
	// udp header filling
	uh = (struct _udp_header *)(buf + offset);
	// 7777 - for recognize this raw socket
	uh->src_port = htons(7777);
	uh->dest_port = htons(atoi(port));
	// 8 - size of udp header
	uh->len = htons(msg_len + 8);
	// chk summ ignor if equal to zero
	uh->chk_summ = 0;
}

void _ip_wrapper (char *buf, char *address, int all_len) {
	struct _ip_header *ih;
	// ip header filling
	ih = (struct _ip_header *) buf;
	ih->vhl = (4 << 4) | 5;
	ih->tos = 0;
	// 20 - ip header size, 14 - udp header size + payload size
	ih->len = htons(20 + 14);
	ih->id = 12345;
	ih->ttl = 64;
	ih->offset = 0;
	// 17 - udp constant
	ih->protocol = 17;
	ih->checksum = 0;
	ih->src.s_addr = inet_addr(address);
	ih->dst.s_addr = inet_addr(address);
	ih->checksum = htons(_crc16_ip(buf));
}

void _headers_print (char *buf) {
	unsigned short *u_src = &buf[20];
	unsigned short *u_dest = &buf[22];
	unsigned short *u_len = &buf[24];
	unsigned short *u_chk = &buf[26];
	printf("udp header: %d %d %d %d\n", *u_src, *u_dest, ntohs(*u_len), *u_chk);
}

int main (int argc, char **argv) {
	int raw_socket, length_addr;
	struct sockaddr_in addr;

	printf("%s", "init net...");
	if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
		perror("[fail] - e1");
		exit(1);
	}

	// enable user ip header
	int val = 1;
	setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(atoi(argv[2]));
	printf("%s\n", "[done]");

	char *buf = malloc(BUFFLEN);
	bzero(buf, BUFFLEN);

	_udp_wrapper(buf, 20, argv[2], sizeof("hello"));
	_ip_wrapper(buf, argv[1], sizeof("hello") + 8);
	_headers_print(buf);
	strncat(buf + 28, "hello", 5);

	printf("%s", "send packet...");
	if (sendto(raw_socket, buf, sizeof("hello") + 28,
	 NULL, &addr, sizeof(addr)) <= 0) {
		perror("[fail] - e2");
		exit(1);
	}
	printf("%s\n", "[done]");
	
	printf("%s\n", "getting answer...");
	unsigned short right_dest = htons(7777);
	struct _udp_header *uh;
	do {
		bzero(buf, BUFFLEN);
		length_addr = sizeof(addr);
		if (recvfrom(raw_socket, buf, BUFFLEN,
	 		NULL, &addr, &length_addr) < 0) {
			perror("[fail] - e3");
			exit(1);
		}
		uh = (struct _udp_header *) (buf + 20);
		printf("udp header: %d %d %d %d %s\n", uh->src_port, uh->dest_port, ntohs(uh->len), uh->chk_summ, buf + 28);
	} while (uh->dest_port != right_dest);
	printf("%s\n", "[done]");
	printf("answer: %s\n", buf + 28);
	free(buf);
	close(raw_socket);
}