/* icmp.h
**
** A great "thank you" to Lorenzo Cavallaro 'Gigi Sullivan' for the help 
** he gave me in writing this code.
**
** Copyright (C) 2001-02 Angelo Dell'Aera 'buffer' <buffer@users.sourceforge.net>  
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** All material for nonprofit, educational use only.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef _RAWICMP_H_
#define _RAWICMP_H_

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define MAXBUFFER 	256
#define DEFAULT_PKT_LEN 1500
#define SEND_TIMEOUT 	1
#define RECEIVE_TIMEOUT 5
#define TIMESTAMP_SIZE 	4
#define DEF_DATA_SIZE 	0
#define ECHO_DATA_SIZE 	36
#define TIME_DATA_SIZE 	-8
#define INFO_DATA_SIZE 	0
#define ADDR_DATA_SIZE 	-16
#define ERROR_DATA_SIZE  8
#define MAX_TIMEEXC_CODE 1
#define MAX_DESTUNREACH_CODE 15
#define MAX_REDIRECT_CODE 3
#define MAX_PARAMETER_CODE 2
#define LINK_MTU 1500
#define MAX_RETRIES_RCV 5

#define ATOI8(optarg)	((atoi(optarg) > UCHAR_MAX) ? UCHAR_MAX : (atoi(optarg)))
#define ATOI16(optarg)  ((atoi(optarg) > USHRT_MAX) ? USHRT_MAX : (atoi(optarg)))

#define RAWICMPVERSION "0.6.0"

struct ip_header_fields {
	uint8_t             tos;
	uint16_t            length;
	uint16_t            id;
	uint8_t             ttl;
	struct in_addr      src;
	struct sockaddr_in  dst;
	struct in_addr      router;
	uint8_t             error;
	uint8_t             fake_ttl;
	uint8_t             fake_proto;
	uint16_t            fake_id;
	uint16_t            fake_len;
	uint16_t            link_mtu;
	u_char              param_ptr;
};

struct ip_header_fields ip_header;

struct options {
	uint8_t        verbose;
	uint8_t        spoof;
	int            type;
	unsigned int   code;
	char           *dev;
	unsigned int   count;
};

extern unsigned short in_cksum(unsigned short *, int);
uint32_t orig_timestamp(void);
void resolve(struct sockaddr_in *, char *);
struct ip *ip_hdr_make(unsigned char *, int, struct ip_header_fields *);
struct icmp *icmp_hdr_make(unsigned char *, int, unsigned int, struct
			   ip_header_fields *);
int dlink_open(char *);
int code_make(unsigned int, int);
void verbose_iphdr(struct ip *);
void verbose_icmphdr(struct icmp *);
int data_size(int);
int Inet_pton(int, const char *, void *);
void init_ipheader(struct ip_header_fields *);
int proto(char *);
void timestamp_verbose(struct icmp *);
void timestampreply_verbose(struct icmp *);
void addressreply_verbose(struct icmp *);
int icmpreply(struct icmp *);
void dump(const char *, int);
void help(char *);
void parse_options(int, char **, struct options *, struct ip_header_fields *);
void init_opt(struct options *);

#endif	/* _RAWICMP_H_ */
