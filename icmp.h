/* icmp.h
**
** Copyright (C) 2001-03 Angelo Dell'Aera 'buffer' <buffer@antifork.org>  
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

#define RAWICMPVERSION VERSION

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

struct options {
	uint8_t        verbose;
	uint8_t        spoof;
	int            type;
	unsigned int   code;
	char           *dev;
	unsigned int   count;
};

struct rtt_stats_t {
	u_int32_t      min;
	u_int32_t      max;
	u_int32_t      sum;
};

extern unsigned short in_cksum(unsigned short *, int);
uint32_t orig_timestamp(void);
void resolve(struct sockaddr_in *, char *);
struct ip *ip_hdr_make(unsigned char *, int, struct ip_header_fields *);
struct icmp *icmp_hdr_make(unsigned char *, int, unsigned int, struct ip_header_fields *);
int dlink_open(char *);
int data_size(int);
void init_and_parse_options(int, char **, struct options *, struct ip_header_fields *);
void stats_report(int, struct rtt_stats_t);
void init_rtt_stats(struct rtt_stats_t *);
void init_dst(struct sockaddr_in *, struct ip_header_fields *);
int Socket(int, int, int);
void Setsockopt(int, int, int, const void *, socklen_t);
int Select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
ssize_t Sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t Recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
int Dlink_open(char *);
void *Calloc(size_t, size_t);
void send_report(int, struct options, struct ip *, struct icmp *,
                 struct ip_header_fields, unsigned char *, int);
u_int32_t rtt_evaluate(u_int32_t);
void update_rtt_stats(u_int32_t, struct rtt_stats_t *);
void receive_report(int, struct options, struct ip *, struct icmp *,
                    unsigned char *, int);
int proto(char *);
int icmp_reply(struct icmp *);
void dump(const char *, int);
void help(char *);

#endif	/* _RAWICMP_H_ */
