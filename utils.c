/* utils.c
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

#include <signal.h>
#include "icmp.h"
#include "option.h"

/* 
 * Initialization functions
 */

void init_ipheader(struct ip_header_fields *iphf)
{
	iphf->tos = 0;
	iphf->length = 0;
	iphf->id = 0;
	iphf->ttl = IPDEFTTL;
	iphf->src.s_addr = htonl(INADDR_ANY);
	iphf->dst.sin_addr.s_addr = 0;
	iphf->router.s_addr = 0;
	iphf->error = 0;
	iphf->fake_ttl = 0;
	iphf->fake_proto = IPPROTO_TCP;
	iphf->fake_id = 0;
	iphf->fake_len = 0;
	iphf->link_mtu = 0;
	iphf->param_ptr = 0;
}


void init_opt(struct options *opt)
{
        opt->verbose = 0;
        opt->spoof = 0;
        opt->type = ICMP_ECHO;
        opt->code = 0;
        opt->dev = NULL;
        opt->count = ~0;
}


void init_dst(struct sockaddr_in *to, struct ip_header_fields *h)
{

	if (!h->dst.sin_addr.s_addr) {
		printf("Must specify IP destination address!\n\n");
                exit(EXIT_FAILURE);
        }

	memset(to, 0, sizeof(struct sockaddr_in));
        to->sin_family = AF_INET;
        to->sin_addr = h->dst.sin_addr;
}

/* 
 * RTT evaluation functions
 */

void init_rtt_stats(struct rtt_stats_t *stats)
{

	stats->min = ~0;
	stats->max = stats->sum = 0;
}


void update_rtt_stats(u_int32_t rtt, struct rtt_stats_t *stats)
{

	if (rtt < stats->min)
		stats->min = rtt;
	if (rtt > stats->max)
		stats->max = rtt;
	stats->sum += rtt;
}


u_int32_t rtt_evaluate(u_int32_t t_send)
{

        return (htonl(orig_timestamp()) - t_send);
}


int proto(char *protocol)
{

	if (!strcmp(protocol, "tcp"))
		return (IPPROTO_TCP);
	else if (!strcmp(protocol, "udp"))
		return (IPPROTO_UDP);
	else {
		fprintf(stderr, "Protocol not know!\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}


/*
 * Some useful wrappers
 */


int Socket(int domain, int type, int protocol)
{

	int sockfd;

	if ( (sockfd = socket(domain, type, protocol)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}


void Setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{

	if (setsockopt(s, level, optname, optval, optlen)) {
		perror("setsockopt");
                exit(EXIT_FAILURE);
        }
}


int Select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) 
{

	int res;
	
	if ( (res = select(n, readfds, writefds, exceptfds, timeout)) < 0) {
		perror("select");
		exit(EXIT_FAILURE);
	}

	return res;
}


ssize_t Sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) 
{
	ssize_t res;

	if ( (res = sendto(s, msg, len, flags, to, tolen)) < 0) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}

	return res;
}


ssize_t Recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	ssize_t res;

	if ( (res = recvfrom(s, buf, len, flags, from, fromlen)) < 0) {
		perror("recvfrom");
		exit(EXIT_FAILURE);
	}

	return res;
}


int Inet_pton(int af, const char *src, void *dst)
{

	int res;

	if ((res = inet_pton(af, src, dst)) < 0) {
		perror("inet_pton error");
		exit(EXIT_FAILURE);
	} else if (res == 0) {
		printf("No valid network address!\n");
		exit(EXIT_FAILURE);
	}

	return (1);
}


int Dlink_open(char *dev)
{
	int sd;

	if ((sd = dlink_open(dev)) < 0) {
                perror("dlink_open");
                exit(EXIT_FAILURE);
        }

	return sd;
}


void *Calloc(size_t nmemb, size_t size) 
{

	void *buffer;

	if ((buffer = calloc(nmemb, size)) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}

	return buffer;
}

/*
 * Functions for verbose output
 */


static inline void verbose_iphdr(struct ip *iphdr)
{
        printf("IP Identification Number : %d  ", ntohs(iphdr->ip_id));
        printf("Time To Live : %d\n", iphdr->ip_ttl);
}


static inline void timestamp_verbose(struct icmp *icmphead)
{
        printf("\nOriginate Timestamp : %x  ", ntohl(icmphead->icmp_otime));
}


static inline void timestampreply_verbose(struct icmp *icmphead)
{
        printf("\nOriginate Timestamp : %x  ", ntohl(icmphead->icmp_otime));
        printf("Receive Timestamp : %x  ", ntohl(icmphead->icmp_rtime));
        printf("Transmit Timestamp : %x  ", ntohl(icmphead->icmp_ttime));
}


static inline void addressreply_verbose(struct icmp *icmphead)
{
        printf("Subnet Address Mask : %x\n", ntohl(icmphead->icmp_mask));
}


static inline void verbose_icmphdr(struct icmp *icmphdr)
{

        extern char *icmptype[];
        extern char *unreach_codes[];
        extern char *timeexc_codes[];
        extern char *redirect_codes[];
        uint8_t error = 0;

        printf("ICMP type : %s  ", icmptype[icmphdr->icmp_type]);

        switch (icmphdr->icmp_type) {
        case ICMP_SOURCE_QUENCH:
        case ICMP_PARAMETERPROB:
                error = 1;
                break;
        case ICMP_DEST_UNREACH:
                printf("ICMP code : %s ",
                       unreach_codes[icmphdr->icmp_code]);
                error = 1;
                break;
        case ICMP_TIME_EXCEEDED:
                printf("ICMP code : %s ",
                       timeexc_codes[icmphdr->icmp_code]);
                error = 1;
                break;
        case ICMP_REDIRECT:
                printf("ICMP code : %s ",
                       redirect_codes[icmphdr->icmp_code]);
                error = 1;
                break;
        default:
                break;
        }

        if (!error) {
                printf("ICMP Sequence Number : %d  ", ntohs(icmphdr->icmp_seq));
                printf("ICMP ID Number : %d  ", ntohs(icmphdr->icmp_id));
        }

        switch (icmphdr->icmp_type) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
                break;
        case ICMP_TIMESTAMP:
                timestamp_verbose(icmphdr);
               break;
        case ICMP_TIMESTAMPREPLY:
                timestampreply_verbose(icmphdr);
                break;
        case ICMP_INFO_REQUEST:
                /*
                 ** Vedere l'RFC per ICMP_INFO_REPLY
                 */
        case ICMP_INFO_REPLY:
        case ICMP_ADDRESS:
                break;
        case ICMP_ADDRESSREPLY:
                addressreply_verbose(icmphdr);
                break;
        default:
                break;

        }

        printf("\n");
}


static inline void generic_report(struct options opt, struct ip *ip, struct icmp *icmp,
				  unsigned char *buffer, int packlen)
{
	verbose_iphdr(ip);
	verbose_icmphdr(icmp);
	if (opt.verbose > 1)
		dump(buffer, packlen);
}


void send_report(int i, struct options opt, struct ip *ip, struct icmp *icmp,
		 struct ip_header_fields ip_header, unsigned char *buffer, int packlen)
{

	extern char *icmptype[];

	printf("\n\nICMP request %d\n", i + 1);
	printf("==================\n");
	if (opt.spoof)
		printf("Spoofed source IP : %s\n", inet_ntoa(ip_header.src));

	if (opt.verbose) 
		generic_report(opt, ip, icmp, buffer, packlen);
	else
		printf("\nSending an ICMP type %s to %s (amount of bytes %d)...\n",
		       icmptype[opt.type], inet_ntoa(ip_header.dst.sin_addr), packlen);
}


void receive_report(int i, struct options opt, struct ip *ip, struct icmp *icmp,
		    unsigned char *buffer, int packlen)
{
	extern char *icmptype[];

	printf("\nICMP reply %d\n", i + 1);
	printf("==================\n");
	if (opt.verbose) 
		generic_report(opt, ip, icmp, buffer, packlen);
	else
		printf("Received an ICMP type %s from %s (amount of bytes %d)",
		       icmptype[icmp->icmp_type], inet_ntoa(ip->ip_src), ntohs(ip->ip_len));
}


void stats_report(int n, struct rtt_stats_t stats)
{

	printf("\nReceived packets : %d\n", n);

        if (n)
                printf("RTT : min/avg/max %d ms/%d ms/%d ms\n",
                       stats.min, stats.sum/n, stats.max);
	printf("\n");

}


/*
 * Parsing options function
 */

void parse_options(int argc, char **argv, struct options *opt, struct ip_header_fields *ip_header)
{

	int c;

	while ((c = getopt_long(argc, argv,
                            "hETIMSXUR:P:e:s:d:c:i:vxt:n:f:k:a:l:m:p:",
                            long_options, NULL)) != EOF) {

                switch (c) {
                case 'h':
                        help(argv[0]);
                        exit(EXIT_FAILURE);
                        break;
                case 'E':
                        opt->type = ICMP_ECHO;
                        break;
                case 'T':
                        opt->type = ICMP_TIMESTAMP;
                        break;
                case 'I':
                        opt->type = ICMP_INFO_REQUEST;
                        break;
                case 'M':
                        opt->type = ICMP_ADDRESS;
                        break;
                case 'S':
                        opt->type = ICMP_SOURCE_QUENCH;
                        ip_header->error = 1;
                        break;
                case 'X':
                        opt->type = ICMP_TIME_EXCEEDED;
                        ip_header->error = 1;
                        break;
                case 'U':
                        opt->type = ICMP_DEST_UNREACH;
                        ip_header->error = 1;
                        break;
                case 'R':
                        opt->type = ICMP_REDIRECT;
                        Inet_pton(AF_INET, optarg, &ip_header->router);
                        ip_header->error = 1;
                        break;
                case 'P':
                        opt->type = ICMP_PARAMETERPROB;
                        ip_header->error = 1;
                        break;
                case 'e':
                        opt->code = atoi(optarg);
                        break;
                case 's':
			Inet_pton(AF_INET, optarg, &ip_header->src);
			opt->spoof = 1;
                        break;
                case 'd':
                        resolve(&ip_header->dst, optarg);
                        break;
                case 'c':
                        opt->count = atoi(optarg) - 1;
                        break;
                case 'i':
                        opt->dev = strdup(optarg);
                        break;
                case 'v':
                        opt->verbose = 1;
                        break;
                case 'x':
                        opt->verbose = 2;
                        break;
                case 't':
                        ip_header->ttl = ATOI8(optarg);
                        break;
                case 'n':
                        ip_header->id = ATOI16(optarg);
                        break;
                case 'f':
                        ip_header->fake_proto = proto(strdup(optarg));
                        break;
                case 'k':
                        ip_header->fake_ttl = ATOI8(optarg);
                        break;
                case 'a':
                        ip_header->fake_id = ATOI16(optarg);
                        break;
                case 'l':
                        ip_header->fake_len = ATOI16(optarg);
                        break;
                case 'm':
                        ip_header->link_mtu = ATOI16(optarg);
                        break;
                case 'p':
                        ip_header->param_ptr = ATOI8(optarg);
                        break;
                default:
                        help(argv[0]);
                        exit(EXIT_FAILURE);
                        break;
                }
        }
}


void init_and_parse_options(int argc, char **argv, struct options *opt, struct ip_header_fields *ip_header)
{
	init_opt(opt);
        init_ipheader(ip_header);
        parse_options(argc, argv, opt, ip_header);
}
