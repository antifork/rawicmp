/* icmp.c 
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

#include <config.h>
#include "icmp.h"
#include "main.h"

int main(int argc, char **argv)
{

	struct sockaddr_in 	to;
	int 			sockd;          
	int 			sd;             
	int 			i;              
	int 			packlen;        
	int 			response = 0;
	int 			optval = 1;    
	struct options 		opt;           
	struct ip_header_fields ip_header;     


	init_and_parse_options(argc, argv, &opt, &ip_header);

	if (!ip_header.dst.sin_addr.s_addr) {
		help(argv[0]);
		printf("Must specify IP destination address!\n\n");
		exit(EXIT_FAILURE);
	}

	if ((sockd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Cannot open raw socket");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	if ((sd = dlink_open(opt.dev)) < 0) {
		perror("dlink_open");
		exit(EXIT_FAILURE);
	}

	init_dst(&to, &ip_header); 

	packlen = sizeof(struct ip) + sizeof(struct icmp) + data_size(opt.type);

	for (i = 0; i <= opt.count; i++) {

		unsigned int   		out_of_order_pkts = 0;
		char           		inbuffer[MAXBUFFER];
		unsigned char  		*buffer;
		struct ip      		*ip;
        	struct icmp    		*icmp;
		int            		res;
		int            		fromlen;
		fd_set                  readset;
	        struct timeval          rec_timeout;
		struct sockaddr_ll      from;
		uint32_t                rtt_send;
	        uint32_t                rtt;


		if ((buffer = (unsigned char *) calloc(packlen, 1)) == NULL) {
			perror("calloc");
			exit(EXIT_FAILURE);
		}
		
		ip = ip_hdr_make(buffer, opt.type, &ip_header);
		icmp = icmp_hdr_make(buffer, opt.type, opt.code, &ip_header);

		rtt_send = htonl(orig_timestamp());

		if ((res = sendto(sockd, (void *) buffer, packlen, 0,
			    (struct sockaddr *) &to, sizeof(struct sockaddr))) < 0) {
			perror("sendto");
			exit(EXIT_FAILURE);
		}

		printf("\nICMP request %d\n", i + 1);

		if (opt.spoof)
			printf("\nSpoofed source IP : %s",
			       inet_ntoa(ip_header.src));

		if (opt.verbose) {
			verbose(ip, icmp);
			if (opt.verbose > 1)
				dump(buffer, packlen);
		} else
			printf
			    ("\nSending an ICMP type %s to %s (amount of bytes %d)...",
			     icmptype[opt.type],
			     inet_ntoa(ip_header.dst.sin_addr), packlen);

out_of_order:
		memset(inbuffer, 0, sizeof(inbuffer));
		fromlen = sizeof(struct sockaddr_ll);

		FD_ZERO(&readset);
		FD_SET(sd, &readset);
		rec_timeout.tv_usec = 0;

		if (out_of_order_pkts <= MAX_RETRIES_RCV)
			rec_timeout.tv_sec = RECEIVE_TIMEOUT;
		else
			continue;

		res = select(sd + 1, &readset, NULL, NULL, &rec_timeout);

		if (res < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		} else if (res == 0) {
			printf("\nNo reply received! (timeout expired)\n");
			continue;
		}

		if (FD_ISSET(sd, &readset)) {

			struct ip   *ip_hdr;
			struct icmp *icmp_hdr;
			int         numbytes;

			if ((numbytes = recvfrom(sd, inbuffer, sizeof(inbuffer), 0,
				      (struct sockaddr *) &from, &fromlen)) < 0) {
				perror("recvfrom");
				exit(EXIT_FAILURE);
			}

			rtt = htonl(orig_timestamp());
			rtt -= rtt_send;

			ip_hdr = (struct ip *) inbuffer;
			icmp_hdr = (struct icmp *) (inbuffer + (ip_hdr->ip_hl << 2));

			if ((from.sll_pkttype == PACKET_HOST)
			    && (ip_hdr->ip_p == IPPROTO_ICMP)) {

				if (icmp_reply(icmp_hdr)
				    && icmp_hdr->icmp_seq != icmp->icmp_seq) {
					out_of_order_pkts++;
					goto out_of_order;
				}

				if (opt.verbose) {
					printf("\nICMP reply %d\n", i + 1);
					verbose(ip_hdr, icmp_hdr);
					if (opt.verbose > 1)
						dump(inbuffer, numbytes);
				} else
					printf
					    ("\nReceived an ICMP type %s from %s (amount of bytes %d)",
					     icmptype[icmp_hdr->icmp_type],
					     inet_ntoa(ip_hdr->ip_src),
					     ntohs(ip_hdr->ip_len));

				printf("\nrtt = %u ms", rtt);
				response++;
			}

			printf("\n");
			free(buffer);
			sleep(SEND_TIMEOUT);
		}
	}
	printf("\nReceived packets : %d\n\n", response);
	return EXIT_SUCCESS;
}
