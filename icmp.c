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
	struct rtt_stats_t      rtt_stats;

	init_and_parse_options(argc, argv, &opt, &ip_header);
	init_rtt_stats(&rtt_stats);
	init_dst(&to, &ip_header);

	sockd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	Setsockopt(sockd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
	sd = Dlink_open(opt.dev);

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
		uint32_t                t_send;
	        uint32_t                rtt;


		buffer = (unsigned char *) Calloc(packlen, 1);
		
		ip = ip_hdr_make(buffer, opt.type, &ip_header);
		icmp = icmp_hdr_make(buffer, opt.type, opt.code, &ip_header);

		t_send = htonl(orig_timestamp());

		res = Sendto(sockd, (void *) buffer, packlen, 0,
			     (struct sockaddr *) &to, sizeof(struct sockaddr));

		send_report(i, opt, ip, icmp, ip_header, buffer, packlen);

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

		if ( (res = Select(sd + 1, &readset, NULL, NULL, &rec_timeout)) == 0) {
			printf("\nNo reply received! (timeout expired)\n");
			continue;
		}

		if (FD_ISSET(sd, &readset)) {

			struct ip   *ip_hdr;
			struct icmp *icmp_hdr;
			int         numbytes;

			numbytes = Recvfrom(sd, inbuffer, sizeof(inbuffer), 0,
					    (struct sockaddr *) &from, &fromlen);

			rtt = rtt_evaluate(t_send);

			ip_hdr = (struct ip *)inbuffer;
			icmp_hdr = (struct icmp *)(inbuffer + (ip_hdr->ip_hl << 2));

			if ((from.sll_pkttype == PACKET_HOST)
			    && (ip_hdr->ip_p == IPPROTO_ICMP)) {

				if (icmp_reply(icmp_hdr) && 
				    icmp_hdr->icmp_seq != icmp->icmp_seq) {
					out_of_order_pkts++;
					goto out_of_order;
				}

				update_rtt_stats(rtt, &rtt_stats);
				receive_report(i, opt, ip_hdr, icmp_hdr, inbuffer, numbytes);
				printf("\nRTT = %u ms", rtt);
				response++;
			}

			printf("\n");
			free(buffer);
			sleep(SEND_TIMEOUT);
		}
	}

	stats_report(response, rtt_stats);
	return EXIT_SUCCESS;
}
