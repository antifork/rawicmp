/* icmp.c 
**
** This program is useful for creating raw ICMP requests.
** A great "thank you" to Lorenzo Cavallaro 'Gigi Sullivan' for the 
** help he gave me in writing this code.
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

#include <config.h>
#include "icmp.h"
#include "main.h"

int main(int argc,char **argv) {
  
	unsigned char            *buffer;
	struct ip                *ip;
	struct icmp              *icmp;
	struct sockaddr_in       to;
	int                      c;  
	int                      sockd;
	int                      sd;
	int                      res;
	int                      i;
	int                      packlen;
	int		         count = 0;
	int 	        	 response = 0;
	uint32_t                 rtt_send = 0;
	uint32_t                 rtt = 0;
	uint8_t                  verbose = 0;
	uint8_t         	 spoof = 0;
	int             	 type = ICMP_ECHO;
	unsigned int    	 code = 0;
	char                     *dev = NULL;
	char                     *program_name = argv[0];
	struct ip_header_fields  ip_header;
	struct sockaddr_ll   	 from;
	struct ip                *ip_hdr;
	struct icmp              *icmp_hdr;
	char                     inbuffer[MAXBUFFER];
	int                      numbytes;
	int                      fromlen;
	int			 optval = 1;
	fd_set		         readset;
	struct timeval	         rec_timeout;

	init_ipheader(&ip_header);

	while ( (c = 
		 getopt_long(argc, argv, "hETIMSXURP:e:s:d:c:i:vt:n:f:k:a:l:m:p:",
			     long_options, NULL)) != EOF ) {
	
		switch(c) {
		case 'h':
			help(program_name);   
			exit(EXIT_FAILURE);
			break;
		case 'E':
			type = ICMP_ECHO;
			break;
		case 'T':
			type = ICMP_TIMESTAMP;
			break;
		case 'I':
			type = ICMP_INFO_REQUEST;
			break;
		case 'M':
			type = ICMP_ADDRESS;
			break;
		case 'S':
			type = ICMP_SOURCE_QUENCH;
			ip_header.error = 1; 
			break;
		case 'X':
			type = ICMP_TIME_EXCEEDED;
			ip_header.error = 1;
			break;
		case 'U':
			type = ICMP_DEST_UNREACH;
			ip_header.error = 1;
			break;
		case 'R':
			type = ICMP_REDIRECT;
			Inet_pton(AF_INET, optarg, &ip_header.router);
			ip_header.error = 1;
			break;
		case 'P':
			type = ICMP_PARAMETERPROB;
			ip_header.error = 1;
			break;
		case 'e':
			code = atoi(optarg);
			break;
		case 's':
			spoof = 1;
			Inet_pton(AF_INET,optarg,&ip_header.src);
			break;
		case 'd':
			resolve(&ip_header.dst, optarg);
			break;	
		case 'c':
			count = atoi(optarg)-1;
			break;
		case 'i':
			dev = strdup(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 't':
			ip_header.ttl = ATOI8(optarg);
			break;
		case 'n':
			ip_header.id = ATOI16(optarg);
			break;
		case 'f':
			ip_header.fake_proto = proto(strdup(optarg));
			break;
		case 'k':
			ip_header.fake_ttl = ATOI8(optarg);
			break;
		case 'a':
			ip_header.fake_id = ATOI16(optarg);
			break;
		case 'l':
			ip_header.fake_len = ATOI16(optarg);
			break;
		case 'm':
			ip_header.link_mtu = ATOI16(optarg);
			break;
		case 'p':
			ip_header.param_ptr = ATOI8(optarg);
			break;
		default :
			help(program_name); 
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!ip_header.dst.sin_addr.s_addr) {
		help(program_name);
		printf("Must specify IP destination address!\n\n");
		exit(EXIT_FAILURE);
	}

	if ( (sockd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("Cannot open raw socket");	
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	if ( (sd = dlink_open(dev)) < 0) {
		perror("dlink_open");
		exit(EXIT_FAILURE);
	}

	packlen = sizeof(struct ip) + sizeof(struct icmp) + data_size(type);
	//FD_ZERO(&readset);

	for (i = 0; i <= count; i++) {

		unsigned int out_of_order_pkts = 0;

		if ( (buffer = (unsigned char *)calloc(packlen, 1)) == NULL) {
			perror("calloc");
			exit(EXIT_FAILURE);
		}

		ip = ip_hdr_make(buffer, type, &ip_header);
		icmp = icmp_hdr_make(buffer, type, code, &ip_header);
	
		memset(&to, 0, sizeof(struct sockaddr_in));
		to.sin_family = AF_INET;
		to.sin_addr = ip->ip_dst;

		rtt_send = htonl(orig_timestamp());

		if ( (res = sendto(sockd, (void *)buffer, packlen, 0, 
				   (struct sockaddr *)&to, sizeof(struct sockaddr))) < 0) {
			perror("sendto");
			exit(EXIT_FAILURE);
		}

		printf("\nICMP request %d\n",i+1);     

		if(spoof)
			printf("\nSpoofed source IP : %s", inet_ntoa(ip_header.src));
 
		if (verbose) {
			printf("\nSending %s to %s...",
			       icmptype[type],
			       inet_ntoa(ip_header.dst.sin_addr));
			printf("\n\nSent ICMP packet fields : \n");
			printf("------------------------- \n");
			verbose_iphdr(ip);
			verbose_icmphdr(icmp);
		}
		else 
			printf("\nSending an ICMP type %s to %s (amount of bytes %d)...",
			       icmptype[type],inet_ntoa(ip_header.dst.sin_addr),packlen);

out_of_order:
		memset(inbuffer, 0, sizeof(inbuffer));
		fromlen = sizeof(struct sockaddr_ll);

		//FD_SET(sd, &readset);
		//rec_timeout.tv_sec  = RECEIVE_TIMEOUT;
		//rec_timeout.tv_usec = 0;

		FD_ZERO(&readset);
		FD_SET(sd, &readset);
		rec_timeout.tv_usec = 0;
		
		if (out_of_order_pkts <= MAX_RETRIES_RCV)
			rec_timeout.tv_sec = RECEIVE_TIMEOUT;
		else
		   	continue;	  

		res = select(sd + 1, &readset , NULL, NULL, &rec_timeout);
		if (res < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		} 
		else if (res == 0) {
			printf("\nNo reply received! (timeout expired)\n");
			continue;
		}

		if (FD_ISSET(sd, &readset)) {
	  
			if ( (numbytes = recvfrom(sd, inbuffer, sizeof(inbuffer), 0,
						  (struct sockaddr *)&from, &fromlen)) < 0) {
				perror("recvfrom");
				exit(EXIT_FAILURE);
			}
	
			rtt = htonl(orig_timestamp());
			rtt -= rtt_send;
	  
			ip_hdr = (struct ip *)inbuffer;
			icmp_hdr = (struct icmp *)(inbuffer + (ip_hdr->ip_hl << 2));
	  
			if ((from.sll_pkttype == PACKET_HOST) && (ip_hdr->ip_p == IPPROTO_ICMP)) {
	    
				if (icmpreply(icmp_hdr) && icmp_hdr->icmp_seq != icmp->icmp_seq) {
					out_of_order_pkts++;
					goto out_of_order;
				}

				if (verbose) {
					printf("\n\nReceived ICMP packet fields : \n");
					printf("----------------------------- \n");
					verbose_iphdr(ip_hdr);
					verbose_icmphdr(icmp_hdr);
				}
				else 
					printf("\nReceived an ICMP type %s from %s (amount of bytes %d)", 
					       icmptype[icmp_hdr->icmp_type],
					       inet_ntoa(ip_hdr->ip_src),
					       ntohs(ip_hdr->ip_len));
	    
				printf("\nrtt = %u ms",
				       rtt);
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



