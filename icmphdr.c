/* icmphdr.c
**
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

#include "icmp.h"

/*
** Function for creating ICMP fields
*/

unsigned char *tmp;

struct icmp *icmp_hdr_make(unsigned char *buf,int icmp_type,unsigned int 
			   icmp_code,struct ip_header_fields *header) {
	
	struct icmp *icmp_pt = (struct icmp *)(buf+sizeof(struct ip));
	
	icmp_pt->icmp_type = icmp_type;
	
	switch(icmp_type) {
	case ICMP_DEST_UNREACH :
		icmp_pt->icmp_code = code_make(icmp_code, MAX_DESTUNREACH_CODE);
		if (icmp_code == ICMP_FRAG_NEEDED)
			icmp_pt->icmp_nextmtu = (!header->link_mtu)
				? htons(LINK_MTU)   
				: htons(header->link_mtu);
		break;
	case ICMP_REDIRECT :
		icmp_pt->icmp_code = code_make(icmp_code, MAX_REDIRECT_CODE);
		icmp_pt->icmp_gwaddr = header->router;
		break;
	case ICMP_TIME_EXCEEDED :
		icmp_pt->icmp_code = code_make(icmp_code, MAX_TIMEEXC_CODE);
		break;
	case ICMP_PARAMETERPROB :
		icmp_pt->icmp_code = code_make(icmp_code, MAX_PARAMETER_CODE);
		if (!icmp_code)
			icmp_pt->icmp_pptr = header->param_ptr;
		break;
	default :
		icmp_pt->icmp_code = 0;
		break;
	}
	
	if (!header->error) {
		icmp_pt->icmp_seq = rand();
		icmp_pt->icmp_id = getpid() & 0xffff;
	}
  
	if (icmp_type == ICMP_TIMESTAMP) 
		icmp_pt->icmp_otime = orig_timestamp();

	if(header->error) {
    
		u_char *data;
		u_char fakedata[] = "buffer";		
    
		icmp_pt->icmp_ip.ip_v            = IPVERSION;
		icmp_pt->icmp_ip.ip_hl           = 5;
		icmp_pt->icmp_ip.ip_tos          = 0;
    
		/*
		** Una cosa interessante sarebbe tirare fuori questo valore
		** di default non da una #define ma a seguito di una valutazione
		** dell'MTU.Per adesso comunque abbiamo che DEFAULT_PKT_LEN 
		** vale 1500 bytes.
		*/
    
		icmp_pt->icmp_ip.ip_len   = (!header->fake_len)
			? htons(DEFAULT_PKT_LEN)
			: htons(header->fake_len);
    
		icmp_pt->icmp_ip.ip_id    = (!header->fake_id)
			? htons(rand())
			: htons(header->fake_id);
    
		icmp_pt->icmp_ip.ip_p     = header->fake_proto;
    
		if (icmp_type == ICMP_TIME_EXCEEDED && icmp_code == ICMP_EXC_TTL)
			icmp_pt->icmp_ip.ip_ttl = 0;
		else
			icmp_pt->icmp_ip.ip_ttl = (!header->fake_ttl)
				? IPDEFTTL
				: header->fake_ttl;
    
		icmp_pt->icmp_ip.ip_off   = htons(IP_DF);
		icmp_pt->icmp_ip.ip_src   = header->dst.sin_addr;
		icmp_pt->icmp_ip.ip_dst   = header->src;
    
		icmp_pt->icmp_ip.ip_sum = in_cksum((unsigned short *)&icmp_pt->icmp_ip,
						   sizeof(struct ip));
    
		data = (u_char *)icmp_pt + sizeof(struct icmp);
		memcpy(data,fakedata,8);
    
	}
    
	icmp_pt->icmp_cksum = in_cksum((unsigned short *)icmp_pt,
                                       data_size(icmp_type) + sizeof(struct icmp));
        if (icmp_pt->icmp_cksum == 0)
                icmp_pt->icmp_cksum = 0xffff;


	return(icmp_pt);
}

int code_make(unsigned int code,int limit) {
   
	if (code <= limit)
		return(code);
	else {
		fprintf(stderr,"Wrong code : must be between 0 and %d\n",limit);
		exit(EXIT_FAILURE);
	}

}

/*
** Function used in 'verbose mode'
*/

void verbose_icmphdr(struct icmp *icmphdr) {
  
	extern char         *icmptype[];
	extern char	    *unreach_codes[];
	extern char         *timeexc_codes[];
	extern char         *redirect_codes[];
	uint8_t	            error = 0;

	printf("ICMP type : %s\n", icmptype[icmphdr->icmp_type]);
  
	switch(icmphdr->icmp_type) {
	case ICMP_SOURCE_QUENCH :
	case ICMP_PARAMETERPROB :
		error = 1;
		break;
	case ICMP_DEST_UNREACH  :
		printf("ICMP code : %s\n", unreach_codes[icmphdr->icmp_code]);
		error = 1;
		break;
	case ICMP_TIME_EXCEEDED :
		printf("ICMP code : %s\n", timeexc_codes[icmphdr->icmp_code]);
		error = 1;
		break; 
	case ICMP_REDIRECT :
		printf("ICMP code : %s\n", redirect_codes[icmphdr->icmp_code]);
		error = 1;
		break; 
	default :
		break;
	}

	if (!error) {	
		printf("ICMP Sequence Number : %d\n",ntohs(icmphdr->icmp_seq));
		printf("ICMP ID Number : %d\n",ntohs(icmphdr->icmp_id));
	}  

	switch(icmphdr->icmp_type) {
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
  
}


void timestamp_verbose(struct icmp *icmphead) {
  
	printf("Originate Timestamp : %x\n", ntohl(icmphead->icmp_otime));
	return;
}


void timestampreply_verbose(struct icmp *icmphead) {
  
	printf("Originate Timestamp : %x\n", ntohl(icmphead->icmp_otime));
	printf("Receive Timestamp : %x\n", ntohl(icmphead->icmp_rtime));
	printf("Transmit Timestamp : %x\n", ntohl(icmphead->icmp_ttime));
	printf("\n");
	return;
}


void addressreply_verbose(struct icmp *icmphead) {
  
	printf("Subnet Address Mask : %x\n", ntohl(icmphead->icmp_mask));
	return;
}
 

int icmpreply(struct icmp *icmp_pt) {

	int ret;

	switch (icmp_pt->icmp_type) {
	case ICMP_ECHOREPLY:
        case ICMP_INFO_REPLY:
	case ICMP_ADDRESSREPLY:
        case ICMP_TIMESTAMPREPLY:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;

}
