/* icmphdr.c
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


static inline int code_make(unsigned int code, int limit)
{

        if (code <= limit)
                return (code);
        
	fprintf(stderr, "Wrong code : must be between 0 and %d\n", limit);
	exit(EXIT_FAILURE);
}


static inline void icmp_build_dest_unreach(struct icmp *p, int icmp_code, struct ip_header_fields *h)
{
	p->icmp_code = code_make(icmp_code, MAX_DESTUNREACH_CODE);
	
	if (icmp_code != ICMP_FRAG_NEEDED)
		return;

	p->icmp_nextmtu = (!h->link_mtu) ? htons(LINK_MTU) : htons(h->link_mtu);
}


static inline void icmp_build_redirect(struct icmp *p, int icmp_code, struct ip_header_fields *h)
{
	p->icmp_code = code_make(icmp_code, MAX_REDIRECT_CODE);
	p->icmp_gwaddr = h->router;
}


static inline void icmp_build_time_exceeded(struct icmp *p, int icmp_code)
{
	p->icmp_code = code_make(icmp_code, MAX_TIMEEXC_CODE);
}


static inline void icmp_build_parameter_prob(struct icmp *p, int icmp_code, struct ip_header_fields *h)
{
	p->icmp_code = code_make(icmp_code, MAX_PARAMETER_CODE);
	if (!icmp_code)
		p->icmp_pptr = h->param_ptr;
}


static inline void icmp_build_timestamp(struct icmp *p)
{
	p->icmp_otime = orig_timestamp();
}


static inline void icmp_idseq(struct icmp *p)
{
	static u_int16_t seq = 0; 

	p->icmp_seq = htons(seq++);
	p->icmp_id = getpid() & 0xffff;
}


void icmp_build_hdr_error(struct icmp *p, int icmp_type, int icmp_code, struct ip_header_fields *h)
{
	u_char *data;
	u_char fakedata[] = "buffer";
	
	p->icmp_ip.ip_v = IPVERSION;
	p->icmp_ip.ip_hl = 5;
	p->icmp_ip.ip_tos = 0;
	
	p->icmp_ip.ip_len = (!h->fake_len) ? htons(DEFAULT_PKT_LEN)
		                           : htons(h->fake_len);

	p->icmp_ip.ip_id = (!h->fake_id) ? htons(rand())
	                                 : htons(h->fake_id);

	p->icmp_ip.ip_p = h->fake_proto;

	p->icmp_ip.ip_ttl = (icmp_type == ICMP_TIME_EXCEEDED && icmp_code == ICMP_EXC_TTL)
	        ? 0 : ((!h->fake_ttl) ? IPDEFTTL : h->fake_ttl);

	p->icmp_ip.ip_off = htons(IP_DF);
	p->icmp_ip.ip_src = h->dst.sin_addr;
	p->icmp_ip.ip_dst = h->src;

        p->icmp_ip.ip_sum = in_cksum((unsigned short *)&p->icmp_ip,
				     sizeof(struct ip));

	data = (u_char *)p + sizeof(struct icmp);
	memcpy(data, fakedata, 8);

}


/*
 * Function for creating ICMP fields
 */

unsigned char *tmp;

struct icmp *icmp_hdr_make(unsigned char *buf, int icmp_type, unsigned int
			   icmp_code, struct ip_header_fields *header)
{

	struct icmp *icmp_pt = (struct icmp *) (buf + sizeof(struct ip));
	
	icmp_pt->icmp_type = icmp_type;

	switch (icmp_type) {
	case ICMP_DEST_UNREACH:
		icmp_build_dest_unreach(icmp_pt, icmp_code, header);
		break;
	case ICMP_REDIRECT:
		icmp_build_redirect(icmp_pt, icmp_code, header);
		break;
	case ICMP_TIME_EXCEEDED:
		icmp_build_time_exceeded(icmp_pt, icmp_code);
		break;
	case ICMP_PARAMETERPROB:
		icmp_build_parameter_prob(icmp_pt, icmp_code, header);
		break;
	case ICMP_TIMESTAMP:
		icmp_build_timestamp(icmp_pt);
	default:
		icmp_pt->icmp_code = 0;
		break;
	}

	if (!header->error) 
		icmp_idseq(icmp_pt);
	else
		icmp_build_hdr_error(icmp_pt, icmp_type, icmp_code, header);

	icmp_pt->icmp_cksum = in_cksum((unsigned short *) icmp_pt,
				       data_size(icmp_type) + sizeof(struct icmp));

	if (icmp_pt->icmp_cksum == 0)
		icmp_pt->icmp_cksum = 0xffff;

	return (icmp_pt);
}


int icmp_reply(struct icmp *icmp_pt)
{

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
