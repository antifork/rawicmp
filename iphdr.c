/* iphdr.c
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

/*
 * Function for creating IP header.
 * It's important to observe DF flag is set on. I'll modify this part of code
 * for allowing the user to set flag he wants.
*/

struct ip *ip_hdr_make(unsigned char *buf, int icmp_type,
		       struct ip_header_fields *ip_head)
{

	struct ip *ip_pt = (struct ip *) buf;

	ip_pt->ip_v = IPVERSION;
	ip_pt->ip_hl = 5;
	ip_pt->ip_tos = 0;
	ip_pt->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp)
			      + data_size(icmp_type));

	ip_pt->ip_id = (!ip_head->id)
	    ? htons(rand())
	    : htons(ip_head->id);

	ip_pt->ip_p = IPPROTO_ICMP;

	ip_pt->ip_ttl = (ip_head->ttl == IPDEFTTL)
	    ? IPDEFTTL : ip_head->ttl;

	ip_pt->ip_sum = 0;
	ip_pt->ip_off = htons(IP_DF);
	ip_pt->ip_dst.s_addr = ip_head->dst.sin_addr.s_addr;
	ip_pt->ip_src = ip_head->src;

	return (ip_pt);

}

