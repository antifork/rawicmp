/* datasize.c
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
** Function for obtaining exact length of ICMP packets.
** It is obtained as 
** 
** sizeof(struct ip)+sizeof(struct icmp)+data_size(icmptype)
**
** as can be seen in icmp.c
*/

int data_size(int icmptype)
{

	switch (icmptype) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		return ECHO_DATA_SIZE;
		break;
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
		return TIME_DATA_SIZE;
		break;
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
		return INFO_DATA_SIZE;
		break;
	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
		return ADDR_DATA_SIZE;
		break;
	case ICMP_SOURCE_QUENCH:
	case ICMP_TIME_EXCEEDED:
	case ICMP_DEST_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		return ERROR_DATA_SIZE;
		break;
	default:
		return DEF_DATA_SIZE;
		break;
	}
}
