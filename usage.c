
/* usage.c
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

void help(char *name)
{

	printf("\nRawICMP : raw ICMP packets generator");
	printf("\nversion %s\n", RAWICMPVERSION);
	printf("Angelo Dell'Aera 'buffer' <buffer@antifork.org>\n");
	printf("\nUsage : %s [options] \n", name);

	printf("Options: \n\n"
	"-h   --help             : prints this help\n\n"
	"ICMP queries\n"
	"-E   --echo             : generates an ICMP echo request\n"
	"-T   --timestamp        : generates an ICMP timestamp request\n"  
	"-I   --info             : generates an ICMP information request\n"
	"-M   --mask             : generates an ICMP mask request\n\n" 
	"ICMP error messagges\n"
	"-S   --source           : generates an ICMP source quench\n"
	"-X   --time             : generates an ICMP TTL exceeded\n"
	"-U   --unreach		: generates an ICMP destination unreachable\n"
	"-R   --redirect         : generates an ICMP redirect (it needs router\n"
	"		 	  address as argument)\n"
	"-P   --parameter	: generates an ICMP parameter problem\n"
	"-e   --code		: ICMP code (only for ICMP TTL exceeded,\n"
	"		 	  ICMP destination unreachable,ICMP\n"
        "                 	  redirect and ICMP parameter problem)\n"
	"-m   --mtu	        : link MTU (only for ICMP destination\n"
	"		 	  unreachable ICMP_FRAG_NEEDED (code 4))\n"
	"-p   --paramptr\t	: pointer in ICMP parameter problem code 0\n\n"
	"Options for both ICMP queries and error messages\n\n"
	"-s   --src              : source IP\n"
	"-d   --dst              : destination IP\n"
	"-i   --iface		: interface\n"
	"-c   --count            : number of packets to send\n"
	"-v   --verbose          : verbose mode\n"
	"-x   --extraverbose     : extra-verbose mode\n"
	"-t   --ttl		: time to live\n"
	"-n   --id		: IP identification value\n\n"
	"Options for ICMP error messages (ignored for ICMP queries)\n\n"
	"-f   --fakeproto	: protocol in fake IP header\n"
	"-k   --fakettl		: TTL in fake IP header\n"
	"-a   --fakeid		: IP identification value in fake IP header\n"
	"-l   --fakelength       : total length in fake IP header\n"

	"\n");

}
