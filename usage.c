/* usage.c
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

void help(char *name) {

	printf("\nRawICMP : raw ICMP packets generator");
	printf("\nversion %s\n", RAWICMPVERSION);
	printf("Angelo Dell'Aera 'buffer' <buffer@users.sourceforge.net>\n");
	printf("\nUsage : %s [options] \n", name);

	printf ("Options:
-h   --help             :prints this help

ICMP queries
-E   --echo             :generates an ICMP echo request
-T   --timestamp        :generates an ICMP timestamp request  
-I   --info             :generates an ICMP information request
-M   --mask             :generates an ICMP mask request 

ICMP error messagges
-S   --source           :generates an ICMP source quench
-X   --time             :generates an ICMP TTL exceeded
-U   --unreach		:generates an ICMP destination unreachable
-R   --redirect         :generates an ICMP redirect (it needs router
			 address as argument)
-P   --parameter	:generates an ICMP parameter problem
-e   --code		:ICMP code (only for ICMP TTL exceeded,
			 ICMP destination unreachable,ICMP
                         redirect and ICMP parameter problem)
-m   --mtu		:link MTU (only for ICMP destination
			 unreachable ICMP_FRAG_NEEDED (code 4))
-p   --paramptr		:pointer in ICMP parameter problem code 0

Options for both ICMP queries and error messages
-s   --src              :source IP
-d   --dst              :destination IP
-i   --iface		:interface
-c   --count            :number of packets to send
-v   --verbose          :verbose mode
-t   --ttl		:time to live
-n   --id		:IP identification value

Options for ICMP error messages (ignored for ICMP queries)
-f   --fakeproto	:protocol in fake IP header
-k   --fakettl		:ttl in fake IP header
-a   --fakeid		:IP identification value in fake IP header
-l   --fakelength       :total length in fake IP header

	\n");

}
