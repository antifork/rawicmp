/* receive.c
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

#include <sys/ioctl.h>
#include "icmp.h"

int dlink_open(char *device)
{

	int sockd;
	int res;
	struct sockaddr_ll ll;
	struct ifreq ifr;

	if ((sockd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
		perror("socket error");
		return -1;
	}

	if (device != NULL) {
		memset(&ll, 0, sizeof(struct sockaddr_ll));
		memset(&ifr, 0, sizeof(struct ifreq));

		strncpy(ifr.ifr_name, device, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';

		if ((res = ioctl(sockd, SIOCGIFINDEX, &ifr)) < 0) {
			perror("ioctl");
			close(sockd);
			return (-1);
		}

		ll.sll_family = AF_PACKET;
		ll.sll_protocol = htons(ETH_P_IP);
		ll.sll_ifindex = ifr.ifr_ifindex;

		if ((res = bind(sockd, (struct sockaddr *) &ll,
				sizeof(struct sockaddr_ll))) < 0) {
			perror("bind");
			close(sockd);
			return (-1);
		}
	}

	return (sockd);
}
