/* resolve.c
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
**
*/

#include <netdb.h>
#include "icmp.h"

void resolve(struct sockaddr_in *address, char *hostname)
{

	struct hostent *host;

	memset(address, 0, sizeof(struct sockaddr_in));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = inet_addr(hostname);

	if ((int) address->sin_addr.s_addr == -1) {
		if ((host = gethostbyname(hostname)) == NULL) {
			printf("gethostbyname error for host : %s %s\n",
			       hostname, hstrerror(h_errno));
			exit(EXIT_FAILURE);
		} else
			memcpy(&address->sin_addr, host->h_addr,
			       host->h_length);
	}

}
