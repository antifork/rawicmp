/* dump.c
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
 * This function is really similar to default_print_unaligned() which
 * is used in tcpdump-3.7.1 to dump packets. It was too good for
 * rewriting it from scratch. I simply modified it for my own
 * purposes.
 */

void dump(const char *buffer, int length)
{
	register int i = 0;
	register int j = 0;
	register unsigned int s;
	register int nshorts;
	unsigned char *cp = (unsigned char *) buffer;

	nshorts = length / sizeof(short);

	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void) printf("\n0x%03x0\t\t", j++);
		s = *cp++;
		(void) printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void) printf("\n\t\t\t");
		(void) printf(" %02x", *cp);
	}
	printf("\n");
	return;
}
