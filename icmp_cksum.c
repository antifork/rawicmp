/* icmp_cksum.c
**
** A great "thank you" to Lorenzo Cavallaro 'Gigi Sullivan' for the
** help he gave me in writing this code.
**
** Copyright (C) 2001 Angelo Dell'Aera 'buffer' <buffer@users.sourceforge.net> 
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
** Function for calculating ICMP checksum
*/

unsigned short in_cksum(unsigned short *addr,int len) {
        
	register int nleft = len;
        register unsigned short *w = addr;
        register unsigned short answer;
        register int sum = 0;
           
        /*
         *  Our algorithm is simple, using a 32 bit accumulator (sum),
         *  we add sequential 16 bit words to it, and at the end, fold   
         *  back all the carry bits from the top 16 bits into the lower
         *  16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
         nleft -= 2;
        }
        
        /* mop up an odd byte, if necessary */
        if (nleft == 1)
                sum += *(u_char *)w;
        /*
         * add back carry outs from top 16 bits to low 16 bits
         */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return (answer);
}

