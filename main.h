/* main.h
**
** A great "thank you" to Lorenzo Cavallaro 'Gigi Sullivan' for the help
** he gave me in writing this code.
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

#ifndef _RAWICMPMAIN_H_
#define _RAWICMPMAIN_H

#include <getopt.h>

struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"echo", no_argument, NULL, 'E'},
        {"timestamp", no_argument, NULL, 'T'},
        {"mask", no_argument, NULL, 'M'},
        {"info", no_argument, NULL, 'I'},
        {"source",no_argument,NULL, 'S'},
        {"time",no_argument,NULL, 'X'},
	{"unreach",no_argument,NULL, 'U'},
	{"redirect",required_argument,NULL, 'R'},
	{"parameter",no_argument,NULL, 'P'},
	{"paramptr",required_argument,NULL, 'p'},
	{"code",required_argument,NULL, 'e'},
        {"src", required_argument, NULL, 's'},
        {"dst", required_argument, NULL, 'd'},
        {"count", required_argument, NULL, 'c'},
        {"iface", required_argument, NULL, 'i'},
        {"mtu", required_argument, NULL, 'm'},
        {"verbose", no_argument, NULL, 'v'},
        {"ttl", required_argument, NULL, 't'},
        {"id", required_argument, NULL, 'n'},
        {"fakeproto", required_argument, NULL, 'f'},
        {"fakettl", required_argument, NULL, 'k'},
        {"fakeid", required_argument, NULL, 'a'},
        {"fakelength", required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
};

char *icmptype[] = {
  "ICMP_ECHOREPLY",       /*type 0*/
  "NULL",
  "NULL",
  "ICMP_DEST_UNREACH",    /*type 3*/
  "ICMP_SOURCE_QUENCH ",  /*type 4*/
  "ICMP_REDIRECT  ",      /*type 5*/
  "NULL",
  "NULL",
  "ICMP_ECHO",            /*type 8*/
  "NULL",
  "NULL",
  "ICMP_TIME_EXCEEDED",   /*type 11*/
  "ICMP_PARAMETERPROB",   /*type 12*/
  "ICMP_TIMESTAMP",       /*type 13*/
  "ICMP_TIMESTAMPREPLY",  /*type 14*/
  "ICMP_INFO_REQUEST",    /*type 15*/
  "ICMP_INFO_REPLY",      /*type 16*/
  "ICMP_ADDRESS",         /*type 17*/
  "ICMP_ADDRESSREPLY"     /*type 18*/
};

char *unreach_codes[]= {
  "ICMP_NET_UNREACH",       /* Network Unreachable          */
  "ICMP_HOST_UNREACH",      /* Host Unreachable             */
  "ICMP_PROT_UNREACH",      /* Protocol Unreachable         */
  "ICMP_PORT_UNREACH",      /* Port Unreachable             */
  "ICMP_FRAG_NEEDED",       /* Fragmentation Needed/DF set  */
  "ICMP_SR_FAILED",         /* Source Route failed          */
  "ICMP_NET_UNKNOWN",        
  "ICMP_HOST_UNKNOWN",       
  "ICMP_HOST_ISOLATED",      
  "ICMP_NET_ANO",            
  "ICMP_HOST_ANO",           
  "ICMP_NET_UNR_TOS",        
  "ICMP_HOST_UNR_TOS",       
  "ICMP_PKT_FILTERED",      /* Packet filtered */
  "ICMP_PREC_VIOLATION",    /* Precedence violation */
  "ICMP_PREC_CUTOFF",       /*  15  Precedence cut off */
  "NR_ICMP_UNREACH"         /*  15  instead of hardcoding immediate value */
};

char *redirect_codes[] = {
  "ICMP_REDIR_NET",         /* Redirect Net                 */
  "ICMP_REDIR_HOST",        /* Redirect Host                */
  "ICMP_REDIR_NETTOS",      /* Redirect Net for TOS         */
  "ICMP_REDIR_HOSTTOS"      /* Redirect Host for TOS        */
};

char *timeexc_codes[] = {   
  "ICMP_EXC_TTL",        /* TTL count exceeded           */
  "ICMP_EXC_FRAGTIME"    /* Fragment Reass time exceeded */
};


#endif /* _RAWICMPMAIN_H */

