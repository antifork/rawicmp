/* main.h
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

#ifndef _RAWICMPMAIN_H_
#define _RAWICMPMAIN_H

char *icmptype[] = {
	"ICMP_ECHOREPLY",       /*type 0*/
	"NULL",
	"NULL",
	"ICMP_DEST_UNREACH",    /*type 3*/
	"ICMP_SOURCE_QUENCH",   /*type 4*/
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
	"ICMP_PREC_CUTOFF",       /* Precedence cut off */
};

char *redirect_codes[] = {
	"ICMP_REDIR_NET",         /* Redirect Net                 */
	"ICMP_REDIR_HOST",        /* Redirect Host                */
	"ICMP_REDIR_NETTOS",      /* Redirect Net for TOS         */
	"ICMP_REDIR_HOSTTOS"      /* Redirect Host for TOS        */
};

char *timeexc_codes[] = {   
	"ICMP_EXC_TTL",        	  /* TTL count exceeded           */
	"ICMP_EXC_FRAGTIME"       /* Fragment Reass time exceeded */
};

#endif /* _RAWICMPMAIN_H */

