/* utils.c
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
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, 
USA.
*/

#include <signal.h>
#include "icmp.h"

void init_ipheader(struct ip_header_fields *iphf) {

  iphf->tos                  = 0;
  iphf->length               = 0;
  iphf->id                   = 0;
  iphf->ttl                  = IPDEFTTL;
  iphf->src.s_addr           = htonl(INADDR_ANY);
  iphf->dst.sin_addr.s_addr  = 0;
  iphf->router.s_addr	     = 0;
  iphf->error		     = 0;
  iphf->fake_ttl	     = 0;
  iphf->fake_proto	     = IPPROTO_TCP;
  iphf->fake_id		     = 0;
  iphf->fake_len	     = 0;
  iphf->link_mtu	     = 0;
  iphf->param_ptr	     = 0;
  return;
}

int proto(char *protocol) {
  
  if (!strcmp(protocol,"tcp")) 
    return(IPPROTO_TCP);
  else if (!strcmp(protocol,"udp"))
    return(IPPROTO_UDP);
  else {
    fprintf(stderr,"Protocol not know!\n");
    exit(EXIT_FAILURE);
  }
  
  return EXIT_SUCCESS;
}

/*
** Function for POSIX signal handling
** (written by W.Richard Stevens)
*/

void (*Signal(int signo, void (*func)(int)))(int)
{
  struct sigaction act, oact;
  
  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0; 		      /* So if set SA_RESETHAND is cleared */
  if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
      act.sa_flags |= SA_INTERRUPT;   /* SunOS 4.x */
#endif
  }
  else {
#ifdef SA_RESTART
      act.sa_flags |= SA_RESTART;     /* SVR4, 4.4BSD, Linux */
#endif
  }
  if (sigaction(signo, &act, &oact) == -1)
    return SIG_ERR;
  return (oact.sa_handler);
}


/* 
** SIGALRM signal handler
*/
 
void sig_alrm(int sig) {
  
  siglongjmp(buf,1);
}

/*
** inet_pton(3) wrapper
*/

int Inet_pton(int af,const char *src,void *dst) {
  
  int res;
  
  if ( (res=inet_pton(af,src,dst)) < 0) {
    perror("inet_pton error");       
    exit(EXIT_FAILURE);
  }
  else if (res == 0) {
    printf("No valid network address!\n");     
    exit(EXIT_FAILURE);
  }
  
  return(1);
}

