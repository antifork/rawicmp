# $Makefile$
# $Angelo Dell'Aera 'buffer' <buffer@users.sourceforge.net>$
# $Copyright (C) 2001 by Angelo Dell'Aera$
# $This software is under GPL version 2 of license$

CC= gcc
CCOPT2=
CCOPT= -O2 -Wall    
DEBUG= 
PREFIX= /usr/local/bin

OBJ=	icmp.o icmphdr.o iphdr.o usage.o\
        icmp_cksum.o orig_timestamp.o receive.o\
	datasize.o resolve.o hstrerror.o utils.o 

rawicmp:$(OBJ)
	$(CC) $(DEBUG) -o rawicmp $(CCOPT) $(OBJ)

.c.o:
	$(CC) $(DEBUG) -c $(CCOPT) $(COMPILE_TIME) $<

install:
	cp rawicmp ${PREFIX}

uninstall:
	rm ${PREFIX}/rawicmp

clean:
	rm -rf *.o
