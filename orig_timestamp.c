/* orig_timestamp.c
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

#include <time.h>
#include <sys/time.h>
#include "icmp.h"

/*
**Function for generating originate timestamp field in ICMP timestamp
**requests.
*/

uint32_t orig_timestamp(void)
{

	struct timeval tv;
	uint32_t msec;

	gettimeofday(&tv, NULL);
	msec = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
	return msec;

}
