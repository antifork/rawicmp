/* hstrerror.c
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
**
** This code was written by W. Richard Stevens
**
*/

#include <netdb.h>
#include "icmp.h"

const char *hstrerror(int err)
{

	if (err == 0)
		return ("no error");

	if (err == HOST_NOT_FOUND)
		return ("Unknown host");

	if (err == TRY_AGAIN)
		return ("Hostname lookup failure");

	if (err == NO_RECOVERY)
		return ("Unknown server error");

	if (err == NO_DATA)
		return ("No address associated with name");

	return ("unknown error");
}
