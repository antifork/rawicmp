# Process this file with autoconf to produce a configure script.
AC_INIT(rawicmp, 0.6.1, buffer@users.sourceforge.net)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([orig_timestamp.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNCS([gethostbyname gettimeofday inet_ntoa memset select socket strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
