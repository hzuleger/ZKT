#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
#	@(#) configure.ac 
#
#

AC_PREREQ(2.59)

### Package name and current version
AC_INIT(zkt-delegate, 0.3, Holger Zuleger hznet.de)
dnl AC_REVISION($Revision: 1.397 $)

### Files to test to check if src dir contains the package
AC_CONFIG_SRCDIR([zkt-delegate.c])
AC_CONFIG_HEADER([config.h])


### Checks for programs.
AC_PROG_CC

### define configure arguments
AC_DEFINE_UNQUOTED(VERSION, "v$PACKAGE_VERSION (c) Mar 2015 - Apr 2015 Holger Zuleger hznet.de", version string)

### Checks for libraries.
AC_CHECK_LIB(ldns, ldns_version)


### Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([getopt.h string.h strings.h])


### Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM


### Checks for library functions.
AC_FUNC_VPRINTF

AC_CHECK_FUNCS([getopt_long snprintf])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
