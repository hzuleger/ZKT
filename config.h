/*****************************************************************
**
**	@(#) config.h -- config options for ZKT
**	
*****************************************************************/
#ifndef CONF_H
# define CONF_H

#ifndef HAS_GETOPT_LONG
# define	HAS_GETOPT_LONG	1
#endif

#ifndef HAS_STRFTIME
# define	HAS_STRFTIME	1
#endif

#ifndef HAS_TIMEGM
# define	HAS_TIMEGM	1
#endif

#ifndef HAS_UTYPES
# define	HAS_UTYPES	1
#endif

#ifndef PRINT_TIMEZONE
# define	PRINT_TIMEZONE	0
#endif

#ifndef PRINT_AGE_WITH_YEAR
# define	PRINT_AGE_WITH_YEAR	0
#endif

#ifndef LOG_WITH_PROGNAME
# define	LOG_WITH_PROGNAME	0
#endif

#ifndef TTL_IN_KEYFILE_ALLOWED
# define	TTL_IN_KEYFILE_ALLOWED	1
#endif

#ifndef USE_TREE
# define	USE_TREE	1
#endif

#ifndef REG_URL
//# define	REG_URL		"register.trusted-keys.de:5327"
#endif

#ifndef LOG_WITH_TIMESTAMP
# define	LOG_WITH_TIMESTAMP	1
#endif

#ifndef LOG_WITH_LEVEL
# define	LOG_WITH_LEVEL		1
#endif

#ifndef LOG_FNAMETMPL
#if 1
#  define	LOG_FNAMETMPL	"/zkt-%04d-%02d-%02dT%02d%02d%02dZ.log"
# else
#  define	LOG_FNAMETMPL	"/zkt-%04d-%02d-%02dT%02d:%02d:%02dZ.log"
# endif
#endif

#ifndef BIND_VERSION
# define	BIND_VERSION	942
#endif

#ifndef BIND_UTIL_PATH
# define	BIND_UTIL_PATH	"/usr/local/sbin/"
#endif

#ifndef CONFIG_PATH
# define	CONFIG_PATH	"/var/named/"
#endif

#ifndef ZKT_VERSION
# if defined(USE_TREE) && USE_TREE
#  define	ZKT_VERSION	"vT0.96 (c) Feb 2005 - Jun 2008 Holger Zuleger hznet.de"
# else
#  define	ZKT_VERSION	"v0.96 (c) Feb 2005 - Jun 2008 Holger Zuleger hznet.de"
# endif
#endif

/* don't change anything below this */

#if !defined(HAS_UTYPES) || !HAS_UTYPES
typedef	unsigned long	ulong;
typedef	unsigned int	uint;
typedef	unsigned short	ushort;
typedef	unsigned char	uchar;
#endif

#endif
