/*****************************************************************
**
**	@(#) config.h -- config options for ZKT
**	
*****************************************************************/
#ifndef CONF_H
# define CONF_H

#ifndef HAS_STRFTIME
# define	HAS_STRFTIME	1
#endif

#ifndef HAS_UTYPES
# define	HAS_UTYPES	1
#endif

#ifndef HAS_ULONG
# define	HAS_ULONG	1
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

# define	REG_URL		"register.trusted-keys.de:5327"
//# define	REG_URL		"regkey://trusted-keys.de"

#ifndef BIND_UTIL_PATH
# define	BIND_UTIL_PATH	"/usr/local/sbin/"
#endif

#ifndef CONFIG_PATH
# define	CONFIG_PATH	"/var/named/"
#endif

#ifndef ZKT_VERSION
# if defined(USE_TREE) && USE_TREE
#  define	ZKT_VERSION	"vT0.70 (c) Feb - Aug 2005  Holger Zuleger  hznet.de"
# else
#  define	ZKT_VERSION	"v0.70 (c) Feb - Aug 2005  Holger Zuleger  hznet.de"
# endif
#endif

#endif
