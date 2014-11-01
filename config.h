/*****************************************************************
**
**	@(#) config.h -- config options 
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

#ifndef SHOW_TIMEZONE
# define	SHOW_TIMEZONE	0
#endif

#ifndef SHOW_AGE_WITH_YEAR
# define	SHOW_AGE_WITH_YEAR	0
#endif

#ifndef BIND_UTIL_PATH
# define	BIND_UTIL_PATH	"/usr/local/sbin/"
#endif

#ifndef CONFIGFILE_PATH
# define	CONFIGFILE_PATH	"/var/named/"
#endif

#ifndef ZKT_VERSION
# define	ZKT_VERSION	"v0.5 (c) March 2005  Holger Zuleger  hznet.de"
#endif

#endif
