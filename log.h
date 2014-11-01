/*****************************************************************
**	@(#) log.h  (c) June 2008  Holger Zuleger  hznet.de
*****************************************************************/
#ifndef LOG_H
# define LOG_H
# include <sys/types.h>
# include <stdarg.h>
# include <stdio.h>
# include <time.h>
# include <syslog.h>

typedef enum {
	LG_NONE = 0,
	LG_DEBUG,
	LG_INFO,
	LG_NOTICE,
	LG_WARNING,
	LG_ERROR,
	LG_FATAL
} lg_lvl_t;

extern	lg_lvl_t	lg_str2lvl (const char *name);
extern	int	lg_str2syslog (const char *facility);
extern	const	char	*lg_lvl2str (lg_lvl_t level);
extern	long	lg_geterrcnt (void);
extern	long	lg_seterrcnt (long value);
extern	long	lg_reseterrcnt (void);
extern	int	lg_open (const char *progname, const char *facility, const char *syslevel, const char *path, const char *file, const char *filelevel);
extern	int	lg_close (void);
extern	void	lg_args (lg_lvl_t level, int argc, char * const argv[]);
extern	void	lg_mesg (int level, char *fmt, ...);
#endif
