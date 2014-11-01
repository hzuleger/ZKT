/*****************************************************************
**	@(#) misc.h  (c) 2005 - 2007  Holger Zuleger  hznet.de
*****************************************************************/
#ifndef MISC_H
# define MISC_H
# include <sys/types.h>
# include <stdarg.h>
# include <stdio.h>
# include "zconf.h"

# define min(a, b)	((a) < (b) ? (a) : (b))
# define max(a, b)	((a) > (b) ? (a) : (b))

extern	const	char	*getnameappendix (const char *progname, const char *basename);
extern	const	char	*getdefconfname (const char *view);
extern	int	fileexist (const char *name);
extern	size_t	filesize (const char *name);
extern	int	file_age (const char *fname);
extern	int	touch (const char *fname, time_t sec);
extern	int	linkfile (const char *fromfile, const char *tofile);
//extern	int	copyfile (const char *fromfile, const char *tofile);
extern	int	copyfile (const char *fromfile, const char *tofile, const char *dnskeyfile);
extern	int	copyzonefile (const char *fromfile, const char *tofile, const char *dnskeyfile);
extern	int	cmpfile (const char *file1, const char *file2);
extern	char	*str_delspace (char *s);
extern	char	*str_tolowerdup (const char *s);
extern	int	in_strarr (const char *str, char *const arr[], int cnt);
extern	const	char	*splitpath (char *path, size_t  size, const char *filename);
extern	char	*pathname (char *name, size_t size, const char *path, const char *file, const char *ext);
extern	char	*time2str (time_t sec, int precision);
extern	char	*time2isostr (time_t sec, int precision);
extern	time_t	timestr2time (const char *timestr);
extern	int	is_keyfilename (const char *name);
extern	int	is_directory (const char *name);
extern	time_t	get_mtime (const char *fname);
extern	char	*age2str (time_t sec);
extern	time_t	stop_timer (time_t start);
extern	time_t	start_timer (void);
extern	void    error (char *fmt, ...);
extern	void    fatal (char *fmt, ...);
extern	void    logmesg (char *fmt, ...);
extern	void	verbmesg (int verblvl, const zconf_t *conf, char *fmt, ...);
extern	void	logflush (void);
extern	int	inc_serial (const char *fname, int use_unixtime);
extern	const	char	*inc_errstr (int err);
extern	char	*str_untaint (char *str);
extern	char	*str_chop (char *str, char c);
extern	int	is_dotfile (const char *name);
extern	void	parseurl (char *url, char **proto, char **host, char **port, char **para);
#endif
