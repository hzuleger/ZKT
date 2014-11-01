/*****************************************************************
**	@(#) misc.h  (c) Jan 2005  Holger Zuleger  hznet.de
*****************************************************************/
#ifndef MISC_H
# define MISC_H
# include <sys/types.h>
# include <stdarg.h>
# include <stdio.h>

extern	int	fileexist (const char *name);
extern	int	copyfile (const char *fname, FILE *outfp);
extern	int	touch (const char *fname, time_t sec);
extern	const	char	*splitpath (char *path, size_t  size, const char *filename);
extern	char	*pathname (char *name, size_t size, const char *path, const char *file, const char *ext);
extern	char	*time2str (time_t sec);
extern	int	is_keyfilename (const char *name);
extern	int	is_directory (const char *name);
extern	time_t	get_mtime (const char *fname);
extern	char	*age2str (time_t sec);
extern	void    error (char *fmt, ...);
extern	void    fatal (char *fmt, ...);
extern	void    logmesg (char *fmt, ...);
extern	int	incr_serial (const char *fname);
extern	char	*strtaint (char *str);
extern	int	is_dotfile (const char *name);
extern	int	domaincmp (const char *a, const char *b);
#endif
