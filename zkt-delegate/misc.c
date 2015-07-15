/*****************************************************************
**
**	@(#) misc.c -- error logging and other functions 
**
**	Copyright (c) Jan 2005, Holger Zuleger HZNET. All rights reserved.
**
**	This software is open source.
**
*****************************************************************/
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <unistd.h>	/* for link(), unlink() */
# include <ctype.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <time.h>
# include <utime.h>
# include <assert.h>
# include <errno.h>
# include <fcntl.h>
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#define extern
# include "misc.h"
#undef extern

extern	const char	*progname;
extern	int		verbose;


/*****************************************************************
**	ttlfromstr (s)
**	Set default ttl depending on RR type (ns, ds, glue)
*****************************************************************/
ulong	ttlfromstr (const char *s)
{
	ulong	ttl;

	if ( s == NULL )	/* no string present ? */
		return 0L;

	while ( isspace (*s) )
		s++;

	switch ( *s )
	{
	case 'n':	/* ns */
		ttl = DAYSEC (7);
		break;
	case 'd':	/* ds */
		ttl = DAYSEC (3);
		break;
	case 'g':	/* glue */
		ttl = MINSEC (10);
		break;
	default:
		ttl = atol (s);
		while ( isdigit (*s) )
			s++;

		switch ( *s )
		{
		case 'w':	ttl = WEEKSEC (ttl);	break;
		case 'd':	ttl = DAYSEC (ttl);	break;
		case 'h':	ttl = HOURSEC (ttl);	break;
		case 'm':	ttl = MINSEC (ttl);	break;
		case 's':				break;
		case '\0':				break;
		default:	fatal ("illegal ttl scaling %c\n", *s);
		}
	}

	return ttl;
}

/*****************************************************************
**	ttltostr (s)
*****************************************************************/
int	ttltostr (char *s, size_t size, ulong ttl)
{
	char	scale[2];

	scale[0] = scale[1] = '\0';
	if ( ttl % WEEKSEC (1) == 0 )
	{
		ttl /= WEEKSEC(1);
		*scale = 'w';
	}
	else if ( ttl % DAYSEC (1) == 0 )
	{
		ttl /= DAYSEC(1);
		*scale = 'd';
	}
	else if ( ttl % HOURSEC (1) == 0 )
	{
		ttl /= HOURSEC(1);
		*scale = 'h';
	}
	else if ( ttl % MINSEC (1) == 0 )
	{
		ttl /= MINSEC(1);
		*scale = 'm';
	}

	return snprintf (s, size, "<%lu%s>", ttl, scale);
}

/*****************************************************************
**	str_delspace (s)
**	Remove in string 's' all white space char 
*****************************************************************/
char	*str_delspace (char *s)
{
	char	*start;
	char	*p;

	if ( !s )	/* no string present ? */
		return NULL;

	start = s;
	for ( p = s; *p; p++ )
		if ( !isspace (*p) )
			*s++ = *p;	/* copy each nonspace */

	*s = '\0';	/* terminate string */

	return start;
}

/*****************************************************************
**	in_strarr (str, arr, cnt)
**	check if string array 'arr' contains the string 'str'
**	return 1 if true or 'arr' or 'str' is empty, otherwise 0
*****************************************************************/
int	in_strarr (const char *str, char *const arr[], int cnt)
{
	if ( arr == NULL || cnt <= 0 )
		return 1;

	if ( str == NULL || *str == '\0' )
		return 0;

	while ( --cnt >= 0 )
		if ( strcmp (str, arr[cnt]) == 0 )
			return 1;

	return 0;
}

/*****************************************************************
**	str_chop (str, c)
**	delete all occurrences of char 'c' at the end of string 's'
*****************************************************************/
char	*str_chop (char *str, char c)
{
	int	len;

	assert (str != NULL);

	len = strlen (str) - 1;
	while ( len >= 0 && str[len] == c )
		str[len--] = '\0';

	return str;
}

/*****************************************************************
**	skipdelim (str, delim)
**	skip all whitespace and optional delim chars at line, and
**	return a pointer in line with the first non-delim char
*****************************************************************/
const char	*skipdelim (const char *line, int delim)
{
	assert ( line != NULL );

	while ( isspace (*line) || (delim && *line == delim) )
		line++;

	return line;
}

/*****************************************************************
**	is_ipv4addr (str)
**	return 1 if str look like an ipv4 address
*****************************************************************/
int	is_ipv4addr (const char *ipaddrstr)
{
	assert ( ipaddrstr );

	while ( *ipaddrstr )
		if ( strchr ("0123456789.", *ipaddrstr++) == NULL )
			return 0;
	return 1;
}

/*****************************************************************
**	is_ipv6addr (str)
**	return 1 if str look like an ipv4 address
*****************************************************************/
int	is_ipv6addr (const char *ipaddrstr)
{
	assert ( ipaddrstr );

	while ( *ipaddrstr )
		if ( strchr ("0123456789:abcdefABCDEF", *ipaddrstr++) == NULL )
			return 0;
	return 1;
}

/*****************************************************************
**	fatal (fmt, ...)
*****************************************************************/
void	fatal (char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        if ( progname )
		fprintf (stderr, "%s: ", progname);
        vfprintf (stderr, fmt, ap);
        va_end(ap);
        exit (127);
}

/*****************************************************************
**	error (fmt, ...)
*****************************************************************/
void	error (char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf (stderr, fmt, ap);
        va_end(ap);
}

/*****************************************************************
**	logmesg (fmt, ...)
*****************************************************************/
void logmesg (char *fmt, ...)
{
        va_list ap;

#if defined (LOG_WITH_PROGNAME) && LOG_WITH_PROGNAME
        fprintf (stdout, "%s: ", progname);
#endif
        va_start(ap, fmt);
        vfprintf (stdout, fmt, ap);
        va_end(ap);
}

/*****************************************************************
**	verbmesg (verblvl, conf, fmt, ...)
*****************************************************************/
void	verbmesg (int verblvl, char *fmt, ...)
{
	char	str[511+1];
        va_list ap;

	str[0] = '\0';
	va_start(ap, fmt);
	vsnprintf (str, sizeof (str), fmt, ap);
	va_end(ap);

	//fprintf (stderr, "verbmesg (%d stdout=%d filelog=%d str = :%s:\n", verblvl, conf->verbosity, conf->verboselog, str);
	if ( verblvl <= verbose )	/* check if we have to print this to stdout */
		logmesg (str);
}


/*****************************************************************
**	logflush ()
*****************************************************************/
void logflush ()
{
        fflush (stdout);
}

