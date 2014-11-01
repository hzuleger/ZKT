/*****************************************************************
**
**	@(#) misc.c -- helper functions for dnssec tools
**	(c) Jan 2005  Holger Zuleger  hznet.de
**
**	See LICENCE file for licence
**
*****************************************************************/
# include <stdio.h>
# include <string.h>
# include <ctype.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <time.h>
# include <utime.h>
# include <assert.h>
# include "config.h"
# include "zconf.h"
#define extern
# include "misc.h"
#undef extern

# define	TAINTCHARS	"$@;&<>|"

extern	const	char	*progname;

static	int	incr_soa (FILE *fp);
static	int	incr_soa_serial (FILE *fp);

int	touch (const char *fname, time_t sec)
{
	struct	utimbuf	utb;

	utb.actime = utb.modtime = sec;
	return utime (fname, &utb);
}

char	*strtaint (char *str)
{
	char	*p;

	for ( p = str; *p; p++ )
		if ( strchr (TAINTCHARS, *p) )
			*p = ' ';
	return str;
}

const	char	*splitpath (char *path, size_t  size, const char *filename)
{
	char 	*p;

	if ( !path )
		return filename;

	*path = '\0';
	if ( !filename )
		return filename;

	if ( (p = strrchr (filename, '/')) )	/* file arg contains path ? */
	{
		if ( strlen (filename) > size )
			return filename;

		strcpy (path, filename);
		path[p-filename] = '\0';
		filename = ++p;
	}
	return filename;
}

char	*pathname (char *path, size_t size, const char *dir, const char *file, const char *ext)
{
	int	len;

	if ( path == NULL || file == NULL )
		return path;

	len = strlen (file) + 1;
	if ( dir )
		len += strlen (dir);
	if ( ext )
		len += strlen (ext);
	if ( len > size )
		return path;

	*path = '\0';
	if ( dir && *dir )
	{
		len = sprintf (path, "%s", dir);
		if ( path[len-1] != '/' )
		{
			path[len++] = '/';
			path[len] = '\0';
		}
	}
	strcat (path, file);
	if ( ext )
		strcat (path, ext);
	return path;
}

int	is_directory (const char *name)
{
	struct	stat	st;

	if ( !name || !*name )	
		return 0;
	
	return ( stat (name, &st) == 0 && S_ISDIR (st.st_mode) );
}

int	fileexist (const char *name)
{
	struct	stat	st;
	return ( stat (name, &st) == 0 && S_ISREG (st.st_mode) );
}

int	is_keyfilename (const char *name)
{
	int	len;

	if ( name == NULL || *name != 'K' )
		return 0;

	len = strlen (name);
	if ( len > 4 && strcmp (&name[len - 4], ".key") == 0 ) 
		return 1;

	return 0;
}

int	is_dotfile (const char *name)
{
	if ( name && (
	     name[0] == '.' && name[1] == '\0' || 
	     name[0] == '.' && name[1] == '.' && name[2] == '\0') )
		return 1;

	return 0;
}

static	const char *strnrchr (const char *start, const char *end, int c)
{
	assert ( start != NULL );
	if ( end == NULL )
		end = start + strlen (start) - 1;

	while ( end >= start && *end != c )
		end--;

	return end >= start ? end : NULL;
}

/*****************************************************************
**	int domaincmp (a, b)
**	compare a and b as fqdns.
**	return <0 | 0 | >0 as in strcmp
**	A subdomain is less than te corresponding toplevel domain,
**	thus domaincmp ("a.example.net", "example.net") return < 0 !!
*****************************************************************/
int	domaincmp (const char *a, const char *b)
{
	int	res;
	const	char	*pa = NULL;
	const	char	*pb = NULL;

	if ( a == NULL ) return -1;
	if ( b == NULL ) return 1;
	do
	{
		if ( (pa = strnrchr (a, pa, '.')) == NULL )
			pa = a;
		if ( (pb = strnrchr (b, pb, '.')) == NULL )
			pb = b;
		if ( (res = strcmp (pa, pb)) != 0 )	/* not equal ? */
			return res;
		pa--;
		pb--;
	}  while ( pa >= a && pb >= b );

	return  (pa >= a) - (pb >= b );
}

time_t	get_mtime (const char *fname)
{
	struct	stat	st;

	if ( stat (fname, &st) < 0 )
		return 0;
	return st.st_mtime;
}

void fatal (char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        if ( progname )
		fprintf (stderr, "%s: ", progname);
        vfprintf (stderr, fmt, ap);
        va_end(ap);
        exit (1);
}

void error (char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf (stderr, fmt, ap);
        va_end(ap);
}

void logmesg (char *fmt, ...)
{
        va_list ap;

        fprintf (stdout, "%s: ", progname);
        va_start(ap, fmt);
        vfprintf (stdout, fmt, ap);
        va_end(ap);
}

char	*time2str (time_t sec)
{
	struct	tm	*t;
	static	char	timestr[31+1];	/* 27+1 should be enough */

#if defined(HAS_STRFTIME) && HAS_STRFTIME
	t = localtime (&sec);
# if SHOW_TIMEZONE
	strftime (timestr, sizeof (timestr), "%b %d %Y %T %z", t);
# else
	strftime (timestr, sizeof (timestr), "%b %d %Y %T", t);
# endif
#else
	static	char	*mstr[] = {
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
# if SHOW_TIMEZONE
	int	h,	s;

	t = localtime (&sec);
	s = abs (t->tm_gmtoff);
	h = t->tm_gmtoff / 3600;
	s = t->tm_gmtoff % 3600;
	snprintf (timestr, sizeof (timestr), "%s %2d %s %4d %02d:%02d:%02d %c%02d%02d", 
		mstr[t->tm_mon], t->tm_mday, t->tm_year + 1900, 
		t->tm_hour, t->tm_min, t->tm_sec,
		t->tm_gmtoff < 0 ? '-': '+',
		h, s);
# else
	t = localtime (&sec);
	snprintf (timestr, sizeof (timestr), "%s %2d %s %4d %02d:%02d:%02d", 
		mstr[t->tm_mon], t->tm_mday, t->tm_year + 1900, 
		t->tm_hour, t->tm_min, t->tm_sec);
# endif
#endif

	return timestr;
}

char	*age2str (time_t sec)
{
	static	char	str[20+1];	/* "2y51w6d23h50m55s" == 16+1 chars */
	int	len;
	int	strsize = sizeof (str);

	len = 0;
#if 1
# if SHOW_AGE_WITH_YEAR
	if ( sec / (YEARSEC) > 0 )
	{
		len += snprintf (str+len, strsize - len, "%1luy", sec / YEARSEC );
		sec %= (YEARSEC);
	}
	else
		len += snprintf (str+len, strsize - len, "  ");
# endif
	if ( sec / WEEKSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2luw", sec / WEEKSEC );
		sec %= WEEKSEC;
	}
	else
		len += snprintf (str+len, strsize - len, "   ");
	if ( sec / DAYSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2lud", sec / (ulong)DAYSEC);
		sec %= DAYSEC;
	}
	else
		len += snprintf (str+len, strsize - len, "   ");
	if ( sec / HOURSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2luh", sec / (ulong)HOURSEC);
		sec %= HOURSEC;
	}
	else
		len += snprintf (str+len, strsize - len, "   ");
	if ( sec / MINSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2lum", sec / (ulong)MINSEC);
		sec %= MINSEC;
	}
	else
		len += snprintf (str+len, strsize - len, "   ");
	if ( sec > 0 )
		snprintf (str+len, strsize - len, "%2lus", sec);
	else
		len += snprintf (str+len, strsize - len, "   ");
#else
# if SHOW_AGE_WITH_YEAR
	if ( sec / (YEARSEC) > 0 )
	{
		len += snprintf (str+len, strsize - len, "%luy", sec / YEARSEC );
		sec %= (YEARSEC);
	}
# endif
	if ( sec / WEEKSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2luw", sec / WEEKSEC );
		sec %= WEEKSEC;
	}
	if ( sec / DAYSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2lud", sec / (ulong)DAYSEC);
		sec %= DAYSEC;
	}
	if ( sec / HOURSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2luh", sec / (ulong)HOURSEC);
		sec %= HOURSEC;
	}
	if ( sec / MINSEC > 0 )
	{
		len += snprintf (str+len, strsize - len, "%2lum", sec / (ulong)MINSEC);
		sec %= MINSEC;
	}
	if ( sec > 0 )
		snprintf (str+len, strsize - len, "%2lus", sec);
#endif
	return str;
}

/****************************************************************
**
**	int	incr_serial (filename)
**
**	This function depends on a special syntax writing the
**	SOA record in the zone file!!
**
**	To match the SOA record the line must be formatted
**	like this:
**	@    IN  SOA <master.fq.dn.> <hostmaster.fq.dn.> (
**	<SPACEes or TABs>      1234567890; serial number 
**	<SPACEes or TABs>      86400	 ; other values
**				...
**	The space from the first digit of the serial number to
**	the first none white space char or to the end of the line
**	must be at least 10 characters!
**	So left justify the serial number in a field with 10
**	digits like this:
**	<SPACEes or TABs>      1         ; Serial 
**
****************************************************************/
int	incr_serial (const char *fname)
{
	FILE	*fp;
	char	buf[4095+1];
	char	master[254+1];
	int	ttl;
	int	error;

	if ( (fp = fopen (fname, "r+")) == NULL )
		return -1;

		/* read until line matches begin of soa record ... */
	while ( fgets (buf, sizeof buf, fp) &&
		    sscanf (buf, "@ IN SOA %255s %*s (\n", master) != 1 )
		;

	if ( feof (fp) )
	{
		fclose (fp);
		return-2;
	}

	error = incr_soa_serial (fp);	/* .. incr soa serial no ... */

	if ( fclose (fp) != 0 )
		return -5;
	return error;
}

/*****************************************************************
**	returns the today serial number in the form of YYYYmmdd00
*****************************************************************/
static	ulong	today_serialtime ()
{
	struct	tm	*t;
	ulong	serialtime;
	time_t	now;

	now =  time (NULL);
	t = gmtime (&now);
	serialtime = (t->tm_year + 1900) * 10000;
	serialtime += (t->tm_mon+1) * 100;
	serialtime += t->tm_mday;
	serialtime *= 100;

	return serialtime;
}

static	int	incr_soa_serial (FILE *fp)
{
	int	c;
	long	pos,	eos;
	ulong	serial;
	int	digits;
	ulong	today;

	/* move forward until any non ws reached */
	while ( (c = getc (fp)) != EOF && isspace (c) )
		;
	ungetc (c, fp);		/* push back the last char */

	pos = ftell (fp);	/* mark position */

	serial = 0L;	/* read in the actual serial number */
	/* be aware of the trailing space in the format string !! */
	if ( fscanf (fp, "%lu ", &serial) != 1 )	/* try to get serial no */
		return -3;
	eos = ftell (fp);	/* mark first non digit/ws character pos */

	digits =  eos - pos;
	if ( digits < 10 )	/* not enough space for serial no */
		return -4;

	today = today_serialtime ();	/* YYYYmmdd00 */
	if ( serial > 1970010100L && serial < today )	
		serial = today;			/* set to current time */
	serial++;			/* increment anyway */

	fseek (fp, pos, SEEK_SET);	/* go back to the beginning */
	fprintf (fp, "%-*lu", digits, serial);	/* write as many chars as before */

	return serial;	/* yep! */
}

#ifdef SOA_TEST
const char *progname;
main (int argc, char *argv[])
{
	ulong	now;
	int	err;
	char	cmd[255];

	progname = *argv;

	now = today_serialtime ();
	printf ("now = %lu\n", now);

	if ( (err = incr_serial (argv[1])) < 0 )
		error ("can't change serial errno=%d\n", err);

	snprintf (cmd, sizeof(cmd), "head -15 %s", argv[1]);
	system (cmd);
}
#endif
#ifdef DOMAINCMP_TEST
static	struct {
	char	*a;
	char	*b;
	int	res;
} ex[] = {
	{ ".",		".",	0 },
	{ "de",		"de",	0 },
	{ "de.",	"de.",	0 },
	{ ".de",	".de",	0 },
	{ ".de.",	".de.",	0 },
	{ "a.de",	".de",	1 },
	{ "a.de",	"b.de",	-1 },
	{ "aa.de",	"b.de",	-1 },
	{ "ba.de",	"b.de",	1 },
	{ "a.de",	"a.dk",	-1 },
	{ "anna.example.de",	"anna.example.de",	0 },
	{ "anna.example.de",	"annamirl.example.de",	-1 },
	{ "anna.example.de",	"ann.example.de",	1 },
	{ "example.de.",	"xy.example.de.",	1 },	/* top level domain is "greater" */
	{ "example.de.",	"ab.example.de.",	1 },
	{ "abc.example.de.",	"xy.example.de.",	-1 },
	{ NULL,	NULL,	0 }
};
main (int argc, char *argv[])
{
	
	int	expect;
	int	res;
	int	c;
	int	i;

	for ( i = 0; ex[i].a; i++ )
	{
		expect = ex[i].res;
		if ( expect < 0 )
			c = '<'; 
		else if ( expect > 0 )
			c = '>'; 
		else 
			c = '='; 
		printf ("%-20s %-20s ==> %c 0 ", ex[i].a, ex[i].b, c);
		fflush (stdout);
		res = domaincmp (ex[i].a, ex[i].b);
		printf ("%3d  ", res);
		if ( res < 0 && expect < 0 || res > 0 && expect > 0 || res == 0 && expect == 0 ) 
			puts ("ok");
		else
			puts ("not ok");
	}
}
#endif
