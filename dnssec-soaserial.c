/*****************************************************************
**
**	@(#) dnssec-soaserial.c  (c) Oct 2007  Holger Zuleger  hznet.de
**
**	A small utility to print out the (unixtime) soa serial
**	number in a human readable form
**
**	See LICENCE file for licence
**
*****************************************************************/
# include <stdio.h>
# include <string.h>
# include <sys/types.h>
# include <time.h>
# include <utime.h>
# include <assert.h>
# include <stdlib.h>
# include "config.h"

static	const char *progname;

static	char	*timestr (time_t sec);
static	int	read_serial_fromfile (const char *fname, unsigned long *serial);
static	void	printserial (const char *fname, unsigned long serial);
static	void	usage (const char *msg);

/*****************************************************************
**	timestr (sec)
*****************************************************************/
static	char	*timestr (time_t sec)
{
	struct	tm	*t;
	static	char	timestr[31+1];	/* 27+1 should be enough */

#if defined(HAS_STRFTIME) && HAS_STRFTIME
	t = localtime (&sec);
	strftime (timestr, sizeof (timestr), "%b %d %Y %T %z", t);
#else
	static	char	*mstr[] = {
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	int	h,	s;

	t = localtime (&sec);
	s = abs (t->tm_gmtoff);
	h = t->tm_gmtoff / 3600;
	s = t->tm_gmtoff % 3600;
	snprintf (timestr, sizeof (timestr), "%s %2d %4d %02d:%02d:%02d %c%02d%02d", 
		mstr[t->tm_mon], t->tm_mday, t->tm_year + 1900, 
		t->tm_hour, t->tm_min, t->tm_sec,
		t->tm_gmtoff < 0 ? '-': '+',
		h, s);
#endif

	return timestr;
}


/****************************************************************
**
**	int	read_serial_fromfile (filename)
**
**	This function depends on a special syntax formating the
**	SOA record in the zone file!!
**
**	To match the SOA record, the SOA RR must be formatted
**	like this:
**	@    IN  SOA <master.fq.dn.> <hostmaster.fq.dn.> (
**	<SPACEes or TABs>      1234567890; serial number 
**	<SPACEes or TABs>      86400	 ; other values
**				...
**
****************************************************************/
static	int	read_serial_fromfile (const char *fname, unsigned long *serial)
{
	FILE	*fp;
	char	buf[4095+1];
	char	master[254+1];
	int	c;
	int	soafound;

	if ( (fp = fopen (fname, "r")) == NULL )
		return -1;		/* file not found */

		/* read until the line matches the beginning of a soa record ... */
	soafound = 0;
	while ( !soafound && fgets (buf, sizeof buf, fp) )
	{
		if ( sscanf (buf, "%*s %*d IN SOA %255s %*s (\n", master) == 1 )
			soafound = 1;
		else if ( sscanf (buf, "%*s IN SOA %255s %*s (\n", master) == 1 )
			soafound = 1;
	}

	if ( !soafound )
		return -2;	/* no zone file (soa not found) */

	/* move forward until any non ws is reached */
	while ( (c = getc (fp)) != EOF && isspace (c) )
		;
	ungetc (c, fp);		/* pushback the non ws */

	*serial = 0L;	/* read in the current serial number */
	if ( fscanf (fp, "%lu", serial) != 1 )	/* try to get serial no */
		return -3;	/* no serial number found */

	fclose (fp);

	return 0;	/* ok! */
}

/*****************************************************************
**	printserial()
*****************************************************************/
static	void	printserial (const char *fname, unsigned long serial)
{
	int	y,	m,	d,	v;

	if ( fname && *fname )
		printf ("%-30s\t", fname);

	printf ("%10lu", serial);

	/* try to guess the soa serial format */
	if ( serial < 1136070000L )	/* plain integer (this is 2006-1-1 00:00 in unixtime format) */
		;
	else if ( serial > 2006010100L )	/* date format */
	{
		int	y,	m,	d,	v;

		v = serial % 100;
		serial /= 100;
		d = serial % 100;
		serial /= 100;
		m = serial % 100;
		serial /= 100;
		y = serial;
		
		printf ("\t%d-%02d-%02d Version %02d", y, m, d, v);
	}
	else					/* unixtime */
		printf ("\t%s\n", timestr (serial) );

	printf ("\n");
}

/*****************************************************************
**	usage (msg)
*****************************************************************/
static	void	usage (const char *msg)
{
	if ( msg && *msg )
		fprintf (stderr, "%s\n", msg);
	fprintf (stderr, "usage: %s {-s serial | signed_zonefile [...]}\n", progname);

	exit (1);
}

/*****************************************************************
**	main()
*****************************************************************/
main (int argc, char *argv[])
{
	unsigned long	serial;

	progname = *argv;

	if ( --argc == 0 )
		usage ("");

	if ( argv[1][0] == '-' )
	{
		if ( argv[1][1] != 's' )
			usage ("illegal option");

		if ( argc != 2 )
			usage ("Option -s requires an argument");

		serial = atol (argv[2]);
		printserial ("", serial);
	}
	else
		while ( argc-- > 0 )
			if ( (read_serial_fromfile (*++argv, &serial)) != 0 )
				fprintf (stderr, "couldn't read serial number from file %s\n", *argv);
			else
				printserial (*argv, serial);

	return 0;
}
