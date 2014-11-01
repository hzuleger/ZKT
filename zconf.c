/****************************************************************
**
**	@(#) zconf.c -- configuration file parser for dnssec.conf
**	Most of the code is from SixXS Heartbeat Client
**	written by by Jeroen Massar <jeroen@sixxs.net>
**
**	New config types and some slightly code changes by <hoz>

**	See LICENCE file for licence
**
****************************************************************/
# include <sys/types.h>
# include <stdio.h>
# include <errno.h>
# include <unistd.h>
# include <stdlib.h>
# include <stdarg.h>
# include <string.h>
# include <strings.h>
# include <ctype.h>

# include "config.h"
#define extern
# include "zconf.h"
#undef extern
# include "dki.h"

# define	ISTRUE(val)	(strcasecmp (val, "yes") == 0 || \
				strcasecmp (val, "true") == 0    )
# define	ISCOMMENT(cp)	(*(cp) == '#' || *(cp) == ';' || \
				(*(cp) == '/' && *((cp)+1) == '/') )
# define	ISDELIM(c)	( isspace (c) || (c) == ':' || (c) == '=' )


#define CONF_END	0
#define CONF_STRING	1
#define CONF_INT	2
#define CONF_TIMEINT	3
#define CONF_BOOL	4
#define CONF_ALGO	5
#define CONF_COMMENT	6

static	zconf_t	def = {
	ZONEDIR, RECURSIVE, 
	1, 0,
	SIG_VALIDITY, MAX_TTL, PROPTIME, RESIGN_INT,
	KSK_LIFETIME, KSK_ALGO, 1024,
	ZSK_LIFETIME, ZSK_ALGO, 512,
	DNSKEYFILE, ZONEFILE, 
	LOOKASIDEDOMAIN,
};

typedef	struct {
	char	*label;
	int	type;
	void	*var;
} zconf_para_t;

static	zconf_para_t	conf[] = {
	{ "",			CONF_COMMENT,	""},
	{ "",			CONF_COMMENT,	"\t@(#) dnssec.conf " ZKT_VERSION },
	{ "",			CONF_COMMENT,	""},
	{ "",			CONF_COMMENT,	NULL },

	{ "",			CONF_COMMENT,	"dnssec-zkt options" },
	{ "Zonedir",		CONF_STRING,	&def.zonedir },
	{ "Recursive",		CONF_BOOL,	&def.recursive },
	{ "PrintTime",		CONF_BOOL,	&def.printtime },
	{ "PrintAge",		CONF_BOOL,	&def.printage },

	{ "",			CONF_COMMENT,	NULL },
	{ "",			CONF_COMMENT,	"zone specific timing values" },
	{ "ResignInterval",	CONF_TIMEINT,	&def.resign },
	{ "Sigvalidity",	CONF_TIMEINT,	&def.sigvalidity },
	{ "Max_TTL",		CONF_TIMEINT,	&def.max_ttl },
	{ "Propagation",	CONF_TIMEINT,	&def.proptime },
#if defined (DEF_TTL)
	{ "def_ttl",		CONF_TIMEINT,	&def.def_ttl },
#endif

	{ "",			CONF_COMMENT,	NULL },
	{ "",			CONF_COMMENT,	"signing key parameters"},
	{ "KSK_lifetime",	CONF_TIMEINT,	&def.k_life },
	{ "KSK_algo",		CONF_ALGO,	&def.k_algo },
	{ "KSK_bits",		CONF_INT,	&def.k_bits },
	{ "ZSK_lifetime",	CONF_TIMEINT,	&def.z_life },
	{ "ZSK_algo",		CONF_ALGO,	&def.z_algo },
	{ "ZSK_bits",		CONF_INT,	&def.z_bits },

	{ "",			CONF_COMMENT,	NULL },
	{ "",			CONF_COMMENT,	"dnssec-signer options"},
	{ "Keyfile",		CONF_STRING,	&def.keyfile },
	{ "Zonefile",		CONF_STRING,	&def.zonefile },
	{ "DLV_Domain",		CONF_STRING,	&def.lookaside },

	{ NULL,			CONF_END,	NULL},
};

static	const char	*bool2str (int val)
{
	return val ? "True" : "False";
}

static	const char	*timeint2str (int val)
{
	static	char	str[20+1];

	if ( val == 0 )
		snprintf (str, sizeof (str), "%d", val / YEARSEC);
	else if ( val % YEARSEC == 0 )
		snprintf (str, sizeof (str), "%dy", val / YEARSEC);
	else if ( val % WEEKSEC == 0 )
		snprintf (str, sizeof (str), "%dw", val / WEEKSEC);
	else if ( val % DAYSEC == 0 )
		snprintf (str, sizeof (str), "%dd", val / DAYSEC);
	else if ( val % HOURSEC == 0 )
		snprintf (str, sizeof (str), "%dh", val / HOURSEC);
	else if ( val % MINSEC == 0 )
		snprintf (str, sizeof (str), "%dm", val / MINSEC);
	else
		snprintf (str, sizeof (str), "%ds", val);

	return str;
}

static	int set_varptr (char *entry, void *ptr)
{
	zconf_para_t	*c;

	for ( c = conf; c->label; c++ )
		if ( strcasecmp (entry, c->label) == 0 )
		{
			c->var = ptr;
			return 1;
		}
	return 0;
}

static	int set_all_varptr (zconf_t *cp)
{
	set_varptr ("zonedir", &cp->zonedir);
	set_varptr ("recursive", &cp->recursive);
	set_varptr ("printage", &cp->printage);
	set_varptr ("printtime", &cp->printtime);

	set_varptr ("resigninterval", &cp->resign);
	set_varptr ("sigvalidity", &cp->sigvalidity);
	set_varptr ("max_ttl", &cp->max_ttl);
	set_varptr ("propagation", &cp->proptime);
#if defined (DEF_TTL)
	set_varptr ("def_ttl", &cp->def_ttl);
#endif

	set_varptr ("ksk_lifetime", &cp->k_life);
	set_varptr ("ksk_algo", &cp->k_algo);
	set_varptr ("ksk_bits", &cp->k_bits);

	set_varptr ("zsk_lifetime", &cp->z_life);
	set_varptr ("zsk_algo", &cp->z_algo);
	set_varptr ("zsk_bits", &cp->z_bits);

	set_varptr ("keyfile", &cp->keyfile);
	set_varptr ("zonefile", &cp->zonefile);
	set_varptr ("dlv_domain", &cp->lookaside);
}

zconf_t	*loadconfig (char *filename, zconf_t *z)
{
	FILE		*fp;
	char		buf[1023+1];
	char		*end, *val, *p;
	unsigned int	line, i, len, found;
	zconf_para_t	*c;

	if ( z == NULL )
	{
		if ( (z = calloc (1, sizeof (zconf_t))) == NULL )
			return NULL;
		memcpy (z, &def, sizeof (*z));		/* init with defaults */
	}

	if ( filename == NULL || *filename == '\0' )
	{
		memcpy (z, &def, sizeof (*z));		/* init with defaults */
		return z;
	}

	set_all_varptr (z);

	if ( (fp = fopen(filename, "r")) == NULL )
		fatal ("Could not open config file \"%s\"\n", filename);

	line = 0;
	while (fgets(buf, sizeof(buf), fp))
	{
		line++;

		p = &buf[strlen(buf)-1];        /* Chop off white space at eol */
		while ( p >= buf && isspace (*p) )
			*p-- = '\0';

		/* Ignore comments and emtpy lines */
		if ( buf[0] == '\0' || ISCOMMENT (buf) )
			continue;

		/* Get the end of the first argument */
		p = buf;
		end = &buf[strlen(buf)-1];
		while ( p < end && !ISDELIM (*p) )      /* Skip until delim */
			p++;
		*p++ = '\0';    /* Terminate this argument */


		while ( p < end && ISDELIM (*p) )	/* Skip delim chars */
			p++;

		val = p;	/* Start of the value */

		/* If starting with quotes, skip until next quotes */
		if ( *p == '"' || *p == '\'' )
		{
			p++;    /* Find next quote */
			while ( p <= end && *p && *p != *val )
				p++;
			*p = '\0';
			val++;          /* Skip the first quote */
		}
		else    /* Otherwise check if there is any comment char at end */
		{
			while ( p < end && *p && !ISCOMMENT(p) )
				p++;
			if ( ISCOMMENT (p) )
			{
				do      /* Chop off white space before comment */
					*p-- = '\0';
				while ( p >= val && isspace (*p) );
			}
		}

		/* Otherwise it is already terminated above */

                found = 0;
                c = conf;
                while ( !found && c->type != CONF_END )
		{
			len = strlen (c->label);
			if ( strcasecmp (buf, c->label) == 0 )
			{
				char	**str;
				char	quantity;
				int	ival;

				found = 1;
				switch ( c->type )
				{
				case CONF_STRING:
					str = (char **)c->var;
					*str = strdup (val);
					strtaint (*str);	/* remove "bad" characters */
					break;
				case CONF_INT:
					sscanf (val, "%d", (int *)c->var);
					break;
				case CONF_TIMEINT:
					quantity = 'd';
					sscanf (val, "%d%c", &ival, &quantity);
					if  ( quantity == 'm' )
						ival *= MINSEC;
					else if  ( quantity == 'h' )
						ival *= HOURSEC;
					else if  ( quantity == 'd' )
						ival *= DAYSEC;
					else if  ( quantity == 'w' )
						ival *= WEEKSEC;
					else if  ( quantity == 'y' )
						ival *= YEARSEC;
					(*(int *)c->var) = ival;
					break;
				case CONF_ALGO:
					if ( strcasecmp (val, "rsa") == 0 || strcasecmp (val, "rsamd5") == 0 )
						*((int *)c->var) = DK_ALGO_RSA;
					else if ( strcasecmp (val, "dsa") == 0 )
						*((int *)c->var) = DK_ALGO_DSA;
					else if ( strcasecmp (val, "rsasha1") == 0 )
						*((int *)c->var) = DK_ALGO_RSASHA1;
					else
						error ("Illegal algorithm \"%s\" "
							"in line %d.\n" , val, line);
					break;
				case CONF_BOOL:
					*((int *)c->var) = ISTRUE (val);
					break;
				default:
					fatal ("Illegal configuration type in line %d.\n", line);
				}
			}
			c++;
		}
                if ( !found )
			error ("Unknown configuration statement: %s \"%s\"\n", buf, val);
	}
	fclose(fp);
	return z;
}

int	printconfig (const char *fname, const zconf_t *z)
{
	zconf_para_t	*cp;
	FILE	*fp;

	if ( z == NULL )
		return;

	fp = stdout;
	if ( fname && *fname )
		if ( strcmp (fname, "stdout") == 0 )
			fp = stdout;
		else if ( strcmp (fname, "stderr") == 0 )
			fp = stderr;
		else if ( (fp = fopen(fname, "w")) == NULL )
		{
			error ("Could not open config file \"%s\" for writing\n", fname);
			return -1;
		}
		
	set_all_varptr ((zconf_t *)z);

	for ( cp = conf; cp->label; cp++ )
	{
		switch ( cp->type )
		{
		int	i;

		case CONF_COMMENT:
			if ( cp->var )
				fprintf (fp, "#   %s\n", (char *)cp->var);
			else
				fprintf (fp, "\n");
			break;
		case CONF_STRING:
			if ( *(char **)cp->var )
				fprintf (fp, "%s:\t\"%s\"\n", cp->label, *(char **)cp->var);
			break;
		case CONF_BOOL:
			fprintf (fp, "%s:\t%s\n", cp->label, bool2str ( *(int*)cp->var ));
			break;
		case CONF_TIMEINT:
			i = *(ulong*)cp->var;
			fprintf (fp, "%s:\t%s", cp->label, timeint2str (i));
			if ( i )
				fprintf (fp, "\t# (%d seconds)", i);
			putc ('\n', fp);
			break;
		case CONF_ALGO:
			i = *(int*)cp->var;
			fprintf (fp, "%s:\t%s", cp->label, dki_algo2str (i));
			fprintf (fp, "\t# (Algorithm ID %d)\n", i);
			break;
		case CONF_INT:
			fprintf (fp, "%s:\t%d\n", cp->label, *(int *)cp->var);
			break;
		}
	}
}
