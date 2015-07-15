/*****************************************************************
**
**	@(#) readkeyfile.c -- A very simple named.conf key parser
**
**	read a keyfile in named.conf syntax and optional look
**	for a named key.
**	return the keyname, algorithm and the secret.
**
*****************************************************************/
#include <stdio.h>
#include <assert.h>
# include <string.h>
# include <ctype.h>
# include "debug.h"
#define extern
# include "readkeyfile.h"
#undef extern

static	int	parse_keyconf (const char *filename, char *dir, size_t dirsize, tsigkey_t *k, const char *lookup);

int	readkeyfile (const char *fname, tsigkey_t *k, const char *lookupkey)
{
	char	directory[255+1];

	assert ( fname != NULL );
	assert ( k != NULL );

	directory[0] = '\0';
	return parse_keyconf (fname, directory, sizeof (directory), k, lookupkey);
}

/*****************************************************************
**	now the private (static) stuff
*****************************************************************/
# define	TOK_STRING	257
# define	TOK_DIR		258
# define	TOK_INCLUDE	259

# define	TOK_KEY		271
# define	TOK_SECRET	272
# define	TOK_ALG		273
# define	TOK_HMAC_MD5	274
# define	TOK_HMAC_SHA1	275
# define	TOK_HMAC_SHA224	276
# define	TOK_HMAC_SHA256	277
# define	TOK_HMAC_SHA384	278
# define	TOK_HMAC_SHA512	279

# define	TOK_UNKNOWN	511

/* list of "named.conf" keywords we are interested in */
static struct KeyWords {
	char	*name;
	int	tok;
} kw[] = {
	{ "STRING",	TOK_STRING },
	{ "include",	TOK_INCLUDE },
	{ "directory",	TOK_DIR },

	{ "key",	TOK_KEY },
	{ "secret",	TOK_SECRET },
	{ "algorithm",	TOK_ALG },
	{ "hmac-md5",	TOK_HMAC_MD5 },
	{ "hmac-sha1",	TOK_HMAC_SHA1 },
	{ "hmac-sha224",	TOK_HMAC_SHA224 },
	{ "hmac-sha256",	TOK_HMAC_SHA256 },
	{ "hmac-sha384",	TOK_HMAC_SHA384 },
	{ "hmac-sha512",	TOK_HMAC_SHA512 },

	{ NULL,		TOK_UNKNOWN },
};

#ifdef DBG
static	const char	*tok2str (int  tok)
{
	int	i;

	i = 0;
	while ( kw[i].name && kw[i].tok != tok )
		i++;

	return kw[i].name;
}
#endif

static	int	searchkw (const char *keyword)
{
	int	i;

	dbg_val ("keyparse: searchkw (%s)\n", keyword);
	i = 0;
	while ( kw[i].name && strcmp (kw[i].name, keyword) != 0 )
		i++;

	return kw[i].tok;
}

static	int	gettok (FILE *fp, char *val, size_t valsize)
{
	int	lastc;
	int	c;
	char	*p;
	char	*bufend;

	*val = '\0';
	do {
		while ( (c = getc (fp)) != EOF && isspace (c) )
			;

		if ( c == '#' )		/* single line comment ? */
		{
			while ( (c = getc (fp)) != EOF && c != '\n' )
				;
			continue;
		}

		if ( c == EOF )
			return EOF;

		if ( c == '{' || c == '}' || c == ';' )
			continue;

		if ( c == '/' )		/* begin of C comment ? */
		{
			if ( (c = getc (fp)) == '*' )	/* yes! */
			{
				lastc = EOF;		/* read until end of c comment */
				while ( (c = getc (fp)) != EOF && !(lastc == '*' && c == '/') )
					lastc = c;
			}	
			else if ( c == '/' )	/* is it a C single line comment ? */
			{
				while ( (c = getc (fp)) != EOF && c != '\n' )
					;
			}
			else		/* no ! */
				ungetc (c, fp);
			continue;
		}

		if ( c == '\"' )
		{
			p = val;
			bufend = val + valsize - 1;
			while ( (c = getc (fp)) != EOF && p < bufend && c != '\"' )
				*p++ = c;
			*p = '\0';
			/* if string buffer is too small, eat up rest of string */
			while ( c != EOF && c != '\"' )
				c = getc (fp);
			
			return TOK_STRING;
		}

		p = val;
		bufend = val + valsize - 1;
		do
			*p++ = tolower (c);
		while ( (c = getc (fp)) != EOF && p < bufend && (isalnum (c) || c == '-') );
		*p = '\0';
		ungetc (c, fp);

		if ( (c = searchkw (val)) != TOK_UNKNOWN )
			return c;
	}  while ( c != EOF );

	return EOF;
}

/*****************************************************************
**
**	parse_keyconf (const char *filename, dir, dirsize, int (*func) ())
**
**	Very dumb named.conf parser.
**	- For every key definition "func (keyname, algo, secret)" will be called
**
*****************************************************************/
static	int	parse_keyconf (const char *filename, char *dir, size_t dirsize, tsigkey_t *k, const char *lookup)
{
	FILE	*fp;
	int	ret;
	int	tok;
	char	path[511+1];
	char	strval[4095+1];
	char	key[255+1];
	char	alg[31+1];
	char	secret[255+1];

	dbg_val ("parse_keyconf: parsing file \"%s\" \n", filename);

	assert (filename != NULL);
	assert (dir != NULL && dirsize != 0);
	assert ( k != NULL);

	if ( (fp = fopen (filename, "r")) == NULL )
		return -1;

	ret = 0;
	while ( (tok = gettok (fp, strval, sizeof strval)) != EOF )
	{
		if ( tok > 0 && tok < 256 )
		{
			fprintf (stderr, "parse_keyconf: token found with value %-10d: %c\n", tok, tok);
		}
		else if ( tok == TOK_DIR )
		{
			if ( gettok (fp, strval, sizeof (strval)) == TOK_STRING )
			{
				dbg_val2 ("parse_namedconf: directory found \"%s\" (dir is %s)\n", strval, dir);
				if ( *strval != '/' &&  *dir )
					snprintf (path, sizeof (path), "%s/%s", dir, strval);
				else
					snprintf (path, sizeof (path), "%s", strval);

				snprintf (dir, dirsize, "%s", path);
				dbg_val ("parse_namedconf: new dir \"%s\" \n", dir);
			}	
		}	
		else if ( tok == TOK_INCLUDE )
		{
			if ( gettok (fp, strval, sizeof (strval)) == TOK_STRING )
			{
				if ( *strval != '/' && *dir )
					snprintf (path, sizeof (path), "%s/%s", dir, strval);
				else
					snprintf (path, sizeof (path), "%s", strval);
				if ( (ret = parse_keyconf (path, dir, dirsize, k, lookup)) != 0 )
					return ret;
			}
			else
			{
				fprintf (stderr, "parse_keyconf: need a filename after \"include\"!\n");
			}
		}
		else if ( tok == TOK_KEY )
		{
			int	nrtok;

			dbg_val0 ("parse_keyconf: new key found \n");
			if ( gettok (fp, strval, sizeof (strval)) != TOK_STRING )
				continue;
			snprintf (key, sizeof key, "%s", strval);	/* store the name of the key */
			dbg_val ("parse_keyconf: keyname \"%s\" \n", key);

			nrtok = 0;
			while ( nrtok < 2 && (tok = gettok (fp, strval, sizeof (strval))) )
			{
				if ( tok == TOK_ALG )
				{
					switch ( gettok (fp, strval, sizeof (strval)) )
					{
					case TOK_HMAC_MD5:
					case TOK_HMAC_SHA1:
					case TOK_HMAC_SHA224:
					case TOK_HMAC_SHA256:
					case TOK_HMAC_SHA384:
					case TOK_HMAC_SHA512:
						snprintf (alg, sizeof alg, "%s", strval);	/* this is the algorithm */
						break;
					default:
						*alg = '\0';
						continue;
					}
				}
				else if ( tok == TOK_SECRET )
				{
					if ( gettok (fp, strval, sizeof (strval)) != TOK_STRING )
						break;
					snprintf (secret, sizeof secret, "%s", strval);	/* this is the secret */
				}
				nrtok++;
			}

			dbg_val5 ("dir %s key %s alg %s secret %s lookup \"%s\"\n",
							dir, key, alg, secret, lookup ? lookup: "NULL");
			if ( lookup == NULL || lookup[0] == '\0' || strcmp (key, lookup) == 0 )
			{
				snprintf (k->name, sizeof (k->name), "%s", key);
				snprintf (k->algo, sizeof (k->algo), "%s", alg);
				snprintf (k->secret, sizeof (k->secret), "%s", secret);
				ret = 1;
				break;
			}
		}
		else 
			dbg_val3 ("%-10s(%d): %s\n", tok2str(tok), tok, strval);
	}
	fclose (fp);

	dbg_val2 ("parse_keyconf: leaving file \"%s\" ret = %d \n", filename, ret);

	return ret;
}

#ifdef TEST
int	printkey (tsigkey_t *k)
{
	printf ("printkey ");
	printf ("key \"%s\" " , k->name);
	printf ("alg \"%s\" " , k->algo);
	printf ("secret \"%s\" " , k->secret);
	putchar ('\n');
	return 1;
}

char	*progname;

main (int argc, char *argv[])
{
	char	directory[255+1];
	tsigkey_t	key;

	progname = argv[0];

	directory[0] = '\0';
	if ( --argc == 0 )
		parse_keyconf ("/var/named/named.conf", directory, sizeof (directory), &key, NULL);
	else 
		parse_keyconf (argv[1], directory, sizeof (directory), &key, argv[2]);
	printkey (&key);
}
#endif
