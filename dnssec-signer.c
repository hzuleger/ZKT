/*****************************************************************
**
**	@(#) dnssec-signer.c  (c) Jan 2005  Holger Zuleger hznet.de
**
**	See LICENCE file for licence
**
*****************************************************************/

# include <stdio.h>
# include <assert.h>
# include <dirent.h>
# include <unistd.h>	/* getopt() etc.. */
# include "config.h"
# include "zconf.h"
# include "strlist.h"
# include "debug.h"
# include "misc.h"
# include "zone.h"
# include "dki.h"

/**	function declaration	**/
static	void	usage (char *mesg, zconf_t *conf);
static	int	parsedir (const char *dir, zone_t **zp, const zconf_t *conf);
static	int	dosigning (zone_t *zp);
static	int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
static	int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *conf);
static	dki_t	*genkey (dki_t **listp, const char *dir, const char *domain, int ksk, const zconf_t *conf, int status);
static	int	writekeyfile (const char *fname, const dki_t *list);
static	int	sign_zone (const char *dir, const char *domain, const zconf_t *conf);
static	int	reload_zone (const char *domain);

/**	global command line options	**/
const	char	*progname;
static	int	verbose = 0;
static	int	force = 0;
static	int	reloadflag = 0;
static	int	noexec = 0;
static	char	*searchlist = NULL;

main (int argc, char *argv[])
{
	int	c;
	char	errstr[255+1];
	char	*dir;
	zconf_t	*config;
	zone_t	*zonelist;
	zone_t	*zp;

	progname = *argv;
	if ( (dir = strrchr (progname, '/')) )
		progname = ++dir;

	config = loadconfig ("", (zconf_t *)NULL);	/* load config (defaults) */
	if ( fileexist (CONFIGFILE) )			/* load default config file */
		config = loadconfig (CONFIGFILE, config);
	if ( config == NULL )
		fatal ("Out of memory\n");

	zonelist = NULL;
        opterr = 0;
	while ( (c = getopt (argc, argv, "N:c:fhl:nrv")) != -1 )
	{
		switch ( c )
		{
		case 'N':
			break;
		case 'c':
			config = loadconfig (optarg, config);
			if ( config == NULL )
				fatal ("Out of memory\n");
			break;
		case 'f':
			force++;
			break;
		case 'h':
			usage (NULL, config);
			break;
		case 'l':
			searchlist = prepstrlist (optarg);
			if ( searchlist == NULL )
				fatal ("Out of memory\n");
			break;
		case 'n':
			noexec = 1;
			break;
		case 'r':
			reloadflag = 1;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
			if ( isprint (optopt) )
				snprintf (errstr, sizeof(errstr),
					"Unknown option \"-%c\".\n", optopt);
			else
				snprintf (errstr, sizeof (errstr),
					"Unknown option char \\x%x.\n", optopt);
			usage (errstr, config);
			break;
		default:
			abort();
		}
	}
	dbg_line();

	c = optind;
	do {
		if ( c < argc )		/* argument given ? */
			parsedir (argv[c++], &zonelist, config);
		else if ( zonelist == NULL )
			parsedir (config->zonedir, &zonelist, config);
	}  while ( c < argc );

	for ( zp = zonelist; zp; zp = zp->next )
		dosigning (zp);
	zone_freelist (&zonelist);

	return 0;
}

static	void	usage (char *mesg, zconf_t *conf)
{
	fprintf (stderr, "%s version %s\n", progname, ZKT_VERSION);
	fprintf (stderr, "\n");

	fprintf (stderr, "usage: %s [-c config] [-l zonelist] [-fhnr] [-v [-v]] [dir]\n",
									progname);

	fprintf (stderr, "\t-c file\t read config from <file> instead of %s\n", CONFIGFILE);
	fprintf (stderr, "\t-l list\t sign only zones given in the comma or space separated <list> \n");
	fprintf (stderr, "\t-h\t print this help\n");
	fprintf (stderr, "\t-f\t force resigning\n");
	fprintf (stderr, "\t-n\t no execution of external commands\n");
	fprintf (stderr, "\t-r\t reload zone via <rndc reload zone>\n");
        fprintf (stderr, "\t-v\t be (very) verbose\n");

	if ( mesg && *mesg )
		fprintf (stderr, "%s\n", mesg);
	exit (1);
}

static	int	parsedir (const char *dir, zone_t **zp, const zconf_t *conf)
{
	dki_t	*dkp;
	DIR	*dirp;
	struct  dirent  *dentp;
	char	path[MAX_PATHSIZE+1];

	dbg_val ("parsedir: (%s)\n", dir);
	if ( !is_directory (dir) )
		return 0;

	dbg_line ();
	zone_readdir (dir, zp, conf, searchlist);

	dbg_val ("parsedir: opendir(%s)\n", dir);
	if ( (dirp = opendir (dir)) == NULL )
		return 0;

	while ( (dentp = readdir (dirp)) != NULL )
	{
		if ( is_dotfile (dentp->d_name) )
			continue;

		pathname (path, sizeof (path), dir, dentp->d_name, NULL);
		if ( !is_directory (path) )
			continue;

		dbg_val ("parsedir: recursive %s\n", path);
		parsedir (path, zp, conf);
	}
	closedir (dirp);
	return 1;
}

static	int	dosigning (zone_t *zp)
{
	char	path[MAX_PATHSIZE+1];
	int	err;
	int	newkey;
	time_t	currtime;
	time_t	zfile_time;
	time_t	zfilesig_time;
	dki_t	*list;		/* start of keylist */

	if ( verbose )
		logmesg ("parsing zone \"%s\" in dir \"%s\"\n", zp->zone, zp->dir);

	err = 0;
	pathname (path, sizeof (path), zp->dir, zp->file, ".signed");
	dbg_val("parsezonedir fileexist (%s)\n", path);
	if ( !fileexist (path) )
	{
		error ("Not a secure zone directory (%s)!\n", path);
		return 1;
	}
	zfilesig_time = get_mtime (path);

	pathname (path, sizeof (path), zp->dir, zp->file, NULL);
	dbg_val("parsezonedir fileexist (%s)\n", path);
	if ( !fileexist (path) )
	{
		error ("No zone file found (%s)!\n", path);
		return 2;
	}
	zfile_time = get_mtime (path);
	
	currtime = time (NULL);

	/* ok, now read all keys for that zone */
	dbg_val("parsezonedir dki_readdir (%s)\n", zp->dir);

	/* check key signing keys, create new one if neccessary */
	newkey = kskstatus (&zp->keys, zp->dir, zp->zone, zp->conf);

	/* check age of zone keys, probably depreciate or remove old keys */
	newkey += zskstatus (&zp->keys, zp->dir, zp->zone, zp->conf);

	/**
	** Check if it is time to do a resign. This is the case if
	**	a) new keys are generated, or
	**	b) "zone.db" is newer than "zone.db.signed" or
	**	c) "zone.db.signed" is older than the resign interval
	**/
	if ( verbose )
	{
		if ( force )
			logmesg ("\tResigning necessary: Option -f\n"); 
		else if ( newkey )
			logmesg ("\tResigning necessary: Modified keys\n"); 
		else if ( zfile_time > zfilesig_time )
			logmesg ("\tResigning necessary: Zone file edited\n");
		else if ( (currtime - zfilesig_time) > zp->conf->resign - (5 * MINSEC) )
			logmesg ("\tResigning necessary: Resign interval (%d) reached\n",
									zp->conf->resign); 
		else
			logmesg ("\tResigning not necessary!\n", zp->conf->resign); 
	}
	if ( !(force || newkey || zfile_time > zfilesig_time ||	
	     (currtime - zfilesig_time) > zp->conf->resign - (5 * MINSEC)) )
		return 0;	/* nothing to do */

	/* let's start signing the zone */

	/* create new "dnskey.db" file */
	pathname (path, sizeof (path), zp->dir, zp->conf->keyfile, NULL);
	if ( verbose )
		logmesg ("\tWriting key file \"%s\"\n", path);
	if ( !writekeyfile (path, zp->keys) )
		error ("Can't create keyfile %s \n", path);

	/* increment serial no in zone file */
	pathname (path, sizeof (path), zp->dir, zp->conf->zonefile, NULL);
	if ( noexec == 0 && (err = incr_serial (path)) < 0 )
		error ("Warning: could not increment serialno of domain %s in file %s (errno=%d)!\n",
							zp->zone, path, err);
	if ( verbose )
		if ( noexec )
			logmesg ("\tIncrementing serial number in file \"%s\"\n", path);
		else
			logmesg ("\tIncrementing serial number (%u) in file \"%s\"\n", err, path);
	/* at last, sign the zone file */
	if ( err > 0 )
	{
		if ( verbose )
			logmesg ("\tSigning zone \"%s\"\n", zp->zone);
		if ( (err = sign_zone (zp->dir, zp->zone, zp->conf)) < 0 )
			error ("Signing of zone %s failed (%d)!\n", zp->zone, err);
	}
	if ( err >= 0 && reloadflag )
		reload_zone (zp->zone);

	return err;
}

static	int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*akey;

	assert ( listp != NULL );
	assert ( z != NULL );

	/* check if a key signing key exist ? */
	akey = (dki_t *)dki_find (*listp, 1, 'a', 1);
	if ( akey == NULL )
	{
		if ( verbose )
			logmesg ("\tNo active KSK found: generate new one\n");
		akey = genkey (listp, dir, domain, 1, z, 'a');
		return 1;
	}
	return 0;
}

static	int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*akey;
	dki_t	*nextkey;
	dki_t	*dkp, *last;
	int	keychange;
	time_t	lifetime;
	time_t	currtime;

	assert ( listp != NULL );
	/* dir can be NULL */
	assert ( domain != NULL );
	assert ( z != NULL );

	currtime = time (NULL);

	keychange = 0;
	/* is the depreciated key expired ? */
	lifetime = z->max_ttl * 2;	/* draft kolkman/gieben */
	last = NULL;
	dkp = *listp;
	while ( dkp )
		if ( dki_isksk (dkp) == 0 &&
		     dki_status (dkp) == 'd' && dki_age (dkp, currtime) > lifetime )
		{
			keychange = 1;
			if ( verbose )
				logmesg ("\tLifetime of depreciated key %d exceeded (%d sec)\n",
						 dkp->tag, dki_age (dkp, currtime));
			dkp = dki_remove (dkp);	/* remove it */
			if ( last )
				last->next = dkp;
			else
				*listp = dkp;
			if ( verbose )
				logmesg ("\t\t->remove it\n");
		}
		else
		{
			last = dkp;
			dkp = dkp->next;
		}

	/* check status of active key */
	lifetime = z->z_life;
	akey = (dki_t *)dki_find (*listp, 0, 'a', 1);
	if ( akey == NULL && lifetime > 0 )	/* no active key found */
	{
		if ( verbose )
			logmesg ("\tNo active key found: generate new one\n");
		akey = genkey (listp, dir, domain, 0, z, 'a');
	}
	/* lifetime of active key expired and pre-publish key exist ? */
	else if ( lifetime > 0 && dki_age (akey, currtime) > lifetime - (5 * MINSEC) )
	{
		if ( verbose )
			logmesg ("\tLifetime of active key %d exceeded (%d sec)\n",
						akey->tag, dki_age (akey, currtime) );

		/* depreciate the key only if there is another active or prepublish key */
		if ( (nextkey = (dki_t *)dki_find (*listp, 0, 'a', 2)) == NULL ||
		      nextkey == akey )
			nextkey = (dki_t *)dki_find (*listp, 0, 'p', 1);
		if ( nextkey && dki_age (nextkey, currtime) > z->max_ttl + z->proptime )
		{
			keychange = 1;
			if ( verbose )
				logmesg ("\t\t->depreciate it\n");
			dki_setstatus (akey, 'd');	/* depreciate the active key */
			akey = nextkey;
			if ( verbose )
				logmesg ("\t\t->activate pre-publish key %d\n", nextkey->tag);
			dki_setstatus (nextkey, 'a');	/* activate pre-published key */
			nextkey = NULL;
		}
	}

	/* should we add a new pre-publish key ? */
	nextkey = (dki_t *)dki_find (*listp, 0, 'p', 1);
	if ( nextkey == NULL && lifetime > 0 && (akey == NULL ||
	     dki_age (akey, currtime + z->resign) > lifetime - (5 * MINSEC)) )
	{
		keychange = 1;
		if ( verbose )
			logmesg ("\tNew pre-publish key needed\n");
		nextkey = genkey (listp, dir, domain, 0, z, 'p');
		if ( verbose )
			logmesg ("\t\t->creating new pre-publish key %d\n",
								nextkey->tag);
	}
	return keychange;
}

static	int	writekeyfile (const char *fname, const dki_t *list)
{
	FILE	*fp;
	const	dki_t	*dkp;
	time_t	curr = time (NULL);
	int	ksk;

	if ( (fp = fopen (fname, "w")) == NULL )
		return 0;
	fprintf (fp, ";\n");
	fprintf (fp, ";\t!!! Don\'t edit this file by hand.\n");
	fprintf (fp, ";\t!!! It will be generated by %s.\n", progname);
	fprintf (fp, ";\n");
	fprintf (fp, ";\t Last generation time %s\n", time2str (curr));
	fprintf (fp, ";\n");

	fprintf (fp, "\n");
	fprintf (fp, ";  ***  List of Key Signing Keys  ***\n");
	ksk = 1;
	for ( dkp = list; dkp; dkp = dkp->next )
	{
		if ( ksk && !dki_isksk (dkp) )
		{
			fprintf (fp, "; ***  List of Zone Signing Keys  ***\n");
			ksk = 0;
		}
		dki_prt_comment (dkp, fp);
		dki_prt_dnskey (dkp, fp);
		putc ('\n', fp);
	}
	
	fclose (fp);
	return 1;
}

static	int	sign_zone (const char *dir, const char *domain, const zconf_t *conf)
{
	char	cmdline[254+1];
	char	str[254+1];
	FILE	*fp;

	assert (conf != NULL);
	assert (domain != NULL);

	str[0] = '\0';
	if ( conf->lookaside && conf->lookaside[0] )
		snprintf (str, sizeof (str), "-l %.250s", conf->lookaside);

	if ( dir == NULL || *dir == '\0' )
		dir = ".";
	snprintf (cmdline, sizeof (cmdline), "cd %s; %s -o %s -e +%d -g %s  %s",
			dir, SIGNCMD, domain, conf->sigvalidity, str, conf->zonefile);

	if ( verbose >= 2 )
		logmesg ("\t  Run cmd \"%s\"\n", cmdline);
	*str = '\0';
	if ( noexec == 0 )
	{
		if ( (fp = popen (cmdline, "r")) == NULL || fgets (str, sizeof str, fp) == NULL )
			return -1;
		pclose (fp);
	}

	if ( verbose >= 2 )
	{
		int	len = strlen (str) - 1;
		if ( len >= 0 && str[len] == '\n' )
			str[len] = '\0';
		logmesg ("\t  Cmd dnssec-signzone returns: \"%s\"\n", str);
	}

	return 0;
}

static	int	reload_zone (const char *domain)
{
	char	cmdline[254+1];
	char	str[254+1];
	FILE	*fp;

	if ( verbose )
		logmesg ("\tReload zone \"%s\"\n", domain);
	snprintf (cmdline, sizeof (cmdline), "%s reload %s", RELOADCMD, domain);

	if ( verbose >= 2 )
		logmesg ("\t  Run cmd \"%s\"\n", cmdline);
	*str = '\0';
	if ( noexec == 0 )
	{
		if ( (fp = popen (cmdline, "r")) == NULL || fgets (str, sizeof str, fp) == NULL )
			return -1;
		pclose (fp);
	}

	if ( verbose >= 2 )
	{
		int	len = strlen (str) - 1;
		if ( len >= 0 && str[len] == '\n' )
			str[len] = '\0';
		logmesg ("\t  rndc reload returns: \"%s\"\n", str);
	}

	return 0;
}

static	dki_t	*genkey (dki_t **listp, const char *dir, const char *domain, int ksk, const zconf_t *conf, int status)
{
	dki_t	*dkp;

	if ( listp == NULL || domain == NULL )
		return NULL;

	if ( ksk )
		dkp = dki_new (dir, domain, 1, conf->k_algo, conf->k_bits);
	else
		dkp = dki_new (dir, domain, 0, conf->z_algo, conf->z_bits);
	dki_add (listp, dkp);
	dki_setstatus (dkp, status);

	return dkp;
}

