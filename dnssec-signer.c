/*****************************************************************
**
**	@(#) dnssec-signer.c  (c) Jan 2005  Holger Zuleger hznet.de
**
**	See LICENCE file for licence
**
*****************************************************************/

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <assert.h>
# include <dirent.h>
# include <unistd.h>	/* getopt() etc.. */
# include <errno.h>	/* getopt() etc.. */
# include "config.h"
# include "zconf.h"
# include "debug.h"
# include "misc.h"
# include "ncparse.h"
# include "zone.h"
# include "dki.h"
# include "zktr.h"

# define	OFFSET	((int) (2.5 * MINSEC))

#if defined(BIND_VERSION) && BIND_VERSION >= 940
# define	OPTSTR	"c:V:D:N:o:dfHhnrv"
#else
# define	OPTSTR	"c:V:D:N:o:fHhnrv"
#endif

/**	function declaration	**/
static	void	usage (char *mesg, zconf_t *conf);
static	int	add2zonelist (const char *dir, const char *view, const char *zone, const char *file);
static	int	parsedir (const char *dir, zone_t **zp, const zconf_t *conf);
static	int	dosigning (zone_t *zp);
static	int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
static	int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *conf);
static	int	check_keydb_timestamp (dki_t *keylist, time_t reftime);
static	int	new_keysetfiles (const char *dir, time_t zone_signing_time);
static	dki_t	*genkey (dki_t **listp, const char *dir, const char *domain, int ksk, const zconf_t *conf, int status);
static	int	writekeyfile (const char *fname, const dki_t *list, int key_ttl);
static	int	sign_zone (const char *dir, const char *domain, const char *file, const zconf_t *conf);
static	int	dyn_update_freeze (const char *domain, const char *view, int freeze);
static	int	reload_zone (const char *domain, const char *view);
static	int	register_key (dki_t *listp, const zconf_t *z);

/**	global command line options	**/
const	char	*progname;
const	char	*viewname = NULL;
const	char	*origin = NULL;
static	int	verbose = 0;
static	int	force = 0;
static	int	reloadflag = 0;
static	int	noexec = 0;
static	int	dynamic_zone = 0;	/* dynamic zone ? */
static	zone_t	*zonelist = NULL;	/* must be static global because add2zonelist use it */
static	zconf_t	*config;

main (int argc, char *const argv[])
{
	int	c;
	char	errstr[255+1];
	char	dir[255+1];
	char	*p;
	const	char	*defconfname;
	zone_t	*zp;

	progname = *argv;
	if ( (p = strrchr (progname, '/')) )
		progname = ++p;
	viewname = getnameappendix (progname, "dnssec-signer");

	defconfname = getdefconfname (viewname);
	config = loadconfig ("", (zconf_t *)NULL);	/* load built in config */
	if ( fileexist (defconfname) )			/* load default config file */
		config = loadconfig (defconfname, config);
	if ( config == NULL )
		fatal ("Out of memory\n");

	zonelist = NULL;
        opterr = 0;
	while ( (c = getopt (argc, (char * const *)argv, OPTSTR)) != -1 )
	{
		switch ( c )
		{
		case 'V':		/* view name */
			viewname = optarg;
			defconfname = getdefconfname (viewname);
			if ( fileexist (defconfname) )		/* load default config file */
				config = loadconfig (defconfname, config);
			if ( config == NULL )
				fatal ("Out of memory\n");
			break;
		case 'c':
			config = loadconfig (optarg, config);
			if ( config == NULL )
				fatal ("Out of memory\n");
			break;
		case 'N':
			memset (dir, '\0', sizeof (dir));
			if ( config->zonedir )
				strncpy (dir, config->zonedir, sizeof(dir));
			if ( !parse_namedconf (optarg, dir, sizeof (dir), add2zonelist) )
				fatal ("Can't read file %s as namedconf file\n", optarg);
			if ( zonelist == NULL )
				fatal ("No signed zone found in file %s\n", optarg);
			break;
		case 'D':
			if ( !parsedir (optarg, &zonelist, config) )
				fatal ("Can't read directory tree %s\n", optarg);
			if ( zonelist == NULL )
				fatal ("No signed zone found in directory tree %s\n", optarg);
			break;
		case 'o':
			origin = optarg;
			break;
		case 'f':
			force++;
			break;
		case 'H':
		case 'h':
			usage (NULL, config);
			break;
#if defined(BIND_VERSION) && BIND_VERSION >= 940
		case 'd':
			dynamic_zone = 1;
			/* dynamic zone requires a name server reload... */
			reloadflag = 0;		/* ...but "rndc thaw" reloads the zone anyway */
			break;
#endif
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

#if defined(DBG) && DBG
	for ( zp = zonelist; zp; zp = zp->next )
		zone_print ("in main: ", zp);
#endif

	if ( origin )
	{
		if ( (argc - optind) <= 0 )	/* no arguments left ? */
			zone_readdir (".", origin, NULL, &zonelist, config, dynamic_zone);
		else
			zone_readdir (".", origin, argv[optind], &zonelist, config, dynamic_zone);

		/* anyway, "delete" all (remaining) arguments */
		optind = argc;

		/* complain if nothing could read in */
		if ( zonelist == NULL )
			fatal ("Couldn't read zone \"%s\"\n", origin);
	}
	if ( zonelist == NULL )
		parsedir (config->zonedir, &zonelist, config);

	for ( zp = zonelist; zp; zp = zp->next )
		if ( in_strarr (zp->zone, &argv[optind], argc - optind) )
			dosigning (zp);

//	zone_freelist (&zonelist);

	return 0;
}

static	void	usage (char *mesg, zconf_t *conf)
{
	fprintf (stderr, "%s version %s\n", progname, ZKT_VERSION);
	fprintf (stderr, "\n");

	fprintf (stderr, "usage: %s [-c config] ", progname);
	fprintf (stderr, "-N named.conf ");
	fprintf (stderr, "[-fhnr] [-v [-v]] [zone ...]\n");

	fprintf (stderr, "usage: %s [-c config] ", progname);
	fprintf (stderr, "[-D directorytree] ");
	fprintf (stderr, "[-fhnr] [-v [-v]] [zone ...]\n");

	fprintf (stderr, "usage: %s [-c config] ", progname);
	fprintf (stderr, "-o origin ");
	fprintf (stderr, "[-fhnr] [-v [-v]] [zonefile.signed]\n");

	fprintf (stderr, "\t-c file\t read config from <file> instead of %s\n", CONFIG_FILE);
	fprintf (stderr, "\t-D dir\t parse the given directory tree for a list of secure zones \n");
	fprintf (stderr, "\t-N file\t get the list of secure zones out of the named like config file \n");
	fprintf (stderr, "\t-o zone\t specify the name of the zone \n");
	fprintf (stderr, "\t\t The file to sign should be given as an argument (\"%s.signed\")\n", conf->zonefile);
	fprintf (stderr, "\t-h\t print this help\n");
	fprintf (stderr, "\t-f\t force re-signing\n");
	fprintf (stderr, "\t-n\t no execution of external signing command\n");
	fprintf (stderr, "\t-r\t reload zone via <rndc reload zone>\n");
        fprintf (stderr, "\t-v\t be (very) verbose\n");

        fprintf (stderr, "\t[zone]\t sign only those zones given as argument\n");

        fprintf (stderr, "\n");
        fprintf (stderr, "\tif neither -D nor -N is given, the directory tree specified in the \n");
	fprintf (stderr, "\tdnssec config file (\"%s\") will be parsed\n", conf->zonedir);

	if ( mesg && *mesg )
		fprintf (stderr, "%s\n", mesg);
	exit (1);
}

/**	fill zonelist with infos coming out of named.conf	**/
static	int	add2zonelist (const char *dir, const char *view, const char *zone, const char *file)
{
#ifdef DBG
	fprintf (stderr, "printzone ");
	fprintf (stderr, "view \"%s\" " , view);
	fprintf (stderr, "zone \"%s\" " , zone);
	fprintf (stderr, "file ");
	if ( dir && *dir )
		fprintf (stderr, "%s/", dir);
	fprintf (stderr, "%s", file);
	fprintf (stderr, "\n");
#endif
	dbg_line ();
	if ( view[0] != '\0' )	/* view found in named.conf */
	{
		if ( viewname == NULL || viewname[0] == '\0' )	/* viewname wasn't set on startup ? */
		{
			dbg_line ();
			error ("zone \"%s\" in view \"%s\" found in name server config, but no matching view was set on startup\n", zone, view);
			return 0;
		}
		dbg_line ();
		if ( strcmp (viewname, view) != 0 )	/* zone is _not_ in current view */
			return 0;
	}
	return zone_readdir (dir, zone, file, &zonelist, config, dynamic_zone);
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
	zone_readdir (dir, NULL, NULL, zp, conf, dynamic_zone);

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
	int	newkeysetfile;
	int	use_unixtime;
	time_t	currtime;
	time_t	zfile_time;
	time_t	zfilesig_time;
	dki_t	*list;		/* start of keylist */

	if ( verbose )
		logmesg ("parsing zone \"%s\" in dir \"%s\"\n", zp->zone, zp->dir);

	pathname (path, sizeof (path), zp->dir, zp->sfile, NULL);
	dbg_val("parsezonedir fileexist (%s)\n", path);
	if ( !fileexist (path) )
	{
		error ("Not a secure zone directory (%s)!\n", zp->dir);
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

	/* check key signing keys, create new one if neccessary */
	dbg_msg("parsezonedir check ksk ");
	newkey = kskstatus (&zp->keys, zp->dir, zp->zone, zp->conf);

	/* check age of zone keys, probably depreciate or remove old keys */
	dbg_msg("parsezonedir check zsk ");
	newkey += zskstatus (&zp->keys, zp->dir, zp->zone, zp->conf);

	/* create pathname of "dnskey.db" file */
	pathname (path, sizeof (path), zp->dir, zp->conf->keyfile, NULL);
	dbg_val("parsezonedir check_keydb_timestamp (%s)\n", path);
	if ( !newkey )
		newkey = check_keydb_timestamp (zp->keys, get_mtime (path));

	/* if we work in subdir mode, check if there is a new keyset- file */
	newkeysetfile = 0;
	if ( !newkey && zp->conf->keysetdir && strcmp (zp->conf->keysetdir, "..") == 0 )
		newkeysetfile = new_keysetfiles (zp->dir, zfilesig_time);

	/**
	** Check if it is time to do a re-sign. This is the case if
	**	a) the command line flag -f is set, or
	**	b) new keys are generated, or
	**	c) we found a new KSK of a delegated domain, or
	**	d) the "dnskey.db" file is newer than "zone.db" 
	**	e) the "zone.db" is newer than "zone.db.signed" or
	**	f) "zone.db.signed" is older than the re-sign interval
	**/
	if ( verbose )
	{
		if ( force )
			logmesg ("\tRe-signing necessary: Option -f\n"); 
		else if ( newkey )
			logmesg ("\tRe-signing necessary: New zone keys\n"); 
		else if ( newkeysetfile )
			logmesg ("\tRe-signing necessary: Modified KSK in delegated domain\n"); 
		else if ( get_mtime (path) > zfilesig_time )
			logmesg ("\tRe-signing necessary: Modified keys\n");
		else if ( zfile_time > zfilesig_time )
			logmesg ("\tRe-signing necessary: Zone file edited\n");
		else if ( (currtime - zfilesig_time) > zp->conf->resign - (OFFSET) )
			logmesg ("\tRe-signing necessary: Re-sign interval (%d) reached\n",
									zp->conf->resign); 
		else if ( dynamic_zone )
			logmesg ("\tRe-signing necessary: dynamic zone\n");
		else
			logmesg ("\tRe-signing not necessary!\n"); 
		logflush ();
	}
	dbg_line ();
	if ( !(force || newkey || newkeysetfile || zfile_time > zfilesig_time ||	
	     get_mtime (path) > zfilesig_time ||
	     (currtime - zfilesig_time) > zp->conf->resign - (OFFSET) || dynamic_zone) )
		return 0;	/* nothing to do */

	/* let's start signing the zone */
	dbg_line ();

	/* create new "dnskey.db" file  */
	pathname (path, sizeof (path), zp->dir, zp->conf->keyfile, NULL);
	if ( verbose )
		logmesg ("\tWriting key file \"%s\"\n", path);
	if ( !writekeyfile (path, zp->keys, zp->conf->key_ttl) )
		error ("Can't create keyfile %s \n", path);

	err = 1;
	use_unixtime = ( zp->conf->serialform == Unixtime );
	dbg_val1 ("Use unixtime = %d\n", use_unixtime);
#if defined(BIND_VERSION) && BIND_VERSION >= 940
	if ( !dynamic_zone && !use_unixtime ) /* increment serial no in static zone files */
#else
	if ( !dynamic_zone ) /* increment serial no in static zone files */
#endif
	{
		pathname (path, sizeof (path), zp->dir, zp->file, NULL);
		err = 0;
		if ( noexec == 0 )
		{
			if ( (err = incr_serial (path, use_unixtime)) < 0 )
				error ("Warning: could not increment serialno of domain %s in file %s (errno=%d)!\n",
								zp->zone, path, err);
			else if ( verbose )
				logmesg ("\tIncrementing serial number in file \"%s\"\n", path);
		}
		else if ( verbose )
				logmesg ("\tIncrementing serial number in file \"%s\"\n", path);
	}

	/* at last, sign the zone file */
	if ( err > 0 )
	{
		time_t	timer;

		if ( verbose )
		{
			logmesg ("\tSigning zone \"%s\"\n", zp->zone);
			logflush ();
		}

		/* dynamic zones uses incremental signing, so we have to */
		/* prepare the old (signed) file as new input file */
		if ( dynamic_zone )
		{
			char	zfile[MAX_PATHSIZE+1];

			dyn_update_freeze (zp->zone, viewname, 1);	/* freeze dynmaic zone ! */

			pathname (zfile, sizeof (zfile), zp->dir, zp->file, NULL);
			pathname (path, sizeof (path), zp->dir, zp->sfile, NULL);
			if ( verbose )
				logmesg ("\tDynamic Zone signing: copy old signed zone file %s to new input file %s\n",
										path, zfile); 
			if ( newkey )	/* if we have new keys, they should be added to the zone file */
				copyzonefile (path, zfile);
			else		/* else we can do a simple file copy */
				copyfile (path, zfile);
		}

		timer = start_timer ();
		if ( (err = sign_zone (zp->dir, zp->zone, zp->file, zp->conf)) < 0 )
			error ("Signing of zone %s failed (%d)!\n", zp->zone, err);
		timer = stop_timer (timer);

		if ( dynamic_zone )
			dyn_update_freeze (zp->zone, viewname, 0);	/* thaw dynamic zone file */

		if ( verbose )
		{
			char	*tstr = str_delspace (age2str (timer));

			if ( !tstr || *tstr == '\0' )
				tstr = "0s";
			logmesg ("\tSigning completed after %s.\n", tstr);
		}

	}
	if ( err >= 0 && reloadflag )
	{
		reload_zone (zp->zone, viewname);
		register_key (zp->keys, zp->conf);
	}

	if ( verbose )
	{
		logmesg ("\n");
		logflush ();
	}

	return err;
}

static	int	register_key (dki_t *list, const zconf_t *z)
{
	dki_t	*dkp;
	time_t	currtime;
	time_t	age;
	static	int	sd = 0;

	assert ( list != NULL );
	assert ( z != NULL );

	currtime = time (NULL);
	for ( dkp = list; dkp && dki_isksk (dkp); dkp = dkp->next )
	{
		age = dki_age (dkp, currtime);

#if defined(REG_URL) 
		/* announce "new" and active key signing keys */
		if ( REG_URL && *REG_URL && dki_status (dkp) == DKI_ACT && age <= z->resign * 4 )
		{
			if ( sd == 0 )
			{
				char	url[1024];
				char	*proto;
				char	*host;
				char	*port = PORT_STR;

				snprintf (url, sizeof(url), "%s", REG_URL);
				parseurl (url, &proto, &host, &port, NULL);
				sd = zktr_socket (host, port, 0);
			}
			if ( verbose )
				logmesg ("\tRegister new KSK with tag %d for domain %s\n",
								dkp->tag, dkp->name);
			send_zktr_v01 (sd, dkp->name, dkp->tag, dkp->algo, dkp->time);
		}
#endif
	}
}

static	int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*akey;
	time_t	currtime;
	time_t	age;

	assert ( listp != NULL );
	assert ( z != NULL );

	/* check if a key signing key exist ? */
	akey = (dki_t *)dki_find (*listp, 1, 'a', 1);
	if ( akey == NULL )
	{
		if ( verbose )
			logmesg ("\tNo active KSK found: generate new one\n");
		akey = genkey (listp, dir, domain, 1, z, 'a');
		if ( !akey )
			error ("\tcould not generate new KSK\n");
		return 1;
	}
	/* check ksk lifetime */
	currtime = time (NULL);
	age = dki_age (akey, currtime);
	if ( z->k_life > 0 && age > z->k_life )
		logmesg ("Warning: Lifetime of Key Signing Key %d exceeded: %s\n",
							akey->tag, age2str (age));

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

	dbg_val("zskstatus for %s \n", domain);
	keychange = 0;
	/* Is the depreciated key expired ? */
	/* As mentioned by olaf, this is the max_ttl of all the rr in the zone */
	lifetime = z->max_ttl + z->proptime;	/* draft kolkman/gieben */
	last = NULL;
	dkp = *listp;
	while ( dkp )
		if ( dki_isksk (dkp) == 0 &&
		     dki_status (dkp) == 'd' && dki_age (dkp, currtime) > lifetime )
		{
			keychange = 1;
			if ( verbose )
				logmesg ("\tLifetime(%d sec) of depreciated key %d exceeded (%d sec)\n",
					 lifetime, dkp->tag, dki_age (dkp, currtime));
			dkp = dki_destroy (dkp);	/* delete the keyfiles */
			dbg_msg("zskstatus depreciated key removed ");
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
	dbg_msg("zskstatus check status of active key ");
	akey = (dki_t *)dki_find (*listp, 0, 'a', 1);
	if ( akey == NULL && lifetime > 0 )	/* no active key found */
	{
		if ( verbose )
			logmesg ("\tNo active ZSK found: generate new one\n");
		akey = genkey (listp, dir, domain, 0, z, 'a');
	}
	/* lifetime of active key expired and pre-publish key exist ? */
	else if ( lifetime > 0 && dki_age (akey, currtime) > lifetime - (OFFSET) )
	{
		if ( verbose )
			logmesg ("\tLifetime(%d +/-%d sec) of active key %d exceeded (%d sec)\n",
				lifetime, (OFFSET) , akey->tag, dki_age (akey, currtime) );

		/* depreciate the key only if there is another active or prepublish key */
		if ( (nextkey = (dki_t *)dki_find (*listp, 0, 'a', 2)) == NULL ||
		      nextkey == akey )
			nextkey = (dki_t *)dki_find (*listp, 0, 'p', 1);

		/* Is the pre-publish key sufficient long in the zone ? */
		/* As mentioned by Olaf, this should be the ttl of the DNSKEY RR ! */
		if ( nextkey && dki_age (nextkey, currtime) > z->key_ttl + z->proptime )
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
		else
			if ( verbose )
				logmesg ("\t\t->waiting for pre-publish key\n");
	}

	/* Should we add a new pre-publish key?  This is neccessary if the active
	 * key will be expired at the next re-signing interval (The pre-publish
	 * time will be checked just before the active key will be removed.
	 * See above).
	 */
	nextkey = (dki_t *)dki_find (*listp, 0, 'p', 1);
	if ( nextkey == NULL && lifetime > 0 && (akey == NULL ||
	     dki_age (akey, currtime + z->resign) > lifetime - (OFFSET)) )
	{
		keychange = 1;
		if ( verbose )
			logmesg ("\tNew pre-publish key needed\n");
		nextkey = genkey (listp, dir, domain, 0, z, 'p');
		if ( verbose )
			if ( nextkey )
				logmesg ("\t\t->creating new pre-publish key %d\n", nextkey->tag);
			else
				error ("\tcould not generate new ZSK: \"%s\"\n", dki_geterrstr());
	}
	return keychange;
}

/*
 *	This function is not working with symbolic links to keyset- files,
 *	because get_mtime() returns the mtime of the underlying file, and *not*
 *	that of the symlink file.
 *	This is bad, because the keyset-file will be newly generated by dnssec-signzone
 *	on every re-signing call.
 *	Instead, in the case of a hierarchical directory structure, we copy the file
 *	(and so we change the timestamp) only if it was changed after the last
 *	generation (checked with cmpfile(), see func sign_zone()).
 */
# define	KEYSET_FILE_PFX	"keyset-"
static	int	new_keysetfiles (const char *dir, time_t zone_signing_time)
{
	DIR	*dirp;
	struct  dirent  *dentp;
	char	path[MAX_PATHSIZE+1];
	int	newkeysetfile;

	if ( (dirp = opendir (dir)) == NULL )
		return 0;

	newkeysetfile = 0;
	dbg_val2 ("new_keysetfile (%s, %s)\n", dir, time2str (zone_signing_time)); 
	while ( !newkeysetfile && (dentp = readdir (dirp)) != NULL )
	{
		if ( strncmp (dentp->d_name, KEYSET_FILE_PFX, strlen (KEYSET_FILE_PFX)) != 0 )
			continue;

		pathname (path, sizeof (path), dir, dentp->d_name, NULL);
		dbg_val2 ("newkeysetfile timestamp of %s = %s\n", path, time2str (get_mtime(path))); 
		if ( get_mtime (path) > zone_signing_time )
			newkeysetfile = 1;
	}
	closedir (dirp);

	return newkeysetfile;
}

static	int	check_keydb_timestamp (dki_t *keylist, time_t reftime)
{
	dki_t	*key;

	assert ( keylist != NULL );
	if ( reftime == 0 )
		return 1;

	for ( key = keylist; key; key = key->next )
		if ( dki_time (key) > reftime )
			return 1;

	return 0;
}

static	int	writekeyfile (const char *fname, const dki_t *list, int key_ttl)
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
		dki_prt_dnskeyttl (dkp, fp, key_ttl);
		putc ('\n', fp);
	}
	
	fclose (fp);
	return 1;
}

static	int	sign_zone (const char *dir, const char *domain, const char *file, const zconf_t *conf)
{
	char	cmd[1023+1];
	char	str[1023+1];
	char	rparam[254+1];
	char	keysetdir[254+1];
	char	*pseudo;
	int	len;
	FILE	*fp;

	assert (conf != NULL);
	assert (domain != NULL);

	len = 0;
	str[0] = '\0';
	if ( conf->lookaside && conf->lookaside[0] )
		len = snprintf (str, sizeof (str), "-l %.250s", conf->lookaside);

	dbg_line();
#if defined(BIND_VERSION) && BIND_VERSION >= 940
	if ( !dynamic_zone && conf->serialform == Unixtime )
		snprintf (str+len, sizeof (str) - len, " -N unixtime");
#endif

	pseudo = "";
	if ( conf->sig_pseudo )
		pseudo = "-p ";

	dbg_line();
	rparam[0] = '\0';
	if ( conf->sig_random && conf->sig_random[0] )
		snprintf (rparam, sizeof (rparam), "-r %.250s ", conf->sig_random);

	dbg_line();
	keysetdir[0] = '\0';
	if ( conf->keysetdir && conf->keysetdir[0] && strcmp (conf->keysetdir, "..") != 0 )
		snprintf (keysetdir, sizeof (keysetdir), "-d %.250s ", conf->keysetdir);

	if ( dir == NULL || *dir == '\0' )
		dir = ".";

	dbg_line();
#if defined(BIND_VERSION) && BIND_VERSION >= 940
	if ( dynamic_zone )
		snprintf (cmd, sizeof (cmd), "cd %s; %s -N increment %s%s%s-o %s -e +%d -g %s -f %s.dsigned %s K*.private",
			dir, SIGNCMD, pseudo, rparam, keysetdir, domain, conf->sigvalidity, str, file, file);
	else
#endif
		snprintf (cmd, sizeof (cmd), "cd %s; %s %s%s%s-o %s -e +%d -g %s %s K*.private",
			dir, SIGNCMD, pseudo, rparam, keysetdir, domain, conf->sigvalidity, str, file);
	if ( verbose >= 2 )
		logmesg ("\t  Run cmd \"%s\"\n", cmd);
	*str = '\0';
	if ( noexec == 0 )
	{
		if ( (fp = popen (cmd, "r")) == NULL || fgets (str, sizeof str, fp) == NULL )
			return -1;
		pclose (fp);
	}

	dbg_line();
	if ( verbose >= 2 )
		logmesg ("\t  Cmd dnssec-signzone return: \"%s\"\n", strchop (str, '\n'));

	/* propagate "keyset"-file to parent dir */
	if ( conf->keysetdir && strcmp (conf->keysetdir, "..") == 0 )
	{
		char	fromfile[1024];
		char	tofile[1024];
		int	ret;

		/* check if special parent-file exist (ksk rollover) */
		snprintf (fromfile, sizeof (fromfile), "%s/parent-%s", dir, domain);
		if ( !fileexist (fromfile) )	/* use "normal" keyset-file */
			snprintf (fromfile, sizeof (fromfile), "%s/keyset-%s", dir, domain);

		if ( verbose >= 2 )
			logmesg ("\t  check \"%s\" against parent dir\n", fromfile);
		snprintf (tofile, sizeof (tofile), "%s/../keyset-%s", dir, domain);
		if ( cmpfile (fromfile, tofile) != 0 )
		{
			if ( verbose >= 2 )
				logmesg ("\t  copy \"%s\" to parent dir\n", fromfile);
			if ( (ret = copyfile (fromfile, tofile)) != 0 )
				error ("Couldn't copy \"%s\" to parent dir (%d:%s)\n",
					fromfile, ret, strerror(errno));
		}
	}

	return 0;
}

static	int	dyn_update_freeze (const char *domain, const char *view, int freeze)
{
	char	cmdline[254+1];
	char	str[254+1];
	char	*action;
	FILE	*fp;

	if ( freeze )
		action = "freeze";
	else
		action = "thaw";

	if ( verbose )
		if ( view )
			logmesg ("\t%s dynamic zone \"%s\" in view \"%s\"\n", action, domain, view);
		else
			logmesg ("\t%s dynamic zone \"%s\"\n", action, domain);
	if ( view )
		snprintf (cmdline, sizeof (cmdline), "%s %s %s IN %s", RELOADCMD, action, domain, view);
	else
		snprintf (cmdline, sizeof (cmdline), "%s %s %s", RELOADCMD, action, domain);

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
		logmesg ("\t  rndc %s return: \"%s\"\n", action, strchop (str, '\n'));

	return 0;
}

static	int	reload_zone (const char *domain, const char *view)
{
	char	cmdline[254+1];
	char	str[254+1];
	FILE	*fp;

	if ( verbose )
		if ( view )
			logmesg ("\tReload zone \"%s\" in view \"%s\"\n", domain, view);
		else
			logmesg ("\tReload zone \"%s\"\n", domain);

	if ( view )
		snprintf (cmdline, sizeof (cmdline), "%s reload %s IN %s", RELOADCMD, domain, view);
	else
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
		logmesg ("\t  rndc reload return: \"%s\"\n", strchop (str, '\n'));

	return 0;
}

static	dki_t	*genkey (dki_t **listp, const char *dir, const char *domain, int ksk, const zconf_t *conf, int status)
{
	dki_t	*dkp;

	if ( listp == NULL || domain == NULL )
		return NULL;

	if ( ksk )
		dkp = dki_new (dir, domain, 1, conf->k_algo, conf->k_bits, conf->k_random);
	else
		dkp = dki_new (dir, domain, 0, conf->z_algo, conf->z_bits, conf->z_random);
	dki_add (listp, dkp);
	dki_setstatus (dkp, status);

	return dkp;
}

