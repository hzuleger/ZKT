/*****************************************************************
**
**	@(#) dnssec-zkt.c (c) Jan 2005  Holger Zuleger  hznet.de
**	Secure DNS zone key tool
**
**	See LICENCE file for licence
**
*****************************************************************/

# include <stdio.h>
# include <dirent.h>
# include <assert.h>
# include <unistd.h>
# include "config.h"
# include "debug.h"
# include "misc.h"
# include "zconf.h"
# include "dki.h"

extern  int     optopt;
const	char	*progname;

static	int	pathflag = 0;
static	int	headerflag = 1;
static	int	kskflag = 1;
static	int	zskflag = 1;
static	int	dirflag = 0;
static	int	recflag = RECURSIVE;
static	int	ageflag = 0;
static	int	timeflag = 1;
static	int	trustedkeyflag = 0;

static	void	list_keys (const dki_t *listp);
static	void	list_dnskeys (const dki_t *listp);
static	void	list_trustedkeys (const dki_t *listp);
static	void	printkeyinfo (const dki_t *dkp, const char *oldpath);
static	int	parsedirectory (const char *dir, dki_t **listp);
static	void	parsefile (const char *file, dki_t **listp);
static	void	createkey (const char *keyname, const dki_t *list, const zconf_t *conf);
static	void    usage (char *mesg, zconf_t *cp);
static	const char *parsetag (const char *str, int *tagp);

main (int argc, char *argv[])
{
	dki_t	*list = NULL;
	dki_t	*dkp;
	int	c;
	int	action;
	int	len;
	const	char	*file;
	char	*p;
	char	str[254+1];
	const char	*keyname;
	int		searchtag;
	zconf_t	*config;

	progname = *argv;
	if ( (p = strrchr (progname, '/')) )
		progname = ++p;

	config = loadconfig ("", (zconf_t *)NULL);	/* load built in config */
	if ( fileexist (CONFIGFILE) )			/* load default config file */
		config = loadconfig (CONFIGFILE, config);
	if ( config == NULL )
		fatal ("Out of memory\n");
	recflag = config->recursive;
	ageflag = config->printage;
	timeflag = config->printtime;

        opterr = 0;
	while ( (c = getopt (argc, argv, "A:C:D:P:R:HKTS:ZVac:dhkprtz")) != -1 )
	{
		switch ( c )
		{
		case 'T':
			trustedkeyflag = 1;
			zskflag = pathflag = 0;
			/* fall through */
		case 'H':
		case 'K':
		case 'V':
		case 'Z':
			action = c;
			break;
		case 'C':
		case 'P':
		case 'A':
		case 'D':
		case 'R':
		case 'S':
			keyname = parsetag (optarg, &searchtag);
			len = strlen (keyname);
			if ( len > 0 && keyname[len-1] != '.' )
			{
				snprintf (str, sizeof(str), "%s.", keyname);
				keyname = str;
			}
			action = c;
			break;
		case 'a':		/* age */
			ageflag = !ageflag;
			break;
		case 'c':
			config = loadconfig (optarg, config);
			recflag = config->recursive;
			ageflag = config->printage;
			timeflag = config->printtime;
			break;
		case 'd':		/* ignore directory arg */
			dirflag = 1;
			break;
		case 'h':		/* print no headline */
			headerflag = 0;
			break;
		case 'k':		/* ksk only */
			zskflag = 0;
			break;
		case 'p':		/* print path */
			pathflag = 1;
			break;
		case 'r':		/* switch recursive flag */
			recflag = !recflag;
			break;
		case 't':		/* time */
			timeflag = !timeflag;
			break;
		case 'z':		/* zsk only */
			kskflag = 0;
			break;
		case '?':
			if ( isprint (optopt) )
				snprintf (str, sizeof(str), "Unknown option \"-%c\".\n",
										optopt);
			else
				snprintf (str, sizeof (str), "Unknown option char \\x%x.\n",
										optopt);
			usage (str, config);
			break;
		default:
			abort();
		}
	}

	if ( kskflag == 0 && zskflag == 0 )
		kskflag = zskflag = 1;

	c = optind;
	do {
		if ( c >= argc )		/* no args left */
			file = config->zonedir;	/* use default directory */
		else
			file = argv[c++];

		if ( is_directory (file) )
			parsedirectory (file, &list);
		else
			parsefile (file, &list);

	}  while ( c < argc );	/* for all arguments */

	switch ( action )
	{
	case 'H':
	case 'V':
		usage ("", config);
	case 'C':
		createkey (keyname, list, config);
		break;
	case 'P':
	case 'A':
	case 'D':
		if ( (dkp = (dki_t*)dki_search (list, searchtag, keyname)) == NULL )
			fatal ("Key with tag %u not found\n", searchtag);
		dki_setstatus (dkp, action);
		break;
	case 'R':
		if ( (dkp = (dki_t *)dki_search (list, searchtag, keyname)) == NULL )
			fatal ("Key (id=%u) not found\n", searchtag);
		dki_remove (dkp);
		break;
	case 'S':
		if ( (dkp = (dki_t *)dki_search (list, searchtag, keyname)) == NULL )
			fatal ("Key (id=%u) not found\n", searchtag);
		dki_prt_dnskey (dkp, stdout);
		break;
	case 'Z':
		printconfig ("stdout", config);
		break;
	case 'K':
		list_dnskeys (list);
		break;
	case 'T':
		list_trustedkeys (list);
		break;
	default:
		list_keys (list);
	}

	return 0;
}

static	void    usage (char *mesg, zconf_t *cp)
{
        fprintf (stderr, "Secure DNS Zone Key Tool %s\n", ZKT_VERSION);
        fprintf (stderr, "\n");
        fprintf (stderr, "Show zone config parameter as %s file\n", LOCALCONFFILE);
        fprintf (stderr, "\tusage: %s -Z\n", progname);
        fprintf (stderr, "\n");
        fprintf (stderr, "List keys in current or given directory (-r for recursive mode)\n");
        fprintf (stderr, "\tusage: %s [-dhatkzpr] [-c config] [file|dir ...]\n", progname);
        fprintf (stderr, "\n");
        fprintf (stderr, "List public part of keys in DNSKEY RR format\n");
        fprintf (stderr, "\tusage: %s -K [-dhkzr] [-c config] [file|dir ...]\n", progname);
        fprintf (stderr, "\n");
        fprintf (stderr, "List keys (output is suitable for trusted-keys section)\n");
        fprintf (stderr, "\tusage: %s -T [-dhzr] [-c config] [file|dir ...]\n", progname);
        fprintf (stderr, "\n");
        fprintf (stderr, "Create new key \n");
        fprintf (stderr, "\tusage: %s -C <name> [-k] [-dpr] [-c config] [dir ...]\n", progname);
        fprintf (stderr, "\t\tKSK (use -k):  %s %d bits\n", dki_algo2str (cp->k_algo), cp->k_bits);
        fprintf (stderr, "\t\tZSK (default): %s %d bits\n", dki_algo2str (cp->z_algo), cp->z_bits);
        fprintf (stderr, "\n");
        fprintf (stderr, "Change key status of specified key to pre-publish, active or depreciated\n");
        fprintf (stderr, "\t(<keyspec> := tag | tag:name) \n");
        fprintf (stderr, "\tusage: %s -P|-A|-D <keyspec> [-dr] [-c config] [dir ...]\n", progname);
        fprintf (stderr, "\n");
        fprintf (stderr, "Remove specified key (<keyspec> := tag | tag:name) \n");
        fprintf (stderr, "\tusage: %s -R <keyspec> [-dr] [-c config] [dir ...]\n", progname);

        fprintf (stderr, "\n");
        fprintf (stderr, "General options \n");
        fprintf (stderr, "\t-c file\t read config from <file> instead of %s\n", CONFIGFILE);
        fprintf (stderr, "\t-d\t skip directory arguments\n");
        fprintf (stderr, "\t-h\t no headline or trusted-key section header/trailer in -T mode\n");
        fprintf (stderr, "\t-p\t show path of keyfile / create key in (already existing) directory\n");
        fprintf (stderr, "\t-r\t recursive mode on/off\n");
        fprintf (stderr, "\t-a\t print age of key (default: %s)\n", ageflag ? "on": "off");
        fprintf (stderr, "\t-t\t print key generation time (default: %s)\n",
								timeflag ? "on": "off");
        fprintf (stderr, "\t-k\t key signing keys only\n");
        fprintf (stderr, "\t-z\t zone signing keys only\n");
        if ( mesg && *mesg )
                fprintf (stderr, "%s\n", mesg);
        exit (1);
}

static	void	list_keys (const dki_t *listp)
{
	const	dki_t	*dkp;
	const	char	*oldpath;

	if ( listp ) 	/* print headline if list is not empty */
		printkeyinfo (NULL, "");

	oldpath = "";
	for ( dkp = listp; dkp; dkp = dkp->next )	/* loop through list */
	{
		printkeyinfo (dkp, oldpath);		/* print entry */
		oldpath = dkp->dname;
	}
}

static	void	list_trustedkeys (const dki_t *listp)
{
	const	dki_t	*dkp;

	/* print headline if list is not empty */
	if ( listp && headerflag )
		printf ("trusted-keys {\n");

	for ( dkp = listp; dkp; dkp = dkp->next )	/* loop through list */
		if ( dki_isksk (dkp) || zskflag )
			dki_prt_trustedkey (dkp, stdout);

	/* print end of trusted-key section */
	if ( listp && headerflag )
		printf ("};\n");
}

static	void	list_dnskeys (const dki_t *listp)
{
	const	dki_t	*dkp;
	int	ksk;

	for ( dkp = listp; dkp; dkp = dkp->next )
	{
		ksk = dki_isksk (dkp);
		if ( ksk && !kskflag || !ksk && !zskflag )
			continue;

		if ( headerflag )
			dki_prt_comment (dkp, stdout);
		dki_prt_dnskey (dkp, stdout);
	}
}

static	void	createkey (const char *keyname, const dki_t *list, const zconf_t *conf)
{
	const char *dir = "";
	dki_t	*dkp;

	if ( keyname == NULL || *keyname == '\0' )
		fatal ("Create key: no keyname!");

	/* search for already existent key to get the directory name */
	if ( pathflag && (dkp = (dki_t *)dki_search (list, 0, keyname)) != NULL )
	{
		char    path[MAX_PATHSIZE+1];
		zconf_t localconf;

		dir = dkp->dname;
		pathname (path, sizeof (path), dir, LOCALCONFFILE, NULL);
		if ( fileexist (path) )                 /* load local config file */
		{
			dbg_val ("Load local config file \"%s\"\n", path);
			memcpy (&localconf, conf, sizeof (zconf_t));
			conf = loadconfig (path, &localconf);
		}
	}
	
	if  ( zskflag )
		dkp = dki_new (dir, keyname, 0, conf->z_algo, conf->z_bits);
	else
		dkp = dki_new (dir, keyname, 1, conf->k_algo, conf->k_bits);
	if ( dkp == NULL )
		fatal ("Can't create key %s: %s!\n", keyname, dki_geterrstr ());
	if  ( zskflag )
		dki_setstatus (dkp, 'p');
}

static	void	printkeyinfo (const dki_t *dkp, const char *oldpath)
{
	time_t	currtime;

	if ( dkp == NULL )	/* print headline */
	{
		if ( headerflag )
		{
			printf ("%-33.33s %5s %3s %3.3s %-7s ", "Keyname",
				"Tag", "Typ", "Status", "Algorit");
			if ( timeflag )
				printf ("%-20s ", "Generation Time");
			if ( ageflag  )
				printf ("%16s ", "  Age");
			putchar ('\n');
		}
		return;
	}
	time (&currtime);

	/* TODO: use if dname is dynamically allocated */
	/* if ( pathflag && dkp->dname && strcmp (oldpath, dkp->dname) != 0 ) */
	if ( pathflag && strcmp (oldpath, dkp->dname) != 0 )
		printf ("%s/\n", dkp->dname);

	if ( kskflag && dki_isksk (dkp) || zskflag && !dki_isksk (dkp) )
	{
		printf ("%-33.33s ", dkp->name);
		printf ("%05d ", dkp->tag);
		printf ("%3s ", dki_isksk (dkp) ? "KSK" : "ZSK");
		printf ("%-3.3s ", dki_statusstr (dkp) );
		printf ("%-7s ", dki_algo2str(dkp->algo));
		if ( timeflag )
			printf ("%-20s ", time2str (dkp->time)); 
		if ( ageflag )
			printf ("%16s ", age2str (dki_age (dkp, currtime))); 
		putchar ('\n');
	}
}

static	int	parsedirectory (const char *dir, dki_t **listp)
{
	dki_t	*dkp;
	DIR	*dirp;
	struct  dirent  *dentp;
	char	path[MAX_PATHSIZE+1];

	if ( dirflag )
		return 0;

	dbg_val ("directory: opendir(%s)\n", dir);
	if ( (dirp = opendir (dir)) == NULL )
		return 0;

	while ( (dentp = readdir (dirp)) != NULL )
	{
		if ( is_dotfile (dentp->d_name) )
			continue;

		dbg_val ("directory: check %s\n", dentp->d_name);
		pathname (path, sizeof (path), dir, dentp->d_name, NULL);
		if ( is_directory (path) && recflag )
		{
			dbg_val ("directory: recursive %s\n", path);
			parsedirectory (path, listp);
		}
		else if ( is_keyfilename (dentp->d_name) )
			if ( (dkp = dki_read (dir, dentp->d_name)) )
				dki_add (listp, dkp);
	}
	closedir (dirp);
	return 1;
}

static	void	parsefile (const char *file, dki_t **listp)
{
	char	path[MAX_PATHSIZE+1];
	dki_t	*dkp;

	/* file arg contains path ? ... */
	file = splitpath (path, sizeof (path), file);	/* ... then split of */

	if ( is_keyfilename (file) )	/* plain file name looks like DNS key file ? */
	{
		if ( (dkp = dki_read (path, file)) )	/* read DNS key file ... */
			dki_add (listp, dkp);		/* ... and add to list */
		else
			error ("error parsing %s: (%s)\n", file, dki_geterrstr());
	}
}

static	const char *parsetag (const char *str, int *tagp)
{
	const	char	*p = str;

	*tagp = 0;
	while ( isspace (*p) )
		p++;
	if ( isdigit (*p) )
	{
		sscanf (p, "%u", tagp);
		do
			p++;
		while ( isdigit (*p) );
	}
	if ( *p == ':' )
		p++;
	return p;
}
