/*****************************************************************
**
**	@(#) dnssec-zkt.c (c) Jan 2005  Holger Zuleger  hznet.de
**	Secure DNS zone key tool
**
**	See LICENCE file for licence
**
*****************************************************************/

# include <stdio.h>
# include <string.h>
# include <dirent.h>
# include <assert.h>
# include <unistd.h>
# include "config.h"
# include "debug.h"
# include "misc.h"
# include "strlist.h"
# include "zconf.h"
# include "dki.h"

extern  int	optopt;
extern  int	opterr;
extern  int	optind;
extern  char	*optarg;
const	char	*progname;

char	*labellist = NULL;

int	headerflag = 1;
int	ageflag = 0;
int	timeflag = 1;
int	pathflag = 0;
int	kskflag = 1;
int	zskflag = 1;

static	int	dirflag = 0;
static	int	recflag = RECURSIVE;
static	int	trustedkeyflag = 0;

static	int	parsedirectory (const char *dir, dki_t **listp);
static	void	parsefile (const char *file, dki_t **listp);
static	void	createkey (const char *keyname, const dki_t *list, const zconf_t *conf);
static	void    usage (char *mesg, zconf_t *cp);
static	const char *parsetag (const char *str, int *tagp);

main (int argc, char *argv[])
{
	dki_t	*data = NULL;
	dki_t	*dkp;
	int	c;
	int	action;
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
	if ( fileexist (CONFIG_FILE) )			/* load default config file */
		config = loadconfig (CONFIG_FILE, config);
	if ( config == NULL )
		fatal ("Out of memory\n");
	recflag = config->recursive;
	ageflag = config->printage;
	timeflag = config->printtime;

        opterr = 0;
	while ( (c = getopt (argc, argv, "A:C:D:P:R:HKTS:ZVac:dhkl:prtz")) != -1 )
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
			pathflag = !pathflag;
			/* fall through */
		case 'P':
		case 'A':
		case 'D':
		case 'R':
		case 'S':
			if ( (keyname = parsetag (optarg, &searchtag)) != NULL )
			{
				int len = strlen (keyname);
				if ( len > 0 && keyname[len-1] != '.' )
				{
					snprintf (str, sizeof(str), "%s.", keyname);
					keyname = str;
				}
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
			checkconfig (config);
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
		case 'l':		/* label list */
			labellist = prepstrlist (optarg, LISTDELIM);
			if ( labellist == NULL )
				fatal ("Out of memory\n");
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

	/* it's better to do this before we read the whole subdirectory tree */
	if ( action == 'Z' )
	{
		printconfig ("stdout", config);
		return 0;
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
			parsedirectory (file, &data);
		else
			parsefile (file, &data);

	}  while ( c < argc );	/* for all arguments */

	switch ( action )
	{
	case 'H':
	case 'V':
		usage ("", config);
	case 'C':
		createkey (keyname, data, config);
		break;
	case 'P':
	case 'A':
	case 'D':
		if ( (dkp = (dki_t*)zkt_search (data, searchtag, keyname)) == NULL )
			fatal ("Key with tag %u not found\n", searchtag);
		else if ( dkp == (void *) 01 )
			fatal ("Key with tag %u found multiple times\n", searchtag);
		dki_setstatus_preservetime (dkp, action);
		break;
	case 'R':
		if ( (dkp = (dki_t *)zkt_search (data, searchtag, keyname)) == NULL )
			fatal ("Key with tag %u not found\n", searchtag);
		else if ( dkp == (void *) 01 )
			fatal ("Key with tag %u found multiple times\n", searchtag);
		dki_remove (dkp);
		break;
	case 'S':
		if ( (dkp = (dki_t *)zkt_search (data, searchtag, keyname)) == NULL )
			fatal ("Key with tag %u not found\n", searchtag);
		else if ( dkp == (void *) 01 )
			fatal ("Key with tag %u found multiple times\n", searchtag);
		dki_prt_dnskey (dkp, stdout);
		break;
	case 'K':
		zkt_list_dnskeys (data);
		break;
	case 'T':
		zkt_list_trustedkeys (data);
		break;
	default:
		zkt_list_keys (data);
	}

	return 0;
}

static	void    usage (char *mesg, zconf_t *cp)
{
        fprintf (stderr, "Secure DNS Zone Key Tool %s\n", ZKT_VERSION);
        fprintf (stderr, "\n");
        fprintf (stderr, "Show zone config parameter as %s file\n", LOCALCONF_FILE);
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
        fprintf (stderr, "Create a new key \n");
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
        fprintf (stderr, "\t-c file\t read config from <file> instead of %s\n", CONFIG_FILE);
        fprintf (stderr, "\t-d\t skip directory arguments\n");
        fprintf (stderr, "\t-h\t no headline or trusted-key section header/trailer in -T mode\n");
        fprintf (stderr, "\t-l list\t print out only zone keys out of the given domain list\n");
        fprintf (stderr, "\t-p\t show path of keyfile / create key in current directory\n");
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

static	void	createkey (const char *keyname, const dki_t *list, const zconf_t *conf)
{
	const char *dir = "";
	dki_t	*dkp;

	if ( keyname == NULL || *keyname == '\0' )
		fatal ("Create key: no keyname!");

	dbg_val ("createkey: keyname %s\n", keyname);
	/* search for already existent key to get the directory name */
	if ( pathflag && (dkp = (dki_t *)dki_search (list, 0, keyname)) != NULL )
	{
		char    path[MAX_PATHSIZE+1];
		zconf_t localconf;

		dir = dkp->dname;
		pathname (path, sizeof (path), dir, LOCALCONF_FILE, NULL);
		if ( fileexist (path) )                 /* load local config file */
		{
			dbg_val ("Load local config file \"%s\"\n", path);
			memcpy (&localconf, conf, sizeof (zconf_t));
			conf = loadconfig (path, &localconf);
		}
	}
	
	if  ( zskflag )
		dkp = dki_new (dir, keyname, 0, conf->z_algo, conf->z_bits, conf->z_random);
	else
		dkp = dki_new (dir, keyname, 1, conf->k_algo, conf->k_bits, conf->k_random);
	if ( dkp == NULL )
		fatal ("Can't create key %s: %s!\n", keyname, dki_geterrstr ());
	if  ( zskflag )
		dki_setstatus (dkp, 'p');
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
			{
				// fprintf (stderr, "parsedir: tssearch (%d %s)\n", dkp, dkp->name);
				dki_t	**p;
#if defined (USE_TREE) && USE_TREE
				dki_tadd (listp, dkp);
#else
				dki_add (listp, dkp);
#endif
			}
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
#if defined (USE_TREE) && USE_TREE
			dki_tadd (listp, dkp);		/* ... and add to tree */
#else
			dki_add (listp, dkp);		/* ... and add to list */
#endif
		else
			error ("error parsing %s: (%s)\n", file, dki_geterrstr());
	}
}

static	const char *parsetag (const char *str, int *tagp)
{
	const	char	*p;

	*tagp = 0;
	while ( isspace (*str) )	/* skip leading ws */
		str++;

	p = str;
	if ( isdigit (*p) )		/* keytag starts with digit */
	{
		sscanf (p, "%u", tagp);	/* try to read keytag as number */
		do
			p++;
		while ( isdigit (*p) );

		if ( *p == ':' )	/* label follows ? */
			return p+1;	/* return that */
		if ( *p == '\0' )
			return NULL;	/* no label */
	}
	return str;	/* return as label string if not a numeric keytag */
}

