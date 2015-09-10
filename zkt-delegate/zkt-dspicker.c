/*****************************************************************
**
**	zkt-dspicker.c -- Update bind ds-file based on CDS records
**
**	! WORK IN PROGRESS (or even actually quite less progress) !
**
**	See the file LICENSE for the license
**			
*****************************************************************/

#include <strings.h>
#include <ldns/ldns.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#if defined(HAVE_GETOPT_LONG) && HAVE_GETOPT_LONG
# include <getopt.h>
#endif

# include "debug.h"
# include "misc.h"


extern	int	optopt;
extern	int	opterr;
extern	int	optind;
extern	char	*optarg;

/* option vars */
const	char	*progname;
const	char	*version = VERSION;
char	parentzone[255+1];
char	origin[255+1];
char	*server;
int	port;
int	verbose;

#define	short_options	"+ho:p:s:vV"	/* don't remove leading '+' (see man getopt_long) */
#if defined(HAVE_GETOPT_LONG) && HAVE_GETOPT_LONG
static	struct	option	long_options[] = {
	{ "version",		no_argument,		NULL,	'V' },
	{ "help",		no_argument,		NULL,	'h' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ "origin",		required_argument,	NULL,	'o' },
	{ "server",		required_argument,	NULL,	's' },
	{ "port",		required_argument,	NULL,	'p' },
};
#endif

/* static function declaration */
static	void	usage (const char *mesg);
static ldns_resolver *getresolver (const char *server, const char *zone, uint16_t port, ldns_tsig_credentials *tsig_cred, ldns_rdf **zone_rdf);


/* the command */
int	main (int argc, char*argv[])
{
	int	opt_index;
	int	c;
	char	tmpstr[127+1];
	const	char	*cmd;		/* the command string */
	ldns_rdf	*zone_rdf;
	ldns_resolver	*res;
	ldns_rr_list	*up_rrlist;
	ldns_rr_list	*pr_rrlist;	/* prerequisite list */

	if ( (progname = strrchr (*argv, '/')) == NULL )
		progname = *argv;
	else
		progname++;

	opterr = 0;	/* prevent the printing of the getopt() buildin error messages */

	
	keyfile = NULL;
	server = NULL;
	origin[0] = '\0';
	parentzone[0] = '\0';
	ttl = 0L;
	port = 53;

#if defined(HAVE_GETOPT_LONG) && HAVE_GETOPT_LONG
	while ( (c = getopt_long (argc, argv, short_options, long_options, &opt_index)) != -1 )
#else
	while ( (c = getopt (argc, argv, short_options)) != -1 )
#endif
	{
		switch ( c )
		{
		case 'V':	fprintf (stderr, "%s version %s\n", progname, version);
				exit (0);
				break;
		case 'v':	verbose = 1;
				break;
		case 'd':	delete = 1;
				break;
		case 'h':	usage (NULL);
				break;
		case 'p':	port = atoi (optarg);
				break;
		case 't':	ttl = ttlfromstr (optarg);
				break;
		case 'k':	keyfile = optarg;
				break;
		case 's':	server = optarg;
				break;
		case 'o':	snprintf (origin, sizeof (origin), "%s", optarg);
				break;
		case ':':	snprintf (tmpstr, sizeof (tmpstr), "option \"-%c\" requires an argument\n", optopt);
				usage (tmpstr);
				break;
		case '?':	if ( isprint (optopt) )
					snprintf (tmpstr, sizeof (tmpstr), "%s: unknown option \"-%c\"\n", progname, optopt);
				else
					snprintf (tmpstr, sizeof (tmpstr), "%s: unknown option char \\x%x\n", progname, optopt);
				usage (tmpstr);
				break;
		default:	abort();
		}
	}

	/* some error checking */

	/* origin is the parentzone */
	{
		int	len;

		len = strlen (origin);
		if ( len && origin[len-1] != '.' )
			snprintf (parentzone, sizeof (parentzone), "%s.", origin);	/* add a dot */
		else
			snprintf (parentzone, sizeof (parentzone), "%s", origin);
	}

	argc -= optind;
	argv += optind;
	if ( argc <= 0 )
		usage ("missing ds-file\n");

	pr_rrlist = NULL;

	/* get an resolver object to get the CDS records */
	res = getresolver (server, parentzone, port, &tsig_cred, &zone_rdf);
	if ( !res || !zone_rdf )
		usage ("error getting resolver structure for update\n");

	if ( up_rrlist )
	{
		if ( sendupdate (res, zone_rdf, pr_rrlist, up_rrlist, NULL, &tsig_cred) != 1 )
			fprintf (stderr, "error sending update\n");
		verbmesg (1, "update done\n");
	}

	return 0;
}

static	void	usage (const char *mesg)
{
	if ( mesg && *mesg )
		fprintf (stderr, "%s\n", mesg);

	fprintf (stderr, "usage: %s -h|-v\n", progname);
	fprintf (stderr, "usage: %s -k keyfile [-d] [-t ttl] [-s server] [-p port] [-o origin] <cmd> [parameter  ...]\n", progname);
	fprintf (stderr, "\t-h, --help\t\t print out this help message \n");
	fprintf (stderr, "\t-V, --version\t\t print out version and exit \n");

	fprintf (stderr, "\t-v, --verbose\t\t \n");
	fprintf (stderr, "\t-k, --keyfile=tsigfile\t name of file with tsig key (named.conf syntax)\n");
	fprintf (stderr, "\t-d, --delete\t\t switch update delete processing \n");
	fprintf (stderr, "\t\t \t\t (default: In file mode delete old RRSet before adding new ones)\n");
	fprintf (stderr, "\t-t, --ttl <ttlspec>\t specify ttl of RR (default depends on cmd)\n");
	fprintf (stderr, "\t-o, --origin=zone\t specify domain (default is tsig keyname)\n");
	fprintf (stderr, "\t-s, --server=master\t specify master server for updates (default is SRV or SOA record)\n");
	fprintf (stderr, "\t-p, --port=<port>\t specify port for updates (default is 53)\n");

	fprintf (stderr, "<cmd>\n");
	fprintf (stderr, "\tns   {-f zonefile | [nsname ...]}\t\tchange delegation record (NS)\n");
	fprintf (stderr, "\tds   {-d dsfile | -f zonefile_with_CDS}\t\tchange delegation signer record (DS)\n");
	fprintf (stderr, "\tglue {-f zonefile | nsname [ipaddr ...]}\tchange glue address record (A/AAAA)\n");

	exit (1);
}

static	void	set_tsig_cred (ldns_tsig_credentials *tsig_cr, tsigkey_t *key)
{
	assert ( key );
	assert ( tsig_cr );

	tsig_cr->keyname = key->name;
	tsig_cr->keydata = key->secret;

	if ( strncasecmp (key->algo, "hmac-sha", 8) == 0)
	{
		int	len;

		len = strlen (key->algo);
		if ( len+1 < sizeof (key->algo) )
			snprintf (key->algo+len, sizeof (key->algo) - len, ".");
	}
	else if (strncasecmp (key->algo, "hmac-md5", 8) == 0)
	{
		snprintf (key->algo, sizeof (key->algo), "hmac-md5.sig-alg.reg.int.");
	}
	else
	{
		fprintf(stderr, "Unknown algorithm %s", key->algo);
		exit (1);
	}
	
	tsig_cr->algorithm = key->algo;
}

static ldns_resolver *getresolver (const char *server, const char *zone, uint16_t port, ldns_tsig_credentials *tsig_cred, ldns_rdf **zone_rdf)
{
	ldns_rr_class	class;
	ldns_resolver   *r1;
	ldns_resolver   *r2;
	ldns_pkt        *query = NULL;
	ldns_pkt        *resp = NULL;
	ldns_rr_list    *nslist;
	ldns_rr_list	*iplist;
	ldns_rdf        *soa_zone;
	ldns_rdf	*soa_mname = NULL;
	ldns_rdf	*ns_name;
	size_t          i;
	ldns_status     s;

	class = LDNS_RR_CLASS_IN;
	if ( port == 0 )
		port = 53;

	/* First, get data from /etc/resolv.conf */
	s = ldns_resolver_new_frm_file (&r1, NULL);
	if ( s != LDNS_STATUS_OK )
		return NULL;

	/* this is the resolver we want to use for the update message */
	if ( (r2 = ldns_resolver_new ()) == NULL )
		goto bad;
	ldns_resolver_set_port (r2, port);

        /* TSIG key data available? Copy into the resolver. */
	if ( tsig_cred )
	{
		ldns_resolver_set_tsig_algorithm(r2, ldns_tsig_algorithm(tsig_cred));
		ldns_resolver_set_tsig_keyname(r2, ldns_tsig_keyname(tsig_cred));
		ldns_resolver_set_tsig_keydata(r2, ldns_tsig_keydata(tsig_cred));
        }

	/* Now get SOA zone, mname, NS, and construct r2. [RFC2136 4.3] */
	soa_zone = ldns_dname_new_frm_str (zone);
	if ( ldns_update_soa_mname (soa_zone, r1, class, &soa_mname) != LDNS_STATUS_OK )
		goto bad;

	/* Pass zone_rdf on upwards. */
	*zone_rdf = ldns_rdf_clone (soa_zone);

	/* form NS record query */
	if ( (query = ldns_pkt_query_new (soa_zone, LDNS_RR_TYPE_NS, class, LDNS_RD)) == NULL )
		goto bad;

	soa_zone = NULL;
	ldns_pkt_set_random_id (query);

	/*  NS record lookup */
	if ( ldns_resolver_send_pkt (&resp, r1, query) != LDNS_STATUS_OK)
	{
		dprintf ("%s", "NS query failed!\n");
		goto bad;
	}
	ldns_pkt_free (query);
	if ( !resp )
		goto bad;

	/* Match SOA MNAME to NS list, adding it first */
	nslist = ldns_pkt_answer (resp);
	for ( i = 0; i < ldns_rr_list_rr_count (nslist); i++ )
	{
		ns_name = ldns_rr_rdf (ldns_rr_list_rr (nslist, i), 0);
		if ( !ns_name )
			continue;
		if ( ldns_rdf_compare (soa_mname, ns_name) == 0 )	/* Match */
		{
			iplist = ldns_get_rr_list_addr_by_name (r1, ns_name, class, 0);
			(void) ldns_resolver_push_nameserver_rr_list (r2, iplist);
			ldns_rr_list_deep_free (iplist);
			break;
		}
	}
	/* Then all the other NSs. XXX Randomize? */
	for ( i = 0; i < ldns_rr_list_rr_count (nslist); i++ )
	{
		ns_name = ldns_rr_rdf (ldns_rr_list_rr (nslist, i), 0);
		if ( !ns_name )
			continue;
		if ( ldns_rdf_compare (soa_mname, ns_name) != 0 )	/* No match, add it now. */
		{
			iplist = ldns_get_rr_list_addr_by_name (r1, ns_name, class, 0);
			(void) ldns_resolver_push_nameserver_rr_list (r2, iplist);
			ldns_rr_list_deep_free (iplist);
		}
	}

	ldns_resolver_set_random (r2, false);
	ldns_pkt_free (resp);
	ldns_resolver_deep_free (r1);

	if ( soa_mname )
		ldns_rdf_deep_free (soa_mname);

	return r2;		/* return the resolver object for the update message */

bad:	/* cleanup */
	if ( r1 ) ldns_resolver_deep_free (r1);
	if ( r2 ) ldns_resolver_deep_free (r2);
	if ( query ) ldns_pkt_free (query);
	if ( resp ) ldns_pkt_free (resp);
	if ( soa_mname ) ldns_rdf_deep_free (soa_mname);
	
	return NULL;
}
