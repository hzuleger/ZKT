
# include <stdio.h>
# include <string.h>
# include <ldns/ldns.h>

# include "debug.h"
# include "misc.h"
# include "nsrrlist.h"
#define extern
# include "update.h"
#undef extern

extern	int	verbose;
extern	int	delete;

static	int	get_ns_from_zonefile (ldns_rr_list **pup_rrlist, ldns_rr_list **pglue_rrlist, const char *origin, const char *zonefile);
static	int	get_ds_from_zonefile (ldns_rr_list **pds_list, const char *origin, const char *zonefile);
static	int	canonicalize (char *fqdn, size_t fqdnsize, const char *dname, const char *origin);
static	void	print_update (FILE *out, ldns_rr_list *upd);

/*****************************************************************
**
**	update_del_rr_rdf ()
**
**	Build an update rrlist to delete all RR of a given dname rdf and type.
**
**	This can also be used to create a prerequisite list for an
**	"RRset exist (value independent)" prereq section (see 2.4.1 RFC2136)
**
*****************************************************************/
static	int	update_del_rr_rdf (ldns_rr_list **pup_rrlist, ldns_rdf *dname_rdf, int type)
{
	ldns_rr	*up_rr;

	assert ( pup_rrlist );
	assert ( *pup_rrlist );
	assert ( dname_rdf );

	up_rr = ldns_rr_new ();
	ldns_rr_set_owner (up_rr, dname_rdf);
	ldns_rr_set_ttl (up_rr, 0);
	ldns_rr_set_class (up_rr, LDNS_RR_CLASS_ANY);

	ldns_rr_set_type (up_rr, type);
	ldns_rr_list_push_rr (*pup_rrlist, up_rr);

	return 1;
}

/*****************************************************************
**
**	update_del_rr ()
**
**	Same as update_del_rr_rdf() but the dname is given as string.
**
*****************************************************************/
static	int	update_del_rr (ldns_rr_list **pup_rrlist, const char *dname, int type)
{
	assert ( pup_rrlist );
	assert ( dname );

	return update_del_rr_rdf (pup_rrlist, ldns_dname_new_frm_str (dname), type);
}

/*****************************************************************
**
**	prepare_ns_update ()
**
**	Build an update rrlist to add or delete a NS recordset. 
**
*****************************************************************/
ldns_rr_list	*prepare_ns_update (const char *origin, uint32_t ttl, int argc, char **argv)
{
	int	i;
	int	len;
	const	char	*dot;
	char	rrstr[511+1];

	ldns_rr_list	*up_rrlist;
	ldns_rr		*up_rr;

	/* Set up the update section. */
	up_rrlist = ldns_rr_list_new ();
	if ( !up_rrlist )
		return NULL;

	if ( argc <= 0 )
	{
		/* We're removing NS from 'dname'. [RFC2136 2.5.2] */
		update_del_rr (&up_rrlist, origin, LDNS_RR_TYPE_NS);

		if ( verbose >= 1 )
			print_update (stdout, up_rrlist);

		return up_rrlist;
	}

	if ( strcmp (argv[0], "-f") == 0 )	/* next arg is a zonefile */
	{
		argc--;	argv++;

		/* push update delete for the old NS RRset before adding the new ones */
		if ( delete == 0 )	/* this is the default */
			update_del_rr (&up_rrlist, origin, LDNS_RR_TYPE_NS);

		if ( !get_ns_from_zonefile (&up_rrlist, NULL, origin, argv[0]) )
			error ("Can't read NS RRset out of zone file \"%s\"\n", argv[0]);

		if ( verbose >= 1 )
			print_update (stdout, up_rrlist);

		return up_rrlist;
	}

	/* take command line args */

	/* push update delete for the old NS RRset before adding the new ones */
	if ( delete )
		update_del_rr (&up_rrlist, origin, LDNS_RR_TYPE_NS);

	for ( i = 0; i < argc; i++ )
	{
		dot = strchr (argv[i], '.');
		if ( dot == NULL )		/* relative rdata == glue needed */
		{
			error ("NS records needs glue. Run again with \"glue %s <gluerecord>\"\n", argv[i]);
			len = snprintf (rrstr, sizeof (rrstr), "%s IN NS %s.%s", origin, argv[i], origin);
		}
		else
		{
			len = strlen (argv[i]);
			if ( len > 0 && argv[i][len-1] == '.' )	/* if rdata ends with "." */
				dot = "";
			else
				dot = ".";

			len = snprintf (rrstr, sizeof (rrstr), "%s IN NS %s%s", origin, argv[i], dot);
		}


		/* We're adding the next NS record */
		if ( ldns_rr_new_frm_str (&up_rr, rrstr, ttl, NULL, NULL) != LDNS_STATUS_OK )
		{
			ldns_rr_list_deep_free (up_rrlist);
			return NULL;
		}
		ldns_rr_list_push_rr (up_rrlist, up_rr);
	}

	if ( verbose >= 1 )
		print_update (stdout, up_rrlist);

	return up_rrlist;
}

ldns_rr_list	*prepare_ds_update (const char *origin, uint32_t ttl, ldns_rr_list **ppr_rrlist, int argc, char **argv)
{
	FILE		*fp;
	ldns_rr         *up_rr;	
	ldns_rr_list    *up_rrlist;	/* update rr_list */
	ldns_rr_list    *pr_rrlist;	/* prerequisites rrlist */

	/* Set up the update section. */
	up_rrlist = ldns_rr_list_new ();
	if ( !up_rrlist )
		return NULL;

	if ( ppr_rrlist )	/* create a prerequisite list */
		if ( (pr_rrlist = ldns_rr_list_new ()) == NULL )
			return NULL;
		
	if ( argc <= 0 )
	{
		/* We're removing DS from 'origin'. */
		update_del_rr (&up_rrlist, origin, LDNS_RR_TYPE_DS);

		if ( verbose >= 1 )
			print_update (stdout, up_rrlist);


		if ( ppr_rrlist )
			*ppr_rrlist = NULL;

		return up_rrlist;
	}

	/* push update delete for the old DS RRset before adding the new ones */
	if ( delete == 0 )	/* this is the default */
		update_del_rr (&up_rrlist, origin, LDNS_RR_TYPE_DS);

	if ( strcmp (argv[0], "-f") == 0 )	/* next arg is zonefile */
	{
		ldns_rr_list	*dslist;

		argc--;	argv++;

		if ( (fp = fopen (argv[0], "r")) == NULL )
			fatal ("can't open zonefile %s\n", argv[0]);

		fclose (fp);

		dslist = NULL;
		if ( !get_ds_from_zonefile (&dslist, origin, argv[0]) )
			fatal ("can't generate DS Records out of zonefile\n");
		ldns_rr_list_push_rr_list (up_rrlist, dslist);
	}
	else if ( strcmp (argv[0], "-d") == 0 )	/* next arg is dsfile */
	{
		argc--;	argv++;

		if ( (fp = fopen (argv[0], "r")) == NULL )
			fatal ("can't open dsfile %s\n", argv[0]);

		verbmesg (2, "update add DS from file \"%s\"\n", argv[0]);
		while ( ldns_rr_new_frm_fp (&up_rr, fp, &ttl, NULL, NULL) == LDNS_STATUS_OK )
		{
			/* We're adding the next DS record */
			/* XXX: Be aware that this could be anything not just DS */
			ldns_rr_list_push_rr (up_rrlist, up_rr);
		}
		fclose (fp);
	}

	/* setting up the prerequisite section */
	if ( ppr_rrlist != NULL )
	{				/* set DS RR only if NS record is set */
#if 1
		update_del_rr (&pr_rrlist, origin, LDNS_RR_TYPE_NS);
#else
		ldns_rr         *pr_rr;

		pr_rr = ldns_rr_new ();
		ldns_rr_set_owner (pr_rr, ldns_origin (origin));
		ldns_rr_set_ttl (pr_rr, 0);
		ldns_rr_set_class (pr_rr, LDNS_RR_CLASS_ANY);	/* !!! */
		ldns_rr_set_type (pr_rr, LDNS_RR_TYPE_NS);
		ldns_rr_list_push_rr (pr_rrlist, pr_rr);
#endif
		*ppr_rrlist = pr_rrlist;
	}

	if ( verbose >= 1 )
		print_update (stdout, up_rrlist);

	return up_rrlist;

}

ldns_rr_list	*prepare_glue_update (const char *origin, uint32_t ttl, ldns_rr_list **ppr_rrlist, int argc, char **argv)
{
	ldns_rr         *rr;	
	ldns_rr_list    *up_rrlist;	/* update rr_list */
	ldns_rr_list    *pr_rrlist;	/* prerequisites rrlist */
	const	char	*addr;
	char		ns_name[255+1];
	char		rrstr[511+1];

	assert (origin != NULL );

	/* create an empty update list */
	up_rrlist = ldns_rr_list_new ();
	if ( !up_rrlist )
		return NULL;

	if ( ppr_rrlist )	/* create a prerequisite list */
		if ( (pr_rrlist = ldns_rr_list_new ()) == NULL )
			return NULL;
		
	if ( argc <= 0 )
		fatal ("glue command requires an argument\n");

	if ( strcmp (argv[0], "-f") == 0 )	/* next arg is zonefile */
	{
		int		i;
		ldns_rr_list	*nslist;
		ldns_rr_list	*gluelist;
		ldns_rr		*nsrr;
		ldns_rdf	*ns_owner;
		ldns_rdf	*rdata;

		argc--;	argv++;

		gluelist = ldns_rr_list_new ();
		if ( !gluelist )
			return NULL;

		if ( !get_ns_from_zonefile (&nslist, &gluelist, origin, argv[0]) )
			error ("Can't read NS RRset out of zone file \"%s\"\n", argv[0]);

		/* push update delete for the old A/AAAA RRset before adding the new ones */
		if ( delete == 0 )	/* this is the default */
		{
			for ( i = 0; i < ldns_rr_list_rr_count (nslist); i++ )
			{
				nsrr = ldns_rr_list_rr (nslist, i);
				ns_owner = ldns_rr_owner (nsrr);
				rdata = ldns_rr_rdf (nsrr, 0);

				if ( ldns_dname_is_subdomain (rdata, ns_owner) )
				{
					update_del_rr_rdf (&up_rrlist, rdata, LDNS_RR_TYPE_A);
					update_del_rr_rdf (&up_rrlist, rdata, LDNS_RR_TYPE_AAAA);
				}
			}
		}

		ldns_rr_list_push_rr_list (up_rrlist, gluelist);
		if ( verbose >= 1 )
			print_update (stdout, up_rrlist);

		return up_rrlist;
	}


	/* take glue from command line */
	if ( ppr_rrlist )
		*ppr_rrlist = NULL;

	canonicalize (ns_name, sizeof (ns_name), argv[0], origin);

	/* push the update delete for the old glue address records before adding new ones */
	if ( delete )
	{
		update_del_rr (&up_rrlist, ns_name, LDNS_RR_TYPE_A);
		update_del_rr (&up_rrlist, ns_name, LDNS_RR_TYPE_AAAA);
	}


#if 0
	/* TODO: prerequisite needs full rrset, not only the one we want to add glue */
	if ( argc > 1 && ppr_rrlist )
	{
		ldns_rr         *pr_rr;
		ldns_rdf	*ns_rdf;

		pr_rr = ldns_rr_new ();
		ldns_rr_set_owner (pr_rr, ldns_dname_new_frm_str (origin));
		ldns_rr_set_ttl (pr_rr, 0);
		ldns_rr_set_class (pr_rr, LDNS_RR_CLASS_IN);
		ldns_rr_set_type (pr_rr, LDNS_RR_TYPE_NS);
		if ( ldns_str2rdf_dname (&ns_rdf, ns_name) != LDNS_STATUS_OK )
			fatal ("error prparing NS prerequisite record\n");
		ldns_rr_push_rdf (pr_rr, ns_rdf);

		ldns_rr_list_push_rr (pr_rrlist, pr_rr);

		*ppr_rrlist = pr_rrlist;
	}
#endif

	while ( --argc )
	{
		addr = *++argv;

		if ( strchr (addr, '.') )	/* assume that this is an IPv4 address */
			snprintf (rrstr, sizeof (rrstr), "%s %d IN A\t%s", ns_name, ttl, addr);
		else if ( strchr (addr, ':') )	/* assume that this is an IPv6 address */
			snprintf (rrstr, sizeof (rrstr), "%s %d IN AAAA\t%s", ns_name, ttl, addr);
		else
			fatal ("argument of glue command does not look like an ip address\n");

		verbmesg (1, "update add %s\n", rrstr);

		/* Now we are adding the next address record */
		if ( ldns_rr_new_frm_str (&rr, rrstr, ttl, NULL, NULL) != LDNS_STATUS_OK )
		{
			ldns_rr_list_deep_free (up_rrlist);
			return NULL;
		}
		ldns_rr_list_push_rr (up_rrlist, rr);
	}

	return up_rrlist;
}

int	sendupdate (ldns_resolver *res, ldns_rdf *zone_rdf, ldns_rr_list *pr_rrlist, ldns_rr_list *up_rrlist, ldns_rr_list *ad_rrlist, ldns_tsig_credentials *tsig_cred)
{
	int		ret = 0;
	ldns_pkt	*u_pkt;
	ldns_pkt	*r_pkt;

        /* Create update packet. */
        u_pkt = ldns_update_pkt_new (zone_rdf, LDNS_RR_CLASS_IN, pr_rrlist, up_rrlist, ad_rrlist);
	zone_rdf = NULL;
        if ( !u_pkt && up_rrlist )
                ldns_rr_list_deep_free (up_rrlist);

	dbg_line();
	ldns_pkt_set_random_id (u_pkt);

	dbg_line();
        /* Add TSIG */
	if ( tsig_cred && (ret = ldns_update_pkt_tsig_add (u_pkt, res)) != LDNS_STATUS_OK )
		goto cleanup;

	/* send packet */
	dbg_line();
	if ( (ret = ldns_resolver_send_pkt (&r_pkt, res, u_pkt)) != LDNS_STATUS_OK )
		goto cleanup;

	dbg_line();
	ldns_pkt_free (u_pkt);
	if ( !r_pkt )
		goto cleanup;

	dbg_line();
	/* get return code */
	if ( (ret = ldns_pkt_get_rcode (r_pkt)) != LDNS_RCODE_NOERROR )
	{
		ldns_lookup_table	*t;
		
		t = ldns_lookup_by_id (ldns_rcodes, (int)ldns_pkt_get_rcode (r_pkt));
		if ( t )
			fatal ("UPDATE error: response was %s\n", t->name);
		else
			fatal ("UPDATE error: response was (%d)\n", ldns_pkt_get_rcode(r_pkt));
	}
	ldns_pkt_free (r_pkt);
	ldns_resolver_deep_free (res);

	return 1;

cleanup:
	fprintf (stderr, "LDNS error (%d): %s \n", ret, ldns_get_errorstr_by_id (ret));
	if ( res )
		ldns_resolver_deep_free (res);
	if ( u_pkt )
		ldns_pkt_free (u_pkt);
	if ( zone_rdf )
		ldns_rdf_deep_free (zone_rdf);

	return 0;
}

static	int	get_ns_from_zonefile (ldns_rr_list **pns_list, ldns_rr_list **pglue_list, const char *origin, const char *zonefile)
{
	FILE	*fp;
	int	defttl = 7200;
	ldns_zone	*z;
	ldns_rr_list	*nslist;
	ldns_rdf	*originrdf;

	if ( (fp = fopen (zonefile, "r")) == NULL )
		fatal ("Can't open zone file %s\n", zonefile);

	ldns_str2rdf_dname (&originrdf, origin);
	if ( ldns_zone_new_frm_fp (&z, fp, originrdf, defttl, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK )
		fatal ("Can't read zone file %s\n", zonefile);
	fclose (fp);

	nslist = zone_ns_rr_list (z, pglue_list);
	if ( nslist == NULL )
		return 0;

	if ( pns_list )
		ldns_rr_list_push_rr_list (*pns_list, nslist);

	return 1;
}

static	int	get_ds_from_zonefile (ldns_rr_list **pds_list, const char *origin, const char *zonefile)
{
	FILE	*fp;
	int	defttl = 7200;
	ldns_zone	*z;
	ldns_rr_list	*dslist;
	ldns_rdf	*originrdf;

	dbg_line();
	if ( (fp = fopen (zonefile, "r")) == NULL )
		fatal ("Can't open zone file %s\n", zonefile);

	/* read zonefile */
	dbg_line();
	ldns_str2rdf_dname (&originrdf, origin);
	if ( ldns_zone_new_frm_fp (&z, fp, originrdf, defttl, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK )
		fatal ("Can't read zone file %s\n", zonefile);
	fclose (fp);

	dbg_line();
	/* generate ds list out of CDS or DNSKEY records */
	dslist = zone_ds_rr_list (z, 1);
	if ( dslist == NULL || ldns_rr_list_rr_count (dslist) == 0 )
		return 0;
#if DBG
	{
	int	i;
	ldns_rr		*rr;

	fprintf (stderr, "DS list:\n");
	for ( i = 0; i < ldns_rr_list_rr_count (dslist); i++ )
	{
		rr = ldns_rr_list_rr (dslist, i);
		ldns_rr_print (stderr, rr);
	}
	}
#endif

	dbg_line();
	if ( pds_list )
		*pds_list = dslist;

	dbg_line();
	return 1;
}

static	int	canonicalize (char *fqdn, size_t fqdnsize, const char *dname, const char *origin)
{
	int	len;

	assert ( fqdn != NULL );
	assert ( dname != NULL );

	len = strlen (dname);
	if ( len && dname[len-1] == '.' )	/* dname ends with a dot? */
		len = snprintf (fqdn, fqdnsize, "%s", dname);
	else
	{
		len = strlen (origin);
		if ( len && origin[len-1] == '.' )	/* origin ends with a dot? */
			len = snprintf (fqdn, fqdnsize, "%s.%s", dname, origin);
		else
			len = snprintf (fqdn, fqdnsize, "%s.%s.", dname, origin);
	}

	return len;
}

static	void	print_update (FILE *out, ldns_rr_list *upd)
{
	int		i;
	uint32_t	ttl;
	ldns_rr		*rr;
	const	char	*rstr;

	for ( i = 0; i < ldns_rr_list_rr_count (upd); i++ )
	{
		rr = ldns_rr_list_rr (upd, i);
		ttl = ldns_rr_ttl (rr);		/* get the ttl of the record (used for upd del output hack) */
		rstr = ldns_rr2str_fmt (ldns_output_format_default, rr);

		if ( ttl )
			fprintf (out, "update add %s", rstr);
		else 
		{
			char	*p;

			if ( (p = strstr (rstr, "\\# 0")) )	/* remove empty rdate */
			{
				*p++ = '\n';
				*p = '\0';
			}	
			fprintf (out, "update del %s", rstr);
		}
	}
}

