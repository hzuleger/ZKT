/*****************************************************************
**
*****************************************************************/

#include <ldns/ldns.h>

#include <strings.h>
#include <limits.h>

#include "debug.h"
#include "misc.h"

#define extern
#include "nsrrlist.h"
#undef extern

/*****************************************************************
**
**	ldns_rr_list	*zone_ns_rr_list (const ldns_zone *z)
**
**	get the list of ns records for a zone
**	Optional put the glue records into the gluelist
**
**	We assume that 1) all NS records of the zone are at the
**	beginning of the file and 2) before any record with a
**	owner other than the origin od the zone.
**
*****************************************************************/
# define	MAXNS	10	/* Maximum no of name servers in an NS record set */
ldns_rr_list	*zone_ns_rr_list (const ldns_zone *z, ldns_rr_list **pglue_rr_list)
{
	ldns_rr_list	*nslist;
	ldns_rr_list	*gluelist;
	ldns_rr		*rr;
	ldns_rdf	*soa_owner;
	ldns_rdf	*ns_owner;
	ldns_rdf	*addr_owner;
	ldns_rdf	*rdata;
	ldns_rdf	*ns_glue[MAXNS];
	int		glueneeded;
	int		i;
	int		j;

	dbg_line();
	/* we cannot determine glue in a 'zone' without a SOA */
	if ( !ldns_zone_soa (z) )
		return NULL;

	if ( (soa_owner = ldns_rr_owner (ldns_zone_soa (z))) == NULL )
		fatal ("can't get owner of soa record\n");

	if ( (nslist = ldns_rr_list_new ()) == NULL )
		goto memory_error;
	if ( (gluelist = ldns_rr_list_new ()) == NULL )
		goto memory_error;

	glueneeded = 0;
	dbg_line();
	/* loop through zone related records */
	for ( i = 0; i < ldns_zone_rr_count (z) && glueneeded < MAXNS; i++ )
	{
		rr = ldns_rr_list_rr (ldns_zone_rrs (z), i);
		if ( ldns_rdf_compare (ldns_rr_owner (rr), soa_owner) != 0 )
			break;		/* First none zone record reached */

		dbg_line();
		if ( ldns_rr_get_type (rr) == LDNS_RR_TYPE_NS )
		{
#if DBG
			fprintf (stderr, "NS found: compare ");
			ldns_rdf_print (stderr, ldns_rr_owner(rr));
			fprintf (stderr, " == ");
			ldns_rdf_print (stderr, ldns_rr_owner (ldns_zone_soa(z)));
			fprintf (stderr, "\n");
#endif
			/* push NS record to the nslist */
			if ( !ldns_rr_list_push_rr (nslist, rr) )
				goto memory_error;

			/* store rdata in array of NS which needs glue records */
			ns_owner = ldns_rr_owner (rr);
			rdata = ldns_rr_rdf (rr, 0);
			if ( ldns_dname_is_subdomain (rdata, ns_owner) )
				ns_glue[glueneeded++] = rdata;
		}
	}

	/* now loop through the rest of the zone file to get the glue records if neccessary */
	while ( glueneeded && i < ldns_zone_rr_count (z) )
	{
		rr = ldns_rr_list_rr (ldns_zone_rrs (z), i++);

		if ( ldns_rr_get_type (rr) != LDNS_RR_TYPE_A  &&
		     ldns_rr_get_type (rr) != LDNS_RR_TYPE_AAAA )
			continue;

		dbg_line();
		addr_owner = ldns_rr_owner (rr);
		/* loop through ns array for A/AAAA glue */
		for ( j = 0; j < glueneeded; j++ )
		{
			if ( ldns_dname_compare (addr_owner, ns_glue[j]) == 0)
				/* push glue to gluelist */
				if ( !ldns_rr_list_push_rr (gluelist, rr) )
					goto memory_error;
		}
	}

	dbg_line ();
	if ( ldns_rr_list_rr_count (gluelist) == 0)
	{
		dbg_line ();
		ldns_rr_list_free (gluelist);
		gluelist = NULL;
	}	

	dbg_line ();
	if ( pglue_rr_list )
		*pglue_rr_list = gluelist;

	return nslist;

memory_error:
	if ( nslist )
		LDNS_FREE (nslist);
	if ( gluelist )
		ldns_rr_list_free (gluelist);

	return NULL;
}

/*****************************************************************
**
**	ldns_rr_list	*zone_ds_rr_list (const ldns_zone *z)
**
**	get the list of CDS or DNSKEY records to create DS for a zone
**
*****************************************************************/
ldns_rr_list	*zone_ds_rr_list (const ldns_zone *z, int use_cds)
{
	static	ldns_hash	hashes[] = { LDNS_SHA1, LDNS_SHA256, 0 };
	ldns_rr_list	*dslist;
	ldns_rr		*rr;
	ldns_rr		*ds;
	size_t		i;
	size_t		j;

	dbg_line();
	/* we cannot determine glue in a 'zone' without a SOA */
	if ( !ldns_zone_soa (z) )
		return NULL;

	if ( (dslist = ldns_rr_list_new ()) == NULL )
		return NULL;

	dbg_line();
	for ( i = 0; i < ldns_zone_rr_count (z); i++ )
	{
		rr = ldns_rr_list_rr (ldns_zone_rrs (z), i);

		if ( use_cds && ldns_rr_get_type (rr) != LDNS_RR_TYPE_CDS )
			continue;
		if ( use_cds == 0 && ldns_rr_get_type (rr) != LDNS_RR_TYPE_DNSKEY )
			continue;

#if DBG
		ldns_rr_print (stderr, rr);
#endif
		dbg_line();
		if ( ldns_rdf_compare (
				ldns_rr_owner (rr),
				ldns_rr_owner (ldns_zone_soa (z))) != 0 )
			continue;

		dbg_line();
		if ( use_cds == 0 && !(ldns_rdf2native_int16 (ldns_rr_dnskey_flags (rr)) & LDNS_KEY_SEP_KEY) )
			continue;
#if DBG
		fprintf (stderr, "%s found ", use_cds ? "CDS": "DNSKEY");
		ldns_rdf_print (stderr, ldns_rr_owner (r));
		fprintf (stderr, "\n");
#endif
		dbg_line();
		if ( use_cds )
		{
			/* change CDS to DS record and push it to the list */
			ds = rr;
			dbg_line();
			ldns_rr_set_type (ds, LDNS_RR_TYPE_DS);
			dbg_line();
			if ( !ldns_rr_list_push_rr (dslist, ds) )
				return NULL;
		}
		else
		{
			for ( j = 0; hashes[j]; j++ )
			{
				if ( (ds = ldns_key_rr2ds (rr, hashes[j])) == NULL )
				{
					ldns_rr_free (rr);
					fatal ("Conversion to a DS RR failed\n");
				}
				if ( !ldns_rr_list_push_rr (dslist, ds) )
					return NULL;
#if DBG
				ldns_rr_print (stderr, ds);
#endif
			}
		}
	}

	dbg_line();

	return dslist;
}

