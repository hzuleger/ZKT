# include <stdio.h>
# include "config.h"
# include "dki.h"
#define extern
# include "zkt.h"
#undef extern

extern	char	*labellist;
extern	int	headerflag;
extern	int	timeflag;
extern	int	ageflag;
extern	int	kskflag;
extern	int	zskflag;
extern	int	pathflag;
extern	int	ljustflag;

static	void	printkeyinfo (const dki_t *dkp, const char *oldpath);

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
		if ( ljustflag )
			printf ("%-33.33s ", dkp->name);
		else
			printf ("%33.33s ", dkp->name);
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

#if defined(USE_TREE) && USE_TREE
static	void	list_key (const dki_t **nodep, const VISIT which, int depth)
{
	const	dki_t	*dkp;
	static	const	char	*oldpath = "";

	if ( nodep == NULL )
		return;
//fprintf (stderr, "listkey %d %d %s\n", which, depth, dkp->name);

	if ( which == INORDER || which == LEAF )
	{
		dkp = *nodep;
		while ( dkp )	/* loop through list */
		{
			if ( labellist == NULL || isinlist (dkp->name, labellist) )
				printkeyinfo (dkp, oldpath);		/* print entry */
			oldpath = dkp->dname;
			dkp = dkp->next;
		}
	}
}
#endif

void	zkt_list_keys (const dki_t *data)
{
	const   dki_t   *dkp;
	const   char    *oldpath;

	if ( data )    /* print headline if list is not empty */
		printkeyinfo (NULL, "");

#if defined(USE_TREE) && USE_TREE
	twalk (data, list_key);
#else
	oldpath = "";
	for ( dkp = data; dkp; dkp = dkp->next )       /* loop through list */
	{
		if ( labellist == NULL || isinlist (dkp->name, labellist) )
			printkeyinfo (dkp, oldpath);            /* print entry */
		oldpath = dkp->dname;
	}
#endif
}

#if defined(USE_TREE) && USE_TREE
static	void	list_trustedkey (const dki_t **nodep, const VISIT which, int depth)
{
	const	dki_t	*dkp;

	if ( nodep == NULL )
		return;

	dkp = *nodep;
//fprintf (stderr, "list_trustedkey %d %d %s\n", which, depth, dkp->name);
	if ( which == INORDER || which == LEAF )
		while ( dkp )	/* loop through list */
		{
			if ( (dki_isksk (dkp) || zskflag) &&
			     (labellist == NULL || isinlist (dkp->name, labellist)) )
				dki_prt_trustedkey (dkp, stdout);
			dkp = dkp->next;
		}
}
#endif

void	zkt_list_trustedkeys (const dki_t *data)
{
#if !defined(USE_TREE) || !USE_TREE
	const	dki_t	*dkp;
#endif
	/* print headline if list is not empty */
	if ( data && headerflag )
		printf ("trusted-keys {\n");

#if defined(USE_TREE) && USE_TREE
	twalk (data, list_trustedkey);
#else

	for ( dkp = data; dkp; dkp = dkp->next )	/* loop through list */
		if ( (dki_isksk (dkp) || zskflag) &&
		     (labellist == NULL || isinlist (dkp->name, labellist)) )
			dki_prt_trustedkey (dkp, stdout);
#endif

	/* print end of trusted-key section */
	if ( data && headerflag )
		printf ("};\n");
}

#if defined(USE_TREE) && USE_TREE
static	void	list_dnskey (const dki_t **nodep, const VISIT which, int depth)
{
	const	dki_t	*dkp;
	int	ksk;

	if ( nodep == NULL )
		return;

	if ( which == INORDER || which == LEAF )
		for ( dkp = *nodep; dkp; dkp = dkp->next )
		{
			ksk = dki_isksk (dkp);
			if ( ksk && !kskflag || !ksk && !zskflag )
				continue;

			if ( labellist == NULL || isinlist (dkp->name, labellist) )
			{
				if ( headerflag )
					dki_prt_comment (dkp, stdout);
				dki_prt_dnskey (dkp, stdout);
			}
		}
}
#endif

void	zkt_list_dnskeys (const dki_t *data)
{
#if defined(USE_TREE) && USE_TREE
	twalk (data, list_dnskey);
#else
	const	dki_t	*dkp;
	int	ksk;

	for ( dkp = data; dkp; dkp = dkp->next )
	{
		ksk = dki_isksk (dkp);
		if ( ksk && !kskflag || !ksk && !zskflag )
			continue;

		if ( labellist == NULL || isinlist (dkp->name, labellist) )
		{
			if ( headerflag )
				dki_prt_comment (dkp, stdout);
			dki_prt_dnskey (dkp, stdout);
		}
	}
#endif
}


#if defined(USE_TREE) && USE_TREE
static	const	dki_t	*searchresult;
static	int	searchitem;
static	void	tag_search (const dki_t **nodep, const VISIT which, int depth)
{
	const	dki_t	*dkp;

	if ( nodep == NULL )
		return;

	if ( which == PREORDER || which == LEAF )
		for ( dkp = *nodep; dkp; dkp = dkp->next )
		{
			if ( dkp->tag == searchitem )
				if ( searchresult == NULL )
					searchresult = dkp;
				else
					searchitem = 0;
		}
}
#endif
const	dki_t	*zkt_search (const dki_t *data, int searchtag, const char *keyname)
{
	const dki_t	*dkp = NULL;

#if defined(USE_TREE) && USE_TREE
	if ( keyname == NULL || *keyname == '\0' )
	{
		searchresult = NULL;
		searchitem = searchtag;
		twalk (data, tag_search);
		if ( searchresult != NULL && searchitem == 0 )
			dkp = (void *)01;
		else
			dkp = searchresult;
	}
	else
		dkp = (dki_t*)dki_tsearch (data, searchtag, keyname);
#else
	dkp = (dki_t*)dki_search (data, searchtag, keyname);
#endif
	return dkp;
}

