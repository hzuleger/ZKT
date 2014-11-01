/*****************************************************************
**
**	@(#) rollover.c -- The key rollover functions
**
**	(c) Jan 2005 - May 2008  Holger Zuleger  hznet.de
**
**	See LICENCE file for licence
**
*****************************************************************/
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h>
# include <time.h>
# include <assert.h>
# include <dirent.h>
# include <errno.h>	
# include <unistd.h>	
# include "config.h"
# include "zconf.h"
# include "debug.h"

# include "misc.h"
# include "zone.h"
# include "dki.h"
# include "zktr.h"
# include "log.h"
#define extern
# include "rollover.h"
#undef extern

/*****************************************************************
**	local function definition
*****************************************************************/

static	dki_t	*genkey (dki_t **listp, const char *dir, const char *domain, int ksk, const zconf_t *conf, int status)
{
	dki_t	*dkp;

	if ( listp == NULL || domain == NULL )
		return NULL;

	if ( ksk )
		dkp = dki_new (dir, domain, DKI_KSK, conf->k_algo, conf->k_bits, conf->k_random, conf->k_life / DAYSEC);
	else
		dkp = dki_new (dir, domain, DKI_ZSK, conf->z_algo, conf->z_bits, conf->z_random, conf->z_life / DAYSEC);
	dki_add (listp, dkp);
	dki_setstatus (dkp, status);

	return dkp;
}

static	time_t	get_exptime (dki_t *key, const zconf_t *z)
{
	time_t	exptime;

	exptime = dki_exptime (key);
	if ( exptime == 0L )
	{
		if ( dki_lifetime (key) )
			exptime = dki_time (key) + dki_lifetime (key);
		else
			exptime = dki_time (key) + z->k_life;
	}

	return exptime;
}

/*****************************************************************
**	global function definition
*****************************************************************/

/*****************************************************************
**	ksk5011status ()
**	Check if the list of zone keys contains a revoked or a
**	standby key.
**	Remove the revoked key if it is older than 30 days.
**	If the lifetime of the active key is reached do a rfc5011
**	keyrollover.
**	Returns an int with the rightmost bit set if a resigning
**	is required. The second rightmost bit is set if it is an
**	rfc5011 zone.
*****************************************************************/
int	ksk5011status (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*standbykey;
	dki_t	*activekey;
	dki_t	*dkp;
	dki_t	*prev;
	time_t	currtime;
	time_t	exptime;
	int	ret;

	assert ( listp != NULL );
	assert ( z != NULL );

	if ( z->k_life == 0 )
		return 0;

	verbmesg (1, z, "\tCheck RFC5011 status\n");

	ret = 0;
	currtime = time (NULL);

	/* go through the list of key signing keys,	*/
	/* remove revoked keys and set a pointer to standby and active key */
	standbykey = activekey = NULL;
	prev = NULL;
	for ( dkp = *listp; dkp && dki_isksk (dkp); dkp = dkp->next )
	{
		exptime = get_exptime (dkp, z);
		if ( dki_isrevoked (dkp) )
			lg_mesg (LG_DEBUG, "Rev Exptime: %s", time2str (exptime, 's'));

		/* revoked key is older than 30 days? */
		if ( dki_isrevoked (dkp) && currtime > exptime + (DAYSEC * 30) )
		{
			verbmesg (1, z, "\tRemove revoked key %d which is older than 30 days\n", dkp->tag);
			lg_mesg (LG_NOTICE, "zone \"%s\": removing revoked key %d", domain, dkp->tag);

			/* remove key from list and mark file as removed */
			if ( prev == NULL )		/* at the beginning of the list ? */
				*listp = dki_remove (dkp);
			else				/* anywhere in the middle of the list */
				prev->next = dki_remove (dkp);

			ret |= 01;		/* from now on a resigning is neccessary */
		}

		/* remember oldest standby and active key */
		if ( dki_status (dkp) == DKI_PUBLISHED )
			standbykey = dkp;
		if ( dki_status (dkp) == DKI_ACTIVE )
			activekey = dkp;
	}

	if ( standbykey == NULL && ret == 0 )	/* no standby key and also no revoked key found ? */
		return ret;				/* Seems that this is a non rfc5011 zone! */

	ret |= 02;		/* Zone looks like a rfc5011 zone */

	exptime = get_exptime (activekey, z);
#if 0
	lg_mesg (LG_DEBUG, "Act Exptime: %s", time2str (exptime, 's'));
	lg_mesg (LG_DEBUG, "Stb time: %s", time2str (dki_time (standbykey), 's'));
	lg_mesg (LG_DEBUG, "Stb time+wait: %s", time2str (dki_time (standbykey) + min (DAYSEC * 30, z->key_ttl), 's'));
#endif
	/* At the time we first introduce a standby key, the lifetime of the current KSK should not be expired, */
	/* otherwise we run into an (nearly) immediate key rollover!	*/
	if ( currtime > exptime && currtime > dki_time (standbykey) + min (DAYSEC * 30, z->key_ttl) )
	{
		lg_mesg (LG_NOTICE, "\"%s\": starting rfc5011 rollover", domain);
		verbmesg (1, z, "\tLifetime of Key Signing Key %d exceeded (%s): Starting rfc5011 rollover!\n",
							activekey->tag, str_delspace (age2str (dki_age (activekey, currtime))));
		verbmesg (2, z, "\t\t=>Generating new standby key signing key\n");
		dkp = genkey (listp, dir, domain, DKI_KSK, z, DKI_PUBLISHED);	/* gentime == now; lifetime = z->k_life; exp = 0 */
		if ( !dkp )
		{
			error ("\tcould not generate new standby KSK\n");
			lg_mesg (LG_ERROR, "\%s\": can't generate new standby KSK", domain);
		}

		/* standby key gets active  */
		verbmesg (2, z, "\t\t=>Activating old standby key %d \n", standbykey->tag);
		dki_setstatus (standbykey, DKI_ACT);

		/* active key should be revoked */ 
		verbmesg (2, z, "\t\t=>Revoking old active key %d \n", activekey->tag);
		dki_setstatus (activekey, DKI_REVOKED);	
		dki_setexptime (activekey, currtime);	/* now the key is expired */

		ret |= 01;		/* resigning neccessary */
	}

	return ret;
}

/*****************************************************************
**	kskstatus ()
**	Check the ksk status of a zone if a ksk lifetime is set.
**	If there is no key signing key present create a new one.
**	Prints out a warning message if the lifetime of the current
**	key signing key is over.
**	Returns 1 if a resigning of the zone is neccessary, otherwise
**	the function returns 0.
*****************************************************************/
int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*akey;
	time_t	lifetime;
	time_t	currtime;
	time_t	age;

	assert ( listp != NULL );
	assert ( z != NULL );

	if ( z->k_life == 0 )
		return 0;

	verbmesg (1, z, "\tCheck ksk status\n");
	/* check if a key signing key exist ? */
	akey = (dki_t *)dki_find (*listp, 1, 'a', 1);
	if ( akey == NULL )
	{
		verbmesg (1, z, "\tNo active KSK found: generate new one\n");
		akey = genkey (listp, dir, domain, DKI_KSK, z, DKI_ACTIVE);
		if ( !akey )
		{
			error ("\tcould not generate new KSK\n");
			lg_mesg (LG_ERROR, "\"%s\": can't generate new KSK: \"%s\"",
								domain, dki_geterrstr());
		}
		return akey != NULL;	/* return value of 1 forces a resigning of the zone */
	}
	/* check ksk lifetime */
	if ( (lifetime = dki_lifetime (akey)) == 0 )	/* if lifetime of key not set.. */
		lifetime = z->k_life;			/* ..use global configured lifetime */
	currtime = time (NULL);
	age = dki_age (akey, currtime);
	if ( lifetime > 0 && age > lifetime )
	{
		logmesg ("\t\tWarning: Lifetime of Key Signing Key %d exceeded: %s\n",
							akey->tag, str_delspace (age2str (age)));
		lg_mesg (LG_WARNING, "\"%s\": lifetime of key signing key %d exceeded since %s",
							domain, akey->tag, str_delspace (age2str (age - lifetime)));
	}

	return 0;
}

/*****************************************************************
**	zskstatus ()
**	Check the zsk status of a zone.
**	Returns 1 if a resigning of the zone is neccessary, otherwise
**	the function returns 0.
*****************************************************************/
int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z)
{
	dki_t	*akey;
	dki_t	*nextkey;
	dki_t	*dkp, *last;
	int	keychange;
	time_t	lifetime;
	time_t	age;
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
		if ( !dki_isksk (dkp) &&
		     dki_status (dkp) == DKI_DEPRECIATED && 
		     dki_age (dkp, currtime) > lifetime )
		{
			keychange = 1;
			verbmesg (1, z, "\tLifetime(%d sec) of depreciated key %d exceeded (%d sec)\n",
					 lifetime, dkp->tag, dki_age (dkp, currtime));
			dkp = dki_destroy (dkp);	/* delete the keyfiles */
			dbg_msg("zskstatus depreciated key removed ");
			if ( last )
				last->next = dkp;
			else
				*listp = dkp;
			verbmesg (1, z, "\t\t->remove it\n");
		}
		else
		{
			last = dkp;
			dkp = dkp->next;
		}

	/* check status of active key */
	dbg_msg("zskstatus check status of active key ");
	lifetime = z->z_life;			/* global configured lifetime for zsk */
	akey = (dki_t *)dki_find (*listp, 0, 'a', 1);
	if ( akey == NULL && lifetime > 0 )	/* no active key found */
	{
		verbmesg (1, z, "\tNo active ZSK found: generate new one\n");
		akey = genkey (listp, dir, domain, DKI_ZSK, z, DKI_ACTIVE);
	}
	else	/* active key exist */
	{
		if ( dki_lifetime (akey) )
			lifetime = dki_lifetime (akey);	/* set lifetime to lt of active key */

		/* lifetime of active key is expired and pre-publish key exist ? */
		age = dki_age (akey, currtime);
		if ( lifetime > 0 && age > lifetime - (OFFSET) )
		{
			const	char	*action = "";

			verbmesg (1, z, "\tLifetime(%d +/-%d sec) of active key %d exceeded (%d sec)\n",
					lifetime, (OFFSET) , akey->tag, dki_age (akey, currtime) );

			/* depreciate the key only if there is another active or pre-publish key */
			if ( (nextkey = (dki_t *)dki_find (*listp, 0, 'a', 2)) == NULL ||
			      nextkey == akey )
				nextkey = (dki_t *)dki_find (*listp, 0, 'p', 1);

			/* Is the pre-publish key sufficient long in the zone ? */
			/* As mentioned by Olaf, this should be the ttl of the DNSKEY RR ! */
			if ( nextkey && dki_age (nextkey, currtime) > z->key_ttl + z->proptime )
			{
				keychange = 1;
				verbmesg (1, z, "\t\t->depreciate it\n");
				dki_setstatus (akey, 'd');	/* depreciate the active key */
				akey = nextkey;
				verbmesg (1, z, "\t\t->activate pre-publish key %d\n", nextkey->tag);
				dki_setstatus (nextkey, 'a');	/* activate pre-published key */
				nextkey = NULL;
				action = "ZSK rollover done";
			}
			else
			{
				verbmesg (1, z, "\t\t->waiting for pre-publish key\n");
				action = "ZSK rollover deferred: waiting for pre-publish key";
			}
			lg_mesg (LG_NOTICE, "\"%s\": lifetime of zone signing key %d exceeded since %s: %s", domain, akey->tag,
										str_delspace (age2str (age - lifetime)), action);
		}
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
		verbmesg (1, z, "\tNew pre-publish key needed\n");
		nextkey = genkey (listp, dir, domain, DKI_ZSK, z, DKI_PUB);

		if ( nextkey )
			verbmesg (1, z, "\t\t->creating new pre-publish key %d\n", nextkey->tag);
		else
		{
			error ("\tcould not generate new ZSK: \"%s\"\n", dki_geterrstr());
			lg_mesg (LG_ERROR, "\"%s\": can't generate new ZSK: \"%s\"",
								domain, dki_geterrstr());
		}
	}
	return keychange;
}

