/*****************************************************************
**
**	@(#) zone.c  (c) Mar 2005  Holger Zuleger  hznet.de
**
**	See LICENCE file for licence
**
*****************************************************************/

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <dirent.h>
# include <assert.h>
# include "config.h"
# include "debug.h"
# include "misc.h"
# include "zconf.h"
# include "dki.h"
#define	extern
# include "zone.h"
#undef	extern

/*****************************************************************
**	private (static) function declaration and definition
*****************************************************************/
static	char	zone_estr[255+1];

static	zone_t	*zone_alloc ()
{
	zone_t	*zp = malloc (sizeof (zone_t));

	if ( (zp = malloc (sizeof (zone_t))) )
	{
		memset (zp, 0, sizeof (zone_t));
		return zp;
	}

	snprintf (zone_estr, sizeof (zone_estr),
			"zone_alloc: Out of memory");
	return NULL;
}

/*****************************************************************
**	public function definition
*****************************************************************/

/*****************************************************************
**	zone_free ()
*****************************************************************/
void	zone_free (zone_t *zp)
{
	assert (zp != NULL);

	if ( zp->zone ) free ((char *)zp->zone);
	if ( zp->dir ) free ((char *)zp->dir);
	if ( zp->file ) free ((char *)zp->file);
	if ( zp->conf ) free ((zconf_t *)zp->conf);
	if ( zp->keys ) dki_freelist (&zp->keys);
	free (zp);
}

/*****************************************************************
**	zone_freelist ()
*****************************************************************/
void	zone_freelist (zone_t **listp)
{
	zone_t	*curr;
	zone_t	*next;

	assert (listp != NULL);

	curr = *listp;
	while ( curr )
	{
		next = curr->next;
		zone_free (curr);
		curr = next;
	}
	if ( *listp )
		*listp = NULL;
}

/*****************************************************************
**	zone_new ()
**	create new keyfile
**	allocate memory for new zone key and init with keyfile
*****************************************************************/
zone_t	*zone_new (zone_t **zp, const char *zone, const char *dir, const char *file, const zconf_t *cp)
{
	char	path[MAX_PATHSIZE+1];
	zone_t	*new;

	assert (zp != NULL);
	assert (zone != NULL && *zone != '\0');

	dbg_val ("zone_new: (zp, %s, ... cp)\n", zone);
	if ( dir == NULL || *dir == '\0' )
		dir = ".";

	if ( file == NULL || *file == '\0' )
	{
		snprintf (path, sizeof (path), "%s.signed", cp->zonefile);
		file = path;
	}
	else
	{	/* check if file contains path */
		const	char	*p;
		if ( (p = strrchr (file, '/')) != NULL )
		{
			snprintf (path, sizeof (path), "%s/%.*s", dir, p-file, file);
			dir = path;
			file = p+1;
		}
	}

	if ( (new = malloc (sizeof (zone_t))) != NULL )
	{
		new->zone = strdup (zone);
		new->dir = strdup (dir);
		new->file = strdup (file);
		new->conf = cp;
		new->keys = NULL;
		dki_readdir (dir, &new->keys, 0);
		new->next = NULL;
	}
	
	return zone_add (zp, new);
}

/*****************************************************************
**	zone_readdir ()
*****************************************************************/
int	zone_readdir (const char *dir, zone_t **listp, const zconf_t *conf, const char *searchlist)
{
	zconf_t	*localconf;
	char	path[MAX_PATHSIZE+1];
	const char	*zone;

	assert (dir != NULL && *dir != '\0');
	assert (conf != NULL);

	/* try to extract key from directory name */
	if ( (zone = strrchr (dir, '/')) )
		zone++;
	else
		zone = dir;

	if ( !isinlist (zone, searchlist) )
		return 0;

	dbg_val ("zone_readdir: (%s, zp, cp)\n", dir ? dir: "NULL");
	pathname (path, sizeof (path), dir, LOCALCONFFILE, NULL);
	if ( fileexist (path) )			/* load local config file */
	{
		localconf = loadconfig (NULL, NULL);
		memcpy (localconf, conf, sizeof (zconf_t));
		conf = loadconfig (path, localconf);
	}

	pathname (path, sizeof (path), dir, conf->zonefile, ".signed");
	dbg_val("parsedirectory fileexist (%s)\n", path);
	if ( !fileexist (path) )	/* no .signed file found ? ... */
		return 0;		/* ... not a secure zone ! */

	zone_new (listp, zone, dir, conf->zonefile, conf);

	return 1;
}



/*****************************************************************
**	zone_geterrstr ()
**	return error string 
*****************************************************************/
const	char	*zone_geterrstr ()
{
	return zone_estr;
}

/*****************************************************************
**	zone_cmp () 	return <0 | 0 | >0
*****************************************************************/
int	zone_cmp (const zone_t *a, const zone_t *b)
{
	if ( a == NULL ) return -1;
	if ( b == NULL ) return 1;

	return domaincmp (a->zone, b->zone);
}

/*****************************************************************
**	zone_add ()
*****************************************************************/
zone_t	*zone_add (zone_t **list, zone_t *new)
{
	zone_t	*curr;
	zone_t	*last;

	if ( list == NULL )
		return NULL;
	if ( new == NULL )
		return *list;

	last = curr = *list;
	while ( curr && zone_cmp (curr, new) < 0 )
	{
		last = curr;
		curr = curr->next;
	}

	if ( curr == *list )	/* add node at start of list */
		*list = new;
	else			/* add node at end or between two nodes */
		last->next = new;
	new->next = curr;
	
	return new;
}

/*****************************************************************
**	zone_search ()
*****************************************************************/
const zone_t	*zone_search (const zone_t *list, const char *zone)
{
	if ( zone == NULL || *zone == '\0' )
		return NULL;

	while ( list && strcmp (zone, list->zone) != 0 )
		list = list->next;

	return list;
}
