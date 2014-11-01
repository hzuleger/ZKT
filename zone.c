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
	if ( zp->sfile ) free ((char *)zp->sfile);
#if 0
	/* TODO: actually there are some problems freeing the config :-( */
	if ( zp->conf ) free ((zconf_t *)zp->conf);
#endif
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
**	allocate memory for new zone structure and initialize it
*****************************************************************/
zone_t	*zone_new (zone_t **zp, const char *zone, const char *dir, const char *file, const char *signed_ext, const zconf_t *cp)
{
	char	path[MAX_PATHSIZE+1];
	zone_t	*new;

	assert (zp != NULL);
	assert (zone != NULL && *zone != '\0');

	dbg_val3 ("zone_new: (zp, zone: %s, dir: %s, file: %s, cp)\n", zone, dir, file);
	if ( dir == NULL || *dir == '\0' )
		dir = ".";

	if ( file == NULL || *file == '\0' )
		file = cp->zonefile;
	else
	{	/* check if file contains a path */
		const	char	*p;
		if ( (p = strrchr (file, '/')) != NULL )
		{
			snprintf (path, sizeof (path), "%s/%.*s", dir, p-file, file);
			dir = path;
			file = p+1;
		}
	}

	if ( (new = zone_alloc ()) != NULL )
	{
		char	*p;

		new->zone = strdup (zone);
		new->dir = strdup (dir);
		new->file = strdup (file);
		/* check if file ends with ".signed" ? */
		if ( (p = strrchr (new->file, '.')) != NULL && strcmp (p, signed_ext) == 0 )
		{
			new->sfile = strdup (new->file);
			*p = '\0';
		}
		else
		{
			snprintf (path, sizeof (path), "%s%s", file, signed_ext);
			new->sfile = strdup (path);
		}
		new->conf = cp;
		new->keys = NULL;
		dki_readdir (new->dir, &new->keys, 0);
		new->next = NULL;
	}
	
	return zone_add (zp, new);
}

/*****************************************************************
**	zone_readdir ()
*****************************************************************/
int	zone_readdir (const char *dir, const char *zone, const char *zfile, zone_t **listp, const zconf_t *conf, int dyn_zone)
{
	char	*p;
	zconf_t	*localconf;
	char	path[MAX_PATHSIZE+1];
	char	*signed_ext = ".signed";

	assert (dir != NULL && *dir != '\0');
	assert (conf != NULL);

	if ( zone == NULL )	/* zone not given ? */
		if ( (zone = strrchr (dir, '/')) )	/* try to extract zone name out of directory */
			zone++;
		else
			zone = dir;
	dbg_val4 ("zone_readdir: (dir: %s, zone: %s, zfile: %s zp, cp, dyn_zone = %d)\n",
					dir, zone, zfile ? zfile: "NULL", dyn_zone);

	if ( dyn_zone )
		signed_ext = ".dsigned";

	if ( zfile && (p = strrchr (zfile, '/')) )	/* check if zfile contains a directory */
	{	
		char	subdir[MAX_PATHSIZE+1];

		snprintf (subdir, sizeof (subdir), "%s/%.*s", dir, p - zfile, zfile);
		pathname (path, sizeof (path), subdir, LOCALCONF_FILE, NULL);
	}
	else
		pathname (path, sizeof (path), dir, LOCALCONF_FILE, NULL);
	dbg_val1 ("zone_readdir: check local config file %s\n", path);
	if ( fileexist (path) )			/* load local config file */
	{
		localconf = loadconfig (NULL, NULL);
		memcpy (localconf, conf, sizeof (zconf_t));
		conf = loadconfig (path, localconf);
	}

	if ( zfile == NULL )
	{
		zfile = conf->zonefile;
		pathname (path, sizeof (path), dir, zfile, signed_ext);
	}
	else
	{
		dbg_val2("zone_readdir: add %s to zonefile if not already there ? (%s)\n", signed_ext, zfile);
		if ( (p = strrchr (zfile, '.')) == NULL || strcmp (p, signed_ext) != 0 )
			pathname (path, sizeof (path), dir, zfile, signed_ext);
		else
			pathname (path, sizeof (path), dir, zfile, NULL);
	}

	dbg_val1("zone_readdir: fileexist (%s): ", path);
	if ( !fileexist (path) )	/* no .signed file found ? ... */
	{
		dbg_val0("no!\n");
		return 0;		/* ... not a secure zone ! */
	}
	dbg_val0("yes!\n");

	dbg_val("zone_readdir: add zone (%s)\n", zone);
	zone_new (listp, zone, dir, zfile, signed_ext, conf);

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

/*****************************************************************
**	zone_print ()
*****************************************************************/
int	zone_print (const char *mesg, const zone_t *z)
{
	dki_t	*dkp;

	if ( !z )
		return 0;
	fprintf (stderr, "%s: zone\t %s\n", mesg, z->zone);
	fprintf (stderr, "%s: dir\t %s\n", mesg, z->dir);
	fprintf (stderr, "%s: file\t %s\n", mesg, z->file);
	fprintf (stderr, "%s: sfile\t %s\n", mesg, z->sfile);

	for ( dkp = z->keys; dkp; dkp = dkp->next )
        {
                dki_prt_comment (dkp, stderr);
        }

	return 1;
}
