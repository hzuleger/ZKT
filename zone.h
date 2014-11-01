/*****************************************************************
**
**	@(#) zone.h (c) Mar 2005 Holger Zuleger  hznet.de
**
**	Header file for zone info
**
*****************************************************************/
#ifndef ZONE_H
# define ZONE_H

# include <sys/types.h>
# include <stdio.h>
# include <time.h>
# include "dki.h"

/* all we have to know about a zone */
typedef	struct	Zone {
	const	char	*zone;	/* domain name or label */
	const	char	*dir;	/* directory of zone data */
	const	char	*file;	/* file name (zone.db)  */
	const	char	*sfile;	/* file name of secured zone (zone.db.signed)  */
	const	zconf_t	*conf;	/* ptr to config */	/* TODO: Should this be only a ptr to a local config ? */
		dki_t	*keys;	/* ptr to keylist */
	struct	Zone	*next;		/* ptr to next entry in list */
} zone_t;

extern	void	zone_free (zone_t *zp);
extern	void	zone_freelist (zone_t **listp);
extern	zone_t	*zone_new (zone_t **zp, const char *zone, const char *dir, const char *file, const char *signed_ext, const zconf_t *cp);
extern	const	char	*zone_geterrstr ();
extern	int	zone_cmp (const zone_t *a, const zone_t *b);
extern	zone_t	*zone_add (zone_t **list, zone_t *new);
extern	const zone_t	*zone_search (const zone_t *list, const char *name);
extern	int	zone_readdir (const char *dir, const char *zone, const char *zfile, zone_t **listp, const zconf_t *conf, int dyn_zone);
extern	const	char	*zone_geterrstr (void);
extern	int	zone_print (const char *mesg, const zone_t *z);

#endif
