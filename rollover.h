/*****************************************************************
**	@(#) rollover.h  (c) 2005 - 2008  Holger Zuleger  hznet.de
*****************************************************************/
#ifndef ROLLOVER_H
# define ROLLOVER_H
# include <sys/types.h>
# include <stdarg.h>
# include <stdio.h>

#ifndef ZCONF_H
# include "zconf.h"
#endif

# define	OFFSET	((int) (2.5 * MINSEC))

extern	int	ksk5011status (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
extern	int	kskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
extern	int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
#endif
