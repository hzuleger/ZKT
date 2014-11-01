/*****************************************************************
**
**	@(#) strlist.h (c) Mar 2005  Holger Zuleger
**
*****************************************************************/

#ifndef STRLIST_H
# define STRLIST_H

# define	LISTDELIM	" ,:;|^\t"

char	*prepstrlist (const char *str, const char *delim);
int	isinlist (const char *str, const char *list);
char	*unprepstrlist (char *list, char delimc);
#endif
