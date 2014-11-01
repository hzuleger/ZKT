/*****************************************************************
**
**	@(#) strlist.c (c) Mar 2005  Holger Zuleger
**
*****************************************************************/

#ifdef TEST
# include <stdio.h>
#endif
#include <string.h>
#include <stdlib.h>
#include "strlist.h"


/*****************************************************************
**	prepare str list
**	String is a list of substrings delimeted by LISTDELIM
**	The function returns a pointer to a dynamic allocated memory
**	which looks like
**	|2ZZ
*****************************************************************/
char	*prepstrlist (const char *str)
{
	char	*p;
	char	*new;
	int	len;
	int	cnt;

	if ( str == NULL )
		return NULL;

	len = strlen (str);
	if ( (new = malloc (len + 2)) == NULL )
		return new;

	cnt = 0;
	p = new;
	for ( *p++ = '\0'; *str; str++ )
	{
		if ( strchr (LISTDELIM, *str) == NULL )
			*p++ = *str;
		else if ( p[-1] != '\0' )
		{
			*p++ = '\0';
			cnt++;
		}
	}
	if ( p[-1] != '\0' )
		cnt++;
	*new = cnt & 0xFF;

	return new;
}

int	isinlist (const char *str, const char *list)
{
	int	cnt;

	if ( list == NULL || *list == '\0' )
		return 1;
	if ( str == NULL || *str == '\0' )
		return 0;

	cnt = *list;
	while ( cnt-- > 0 )
	{
		list++;
		if ( strcmp (str, list) == 0 )
			return 1;
		list += strlen (list);
	}

	return 0;
}

char	*unprepstrlist (char *list)
{
	char	*p;
	int	cnt;

	cnt = *list;
	p = list;
	for ( *p++ = ' '; cnt > 0; p++ )
		if ( *p == '\0' )
		{
			*p = ' ';
			cnt--;
		}

	return list;
}

#ifdef TEST
main (int argc, char *argv[])
{
	FILE	*fp;
	char	*p;
	char	*searchlist = NULL;
	char	group[255];

	if ( argc > 1 )
		searchlist = prepstrlist (argv[1]);

	printf ("searchlist: %d entrys: \n", searchlist[0]);
	if ( (fp = fopen ("/etc/group", "r")) == NULL )
		exit (fprintf (stderr, "can't open file\n"));

	while ( fscanf (fp, "%[^:]:%*[^\n]\n", group) != EOF )
		if ( isinlist (group, searchlist) )
			printf ("%s\n", group);

	fclose (fp);

	printf ("searchlist: \"%s\"\n", unprepstrlist  (searchlist));
	for ( p = searchlist; *p; p++ )
		if ( *p < 32 )
			printf ("<%d>", *p);
		else
			printf ("%c", *p);
	printf ("\n");
}
#endif
