/*****************************************************************
**
**	@(#) strlist.c (c) Mar 2005  Holger Zuleger
**
**	TODO:	Maybe we should use a special type for the list:
**		typedef struct { char cnt; char list[0+1]; } strlist__t;
**		This results in better type control of the function parameters
**
*****************************************************************/

#ifdef TEST
# include <stdio.h>
#endif
#include <string.h>
#include <stdlib.h>
#include "strlist.h"


/*****************************************************************
**	prepstrlist (str, delim)
**	prepare a string with delimeters to a so called strlist.
**	'str' is a list of substrings delimeted by 'delim'
**	The # of strings is stored at the first byte of the allocated
**	memory. Every substring is stored as a '\0' terminated C-String.
**	The function returns a pointer to dynamic allocated memory
*****************************************************************/
char	*prepstrlist (const char *str, const char *delim)
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
		if ( strchr (delim, *str) == NULL )
			*p++ = *str;
		else if ( p[-1] != '\0' )
		{
			*p++ = '\0';
			cnt++;
		}
	}
	*p = '\0';	/*terminate string */
	if ( p[-1] != '\0' )
		cnt++;
	*new = cnt & 0xFF;

	return new;
}

/*****************************************************************
**	isinlist (str, list)
**	check if 'list' contains 'str'
*****************************************************************/
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

/*****************************************************************
**	unprepstrlist (list, delimc)
*****************************************************************/
char	*unprepstrlist (char *list, char delimc)
{
	char	*p;
	int	cnt;

	cnt = *list & 0xFF;
	p = list;
	for ( *p++ = delimc; cnt > 1; p++ )
		if ( *p == '\0' )
		{
			*p = delimc;
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
		searchlist = prepstrlist (argv[1], LISTDELIM);

	printf ("searchlist: %d entrys: \n", searchlist[0]);
	if ( (fp = fopen ("/etc/group", "r")) == NULL )
		exit (fprintf (stderr, "can't open file\n"));

	while ( fscanf (fp, "%[^:]:%*[^\n]\n", group) != EOF )
		if ( isinlist (group, searchlist) )
			printf ("%s\n", group);

	fclose (fp);

	printf ("searchlist: \"%s\"\n", unprepstrlist  (searchlist, *LISTDELIM));
	for ( p = searchlist; *p; p++ )
		if ( *p < 32 )
			printf ("<%d>", *p);
		else
			printf ("%c", *p);
	printf ("\n");
}
#endif
