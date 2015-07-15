/*****************************************************************
**
**	readkeyfile.h
**
*****************************************************************/
#ifndef READKEYFILE_H
# define READKEYFILE_H

typedef struct	{
	char	name[255+1];
	char	algo[31+1];
	char	secret[127+1];
} tsigkey_t;

extern	int	readkeyfile (const char *fname, tsigkey_t *k, const char *lookupkey);

#endif
