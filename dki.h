/*****************************************************************
**
**	@(#) dki.h (c) July 2004 - Jan 2005 Holger Zuleger  hznet.de
**
**	Header file for DNSsec Key info/manipulation
**
*****************************************************************/
#ifndef DKI_H
# define DKI_H

# ifndef TYPES_H
#  include <sys/types.h>
#  include <stdio.h>
#  include <time.h>
# endif

#if !defined(HAS_UTYPES) || !HAS_UTYPES
typedef	unsigned long	ulong;
typedef	unsigned int	uint;
typedef	unsigned short	ushort;
typedef	unsigned char	uchar;
#endif

# define	MAX_LABELSIZE	(255)	
# define	MAX_FNAMESIZE	(1+255+2+3+1+5+1+11)
				/* Kdomain.+ALG+KEYID.type  */
				/* domain == FQDN (max 255) */
				/* ALG == 3; KEYID == 5 chars */
				/* type == key||published|private|depreciated == 11 chars */
//# define	MAX_DNAMESIZE	(254)
# define	MAX_DNAMESIZE	(1023)
				/*   /path/name  /   filename  */
# define	MAX_PATHSIZE	(MAX_DNAMESIZE + 1 + MAX_FNAMESIZE)

/* algorithm types */
# define	DK_ALGO_RSA	1	/* RFC2537 */
# define	DK_ALGO_DH	2	/* RFC2539 */
# define	DK_ALGO_DSA	3	/* RFC2536 (mandatory) */
# define	DK_ALGO_EC	4	/* */
# define	DK_ALGO_RSASHA1	5	/* RFC3110 */

/* protocol types */
# define	DK_PROTO_DNS	3

/* flag bits */
# define	DK_FLAG_ZONE	0400 (256 == 1 0000 0000)
# define	DK_FLAG_KSK	01

typedef	struct	dki {
	char	dname[MAX_DNAMESIZE+1];	/* directory */
	char	fname[MAX_FNAMESIZE+1];	/* file name without extension */
	char	name[MAX_LABELSIZE+1];	/* domain name or label */
	ushort	algo;			/* key algorithm */
	ushort	proto;			/* must be 3 (DNSSEC) */
	ushort	flags;			/* ZONE optional SEP Flag */
	time_t	time;			/* key (file) creation time */
	uint	tag;			/* key id */
	char	status;			/* key exist (".key") and name of private */
					/* key file is ".published", ".private" */
					/* or ".depreciated" */
	char	*pubkey;		/* base64 public key */
	struct	dki	*next;		/* ptr to next entry in list */
} dki_t;

/* status types */
# define	DKI_SEP	('s')
# define	DKI_PUB	('p')
# define	DKI_ACT	('a')
# define	DKI_DEP	('d')
# define	DKI_SECUREENTRYPOINT	DKI_SEP
# define	DKI_PUBLISHED	DKI_PUB
# define	DKI_ACTIVE	DKI_ACT
# define	DKI_DEPRECIATED	DKI_DEP	

# define	DKI_KEY_FILEEXT	".key"
# define	DKI_PUB_FILEEXT	".published"
# define	DKI_ACT_FILEEXT	".private"
# define	DKI_DEP_FILEEXT	".depreciated"

/* key type parameter */
# define	DKI_KSK	1
# define	DKI_ZSK	0

/*
 *	Instead of including <search.h>, which contains horrible false function
 *	declarations, we declared it for our usage (Yes, these functions return
 *	the adress of a pointer variable)
 */
#if defined(USE_TREE) && USE_TREE
typedef enum
{
	/* we change the naming to the new, and more predictive one, used by Knuth */
	PREORDER,	/* preorder,	*/
	INORDER,	/* postorder,	*/
	POSTORDER,	/* endorder,	*/
	LEAF		/* leaf		*/
}
VISIT;

dki_t	**tsearch (const dki_t *dkp, dki_t **tree, int(*compar)(const dki_t *, const dki_t *));
dki_t	**tfind (const dki_t *dkp, const dki_t **tree, int(*compar)(const dki_t *, const dki_t *));
dki_t	**tdelete (const dki_t *dkp, dki_t **tree, int(*compar)(const dki_t *, const dki_t *));
void	twalk (const dki_t *root, void (*action)(const dki_t **nodep, VISIT which, int depth));
#endif


#if defined(USE_TREE) && USE_TREE
extern	void	dki_tfree (dki_t **tree);
extern	dki_t	*dki_tadd (dki_t **tree, dki_t *new);
extern	int	dki_tagcmp (const dki_t *a, const dki_t *b);
extern	int	dki_namecmp (const dki_t *a, const dki_t *b);
extern	int	dki_allcmp (const dki_t *a, const dki_t *b);
#endif

extern	dki_t	*dki_read (const char *dir, const char *fname);
extern	int	dki_readdir (const char *dir, dki_t **listp, int recursive);
extern	int	dki_prt_trustedkey (const dki_t *dkp, FILE *fp);
extern	int	dki_prt_dnskey (const dki_t *dkp, FILE *fp);
extern	int	dki_prt_dnskeyttl (const dki_t *dkp, FILE *fp, int ttl);
extern	int	dki_prt_comment (const dki_t *dkp, FILE *fp);
extern	int	dki_cmp (const dki_t *a, const dki_t *b);
extern	int	dki_timecmp (const dki_t *a, const dki_t *b);
extern	int	dki_age (const dki_t *dkp, time_t curr);
extern	int	dki_status (const dki_t *dkp);
extern	const	char	*dki_statusstr (const dki_t *dkp);
extern	int	dki_isksk (const dki_t *dkp);
extern	int	dki_isdepreciated (const dki_t *dkp);
extern	int	dki_isactive (const dki_t *dkp);
extern	int	dki_ispublished (const dki_t *dkp);
extern	time_t	dki_time (const dki_t *dkp);
extern	dki_t	*dki_new (const char *dir, const char *name, int ksk, int algo, int bitsize, const char *rfile);
extern	dki_t	*dki_remove (dki_t *dkp);
extern	dki_t	*dki_destroy (dki_t *dkp);
extern	int	dki_setstatus (dki_t *dkp, int status);
extern	int	dki_setstatus_preservetime (dki_t *dkp, int status);
#if 0
extern	int	dki_depreciate (dki_t *dkp);
extern	int	dki_activate (dki_t *dkp);
#endif
extern	dki_t	*dki_add (dki_t **dkp, dki_t *new);
extern	const dki_t	*dki_tsearch (const dki_t *tree, int tag, const char *name);
extern	const dki_t	*dki_search (const dki_t *list, int tag, const char *name);
extern	const dki_t	*dki_find (const dki_t *list, int ksk, int status, int first);
extern	void	dki_free (dki_t *dkp);
extern	void	dki_freelist (dki_t **listp);
extern	char	*dki_algo2str (int algo);
extern	const char	*dki_geterrstr (void);


#endif
