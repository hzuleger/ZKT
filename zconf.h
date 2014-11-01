/*****************************************************************
**	@(#) zconf.h  (c)  Jan 2005  Holger Zuleger  hznet.de
*****************************************************************/
#ifndef ZCONF_H
# define ZCONF_H


# define	MINSEC	60
# define	HOURSEC	(MINSEC * 60)
# define	DAYSEC	(HOURSEC * 24)
# define	WEEKSEC	(DAYSEC * 7)
# define	YEARSEC	(DAYSEC * 365)
# define	DAY	(1)
# define	WEEK	(DAY * 7)
# define	MONTH	(DAY * 30)
# define	YEAR	(DAY * 365)

# define	SIG_VALIDITY	(30 * DAYSEC)
# define	MAX_TTL		( 6 * HOURSEC)	/* default value of maximum ttl time */
# define	PROPTIME	( 5 * MINSEC)	/* expected slave propagation time */
						/* should be small if notify is used  */
#if defined (DEF_TTL)
# define	DEF_TTL		(MAX_TTL/2)	/* currently not used */
#endif

# define	RESIGN_INT	(SIG_VALIDITY / 10)
# define	KSK_LIFETIME	0	/* 360 Days ? */
# define	ZSK_LIFETIME	(SIG_VALIDITY / 3)

# define	KSK_ALGO	(DK_ALGO_RSASHA1)
# define	KSK_BITS	(1024)
# define	KSK_RANDOM	NULL	/* "/dev/random" */
# define	ZSK_ALGO	(DK_ALGO_RSASHA1)
# define	ZSK_BITS	(512)
# define	ZSK_RANDOM	"/dev/urandom"

# define	ZONEDIR		"."
# define	KEYSETDIR	NULL	/* keysets */
# define	RECURSIVE	0
# define	ZONEFILE	"zone.db"
# define	DNSKEYFILE	"dnskey.db"
# define	LOOKASIDEDOMAIN	""	/* "trusted-keys.de" */
# define	SIG_RANDOM	NULL	/* "/dev/urandom" */
# define	SIG_PSEUDO	1

#ifndef CONFIG_PATH
# define	CONFIG_PATH	"/var/named/"
#endif
# define	CONFIG_FILE	CONFIG_PATH "dnssec.conf"
# define	LOCALCONF_FILE	"dnssec.conf"

/* external command execution path (should be set via config.h) */
#ifndef BIND_UTIL_PATH
# define BIND_UTIL_PATH	"/usr/local/sbin/"	/* beware of trailing '/' */
#endif
# define	SIGNCMD		BIND_UTIL_PATH "dnssec-signzone"
# define	KEYGENCMD	BIND_UTIL_PATH "dnssec-keygen"
# define	RELOADCMD	BIND_UTIL_PATH "rndc"

typedef	struct zconf	{
	char	*zonedir;
	int	recursive;
	int	printtime;
	int	printage;
	int	sigvalidity;	/* should be less than expire time */
	int	max_ttl;	/* should be set to the maximum used ttl in the zone */
	int	proptime;	/* expected time offset for zone propagation */
#if defined (DEF_TTL)
	int	def_ttl;	/* default ttl set in soa record  */
#endif
	int	resign;		/* resign interval */
	int	k_life;
	int	k_algo;
	int	k_bits;
	char	*k_random;
	int	z_life;
	int	z_algo;
	int	z_bits;
	char	*z_random;
	char	*keyfile;
	char	*zonefile;
	char	*keysetdir;
	char	*lookaside;
	char	*sig_random;
	int	sig_pseudo;
} zconf_t;

extern	zconf_t	*loadconfig (char *filename, zconf_t *z);
extern	int	printconfig (const char *fname, const zconf_t *cp);
extern	int	checkconfig (const zconf_t *z);

#endif
