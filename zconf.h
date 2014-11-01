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
# define	MAX_TTL		(6 * HOURSEC)	/* default value of maximum ttl time */
# define	PROPTIME	(5 * MINSEC)	/* expected slave propagation time */
						/* should be small if notify is used  */
						/* otherwise same as SOA refresh interval */
#if defined (DEF_TTL)
# define	DEF_TTL		(MAX_TTL/2)
#endif

# define	RESIGN_INT	(SIG_VALIDITY / 10)
# define	KSK_LIFETIME	0	/* 360 Days ? */
# define	ZSK_LIFETIME	(SIG_VALIDITY / 3)

# define	KSK_ALGO	(DK_ALGO_DSA)
# define	KSK_BITS	(1024)
# define	ZSK_ALGO	(DK_ALGO_RSA)
# define	ZSK_BITS	(256)

# define	ZONEDIR		"."
# define	RECURSIVE	0
# define	ZONEFILE	"zone.db"
# define	DNSKEYFILE	"dnskey.db"
# define	LOOKASIDEDOMAIN	""	/* "trusted-keys.de" */

#ifndef CONFIGPATH
# define	CONFIGPATH	"/var/named/"
#endif
# define	CONFIGFILE	CONFIGPATH "dnssec.conf"
# define	LOCALCONFFILE	"dnssec.conf"

/* external command execution path (should be set via config.h) */
#ifndef BIND_UTIL_PATH
# define BIND_UTIL_PATH	"/usr/local/sbin/"	/* beware of trailing '/' */
#endif
# define	SIGNCMD		BIND_UTIL_PATH "dnssec-signzone -p"
# define	KEYGENCMD	BIND_UTIL_PATH "dnssec-keygen -r /dev/urandom "
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
	int	z_life;
	int	z_algo;
	int	z_bits;
	char	*keyfile;
	char	*zonefile;
	char	*lookaside;
} zconf_t;

extern	zconf_t	*loadconfig (char *filename, zconf_t *z);
extern	int	printconfig (const char *fname, const zconf_t *cp);

#endif
