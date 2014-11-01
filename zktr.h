/*****************************************************************
**
**	@(#) zktr.h
**
*****************************************************************/
#ifndef ZKTR_H
# define ZKTR_H

# define	MAGIC		"ZKTR"
# define	PORT		5327
# define	PORT_STR	"5327"

# define	VERSION_01	1
# define	VERSION_01_STR	"0.1"

# define	MAGICv01	MAGIC "v" VERSION_01_STR
			//	ZKTRv0.1 d=domain.name t=12345 a=5 T=12345678o12
# define	BUFSIZE_01	(  8 +  1   + 254+2  +1+  7  +1+3+1+    12+2   +1	)
# define	MAX_BUFSIZE	(BUFSIZE_01 * 2)

typedef	struct Zktr01 {
	char	domain[255+1];	// fqdn
	ushort	tag;		// Key tag
	ushort	alg;		// Algorithm No
	time_t	epoch;		// local time
} zktr01_t;

typedef	struct Zktr {
	// char	magicstr[7+1];
	ushort	version;
	union {
		zktr01_t	zr_01;
# define	zr_01	u.zr_01
	//	zktr02_t	zr_02;
// # define	zr_02	u.zr_02
	} u;
} zktr_t;

extern	int	zktr2buf (const zktr_t *z, char *buf, int len);
extern	int	buf2zktr (zktr_t *z, const char *buf, int len);
extern	int	send_zktr_v01 (int fd, const char *domain, int tag, int algo, time_t epoch);
extern	int	zktr_socket (const char *host, const char *service, int af);
#endif
