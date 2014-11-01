/*****************************************************************
**
**	@(#) zktrc.c
**
*****************************************************************/
# include <sys/types.h>
# include <sys/socket.h>	/* socket() ... */
# include <sys/select.h>	/* select() ... */
# include <netdb.h>		/* getaddrinfo(), getnameinfo(), etc. */
# include <stdio.h>
# include <time.h>
# include <assert.h>
# include "zktr.h"

static	char	*cmd2buf (char cmd, char *buf, int *plen)
{
	if ( *plen < 4 )
		return NULL;

	*buf++ = 'c'; *buf++ = '=';
	*buf++ = cmd; *buf++ = ' ';
	*plen -= 4;

	return buf;
}

static	char	*alg2buf (char alg, char *buf, int *plen)
{
	if ( *plen < 4 )
		return NULL;

	*buf++ = 'a'; *buf++ = '=';
	*buf++ = alg + '0'; *buf++ = ' ';
	*plen -= 4;

	return buf;
}

static	char	*tag2buf (ushort tag, char *buf, int *plen)
{
	int	i;

	if ( *plen < 7 )
		return NULL;

	i = snprintf (buf, *plen, "t=%05.5d ", tag);
	*plen -= i;

	return buf + i;
}

static	char	*domain2buf (const char *domain, char *buf, int *plen)
{
	int	len;

	len = strlen (domain);
	if ( *plen < len )
		return NULL;

	len = snprintf (buf, *plen, "d=%.254s ", domain);
	*plen -= len;

	return buf + len;
}

static	char	*time2buf (time_t time, char *buf, int *plen)
{
	int	len;

	if ( *plen < 12 )
		return NULL;

	len = snprintf (buf, *plen, "T=%lu ", time);
	*plen -= len;

	return buf + len;
}

int	zktr2buf (const zktr_t *z, char *buf, int len)
{
	char	*p;
	int	n;

	assert ( z != NULL );
	assert ( buf != NULL );

	n = len;
	p = buf;
	p += snprintf (p, n, "%sv%1.1d.%1.1d ", MAGIC, z->version / 10, z->version % 10);
	len -= strlen (MAGIC) + 4;
	switch ( z->version )
	{
	case VERSION_01:
		if ( (p = domain2buf (z->zr_01.domain, p, &len)) == NULL )
			return -1;
		if ( (p = tag2buf (z->zr_01.tag, p, &len)) == NULL )
			return -1;
		if ( (p = alg2buf (z->zr_01.alg, p, &len)) == NULL )
			return -1;
		if ( (p = time2buf (z->zr_01.epoch, p, &len)) == NULL )
			return -1;
		*p = '\0';
		return n - len;
	break;
	}
}

int	zktr_socket (const char *host, const char *service, int af)
{
	struct	addrinfo	hints;
	struct	addrinfo	*ai;	/* linked list of ai records */
	struct	addrinfo	*ap;	/* ai pointer */
	char	hbuf[NI_MAXHOST];
	char	sbuf[NI_MAXSERV];
	int	err;
	int	sfd;

	assert (host != NULL);
		assert (service != NULL);

		memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;		/* AF_INET or AF_INET6 or AF_UNSPEC */
	hints.ai_socktype = SOCK_DGRAM;		/* UDP socket */
	// hints.ai_flags = AI_NUMERICHOST;	/* Client port */

	if ( (err = getaddrinfo (host, service, &hints, &ai)) != 0 )
		return -2;

	ap = ai;
	do
	{
		/* Try to create socket of specified type, family and protocol */
		sfd = socket (ap->ai_family, ap->ai_socktype, ap->ai_protocol);
		if ( sfd >= 0 )
		{
			if ( connect (sfd, ap->ai_addr, ap->ai_addrlen) == 0 )
				break;			/* yeah, we got one */

			close (sfd);	/* free this, try next one */
		}
	} while ( (ap = ap->ai_next) != NULL );

	freeaddrinfo (ai);

	return (ap == NULL) ? -1 : sfd;
}

int	send_zktr_v01 (int fd, const char *domain, int tag, int algo, time_t epoch)
{
	char msg[BUFSIZE_01];
	zktr_t	z;
	int	n;

	z.version = VERSION_01;
	z.zr_01.tag = tag;
	strncpy (z.zr_01.domain, domain, sizeof (z.zr_01.domain));
	z.zr_01.epoch = epoch;
	z.zr_01.alg = algo;

	if ( (n = zktr2buf (&z, msg, sizeof (msg))) >= 0 )
	{
#if 0
		fprintf (stderr, "send %d bytes\n", n);
		fprintf (stderr, "\"%.*s\"", n, msg);
#endif
		n = send (fd, msg, n, 0);
	}
	return n;
}
