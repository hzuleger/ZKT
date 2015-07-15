/*****************************************************************
**
**	@(#) misc.h  (c) 2005 - 2007  Holger Zuleger  hznet.de
**
**	Copyright (c) 2005 - 2007, Holger Zuleger HZnet. All rights reserved.
**
**	This software is open source.
**
**	Redistribution and use in source and binary forms, with or without
**	modification, are permitted provided that the following conditions
**	are met:
**
**	Redistributions of source code must retain the above copyright notice,
**	this list of conditions and the following disclaimer.
**
**	Redistributions in binary form must reproduce the above copyright notice,
**	this list of conditions and the following disclaimer in the documentation
**	and/or other materials provided with the distribution.
**
**	Neither the name of Holger Zuleger HZnet nor the names of its contributors may
**	be used to endorse or promote products derived from this software without
**	specific prior written permission.
**
**	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
**	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
**	TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
**	PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
**	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
**	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
**	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
**	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
**	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
**	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
**	POSSIBILITY OF SUCH DAMAGE.
**
*****************************************************************/
#ifndef MISC_H
# define MISC_H
# include <sys/types.h>
# include <stdarg.h>
# include <stdio.h>

#ifndef PATH_MAX
# define PATH_MAX	4096
#endif

# define	MINSEC(x)	((x) * 60)
# define	HOURSEC(x)	(MINSEC(x) * 60)
# define	DAYSEC(x)	(HOURSEC(x) * 24)
# define	WEEKSEC(x)	(DAYSEC(x) * 7)

#ifndef ulong
typedef	unsigned long	ulong;
#endif

extern	int	ttltostr (char *s, size_t size, ulong ttl);
extern	ulong	ttlfromstr (const char *s);
extern	char	*str_delspace (char *s);
extern	int	in_strarr (const char *str, char *const arr[], int cnt);
extern	const char	*skipdelim (const char *line, int delim);
extern	void    error (char *fmt, ...);
extern	void    fatal (char *fmt, ...);
extern	void    logmesg (char *fmt, ...);
extern	void	verbmesg (int verblvl, char *fmt, ...);
extern	void	logflush (void);
extern	char	*str_untaint (char *str);
extern	char	*str_chop (char *str, char c);
extern	int	is_ipv4addr (const char *ipaddrstr);
extern	int	is_ipv6addr (const char *ipaddrstr);
#endif
