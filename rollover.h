/*****************************************************************
**
**	@(#) rollover.h  (c) 2005 - 2008  Holger Zuleger  hznet.de
**
**	Copyright (c) 2005 - 2008, Holger Zuleger HZnet. All rights reserved.
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
#ifndef ROLLOVER_H
# define ROLLOVER_H

# define	OFFSET			((int) (2.5 * MINSEC))
# define	PARENT_PROPAGATION	(5 * MINSEC)
# define	ADD_HOLD_DOWN		(30 * DAYSEC)
# define	REMOVE_HOLD_DOWN	(30 * DAYSEC)

extern	int	ksk5011status (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
extern	int	kskstatus (zone_t *zonelist, zone_t *zp);
extern	int	zskstatus (dki_t **listp, const char *dir, const char *domain, const zconf_t *z);
#endif
