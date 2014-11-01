/*****************************************************************
**
**	@(#) debug.h -- macros for debug messages
**	(c) Jan 2005  Holger Zuleger  hznet.de
**	
**	compile with cc -DDBG to activate
**
*****************************************************************/
#ifndef DEBUG_H
# define DEBUG_H

# ifdef DBG
#  define	dbg_line()	fprintf (stderr, "DBG: %s(%d) reached\n", __FILE__, __LINE__)
#  define	dbg_msg(msg)	fprintf (stderr, "DBG: %s(%d) %s\n", __FILE__, __LINE__, msg)
#  define	dbg_val(fmt, var)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, var)
# else
#  define	dbg_line()
#  define	dbg_msg(msg)
#  define	dbg_val(fmt, str)
# endif

#endif
