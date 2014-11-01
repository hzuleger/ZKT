/*****************************************************************
**
**	@(#) debug.h -- macros for debug messages
**
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
#  define	dbg_val0(text)	fprintf (stderr, "DBG: %s(%d) %s", __FILE__, __LINE__, text)
#  define	dbg_val1(fmt, var)	dbg_val (fmt, var)
#  define	dbg_val(fmt, var)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, var)
#  define	dbg_val2(fmt, v1, v2)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, v1, v2)
#  define	dbg_val3(fmt, v1, v2, v3)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, v1, v2, v3)
#  define	dbg_val4(fmt, v1, v2, v3, v4)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, v1, v2, v3, v4)
#  define	dbg_val5(fmt, v1, v2, v3, v4, v5)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, v1, v2, v3, v4, v5)
#  define	dbg_val6(fmt, v1, v2, v3, v4, v5, v6)	fprintf (stderr, "DBG: %s(%d) " fmt, __FILE__, __LINE__, v1, v2, v3, v4, v5, v6)
# else
#  define	dbg_line()
#  define	dbg_msg(msg)
#  define	dbg_val0(text)
#  define	dbg_val1(fmt, var)
#  define	dbg_val(fmt, str)
#  define	dbg_val2(fmt, v1, v2)
#  define	dbg_val3(fmt, v1, v2, v3)
#  define	dbg_val4(fmt, v1, v2, v3, v4)
#  define	dbg_val5(fmt, v1, v2, v3, v4, v5)
#  define	dbg_val6(fmt, v1, v2, v3, v4, v5, v6)
# endif

#endif
