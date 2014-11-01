#################################################################
#
#	@(#) Makefile for dnssec zone key tool  (c) Mar 2005 hoz
#
#################################################################

INSTALL_DIR =	$$HOME/bin

CC	=	gcc

PROFILE =	# -pg
OPTIM	=	# -O3 -DNDEBUG

CFLAGS	=	-Wall #-DDBG
CFLAGS	+=	-Wmissing-prototypes
CFLAGS	+=	$(PROFILE) $(OPTIM)
LDFLAGS	+=	$(PROFILE)

PROJECT =	zkt
VERSION =	0.96

HEADER	=	dki.h misc.h domaincmp.h zconf.h config.h strlist.h \
		zone.h zkt.h debug.h ncparse.h zktr.h log.h rollover.h
SRC_ALL	=	dki.c misc.c domaincmp.c zconf.c log.c
OBJ_ALL	=	$(SRC_ALL:.c=.o)

SRC_SIG	=	dnssec-signer.c zone.c ncparse.c zktr.c rollover.c
OBJ_SIG	=	$(SRC_SIG:.c=.o)
MAN_SIG	=	dnssec-signer.8
PROG_SIG= dnssec-signer

SRC_ZKT	=	dnssec-zkt.c strlist.c zkt.c
OBJ_ZKT	=	$(SRC_ZKT:.c=.o)
MAN_ZKT	=	dnssec-zkt.8
PROG_ZKT= dnssec-zkt

SRC_SER	=	dnssec-soaserial.c
OBJ_SER	=	$(SRC_SER:.c=.o)
#MAN_SER	=	dnssec-soaserial.8
PROG_SER= dnssec-soaserial

MAN	=	$(MAN_ZKT) $(MAN_SIG) #$(MAN_SER)
OTHER	=	README README.logging TODO LICENSE CHANGELOG tags Makefile examples
SAVE	=	$(HEADER) $(SRC_ALL) $(SRC_SIG) $(SRC_ZKT) $(SRC_SER) $(MAN) $(OTHER)


all:	$(PROG_ZKT) $(PROG_SIG) $(PROG_SER)

macos:		## for MAC OS
macos:
	$(MAKE) CFLAGS="$(CFLAGS) -D HAS_UTYPES=0" all

solaris:	## for solaris
solaris:
	@$(MAKE) CFLAGS="$(CFLAGS) -D HAS_GETOPT_LONG=0" all

linux:		## for linux (default)
linux:
	@$(MAKE) all

$(PROG_SIG):	$(OBJ_SIG) $(OBJ_ALL) Makefile
	$(CC) $(LDFLAGS) $(OBJ_SIG) $(OBJ_ALL) -o $(PROG_SIG)

$(PROG_ZKT):	$(OBJ_ZKT) $(OBJ_ALL) Makefile
	$(CC) $(LDFLAGS) $(OBJ_ZKT) $(OBJ_ALL) -o $(PROG_ZKT)

$(PROG_SER):	$(OBJ_SER) Makefile
	$(CC) $(LDFLAGS) $(OBJ_SER) -o $(PROG_SER)

install:	## install binaries in INSTALL_DIR
install:	$(PROG_ZKT) $(PROG_SIG) $(PROG_SER)
	cp $(PROG_ZKT) $(PROG_SIG) $(PROG_SER) $(INSTALL_DIR)

tags:	$(SRC_ALL) $(SRC_SIG) $(SRC_ZKT) $(SRC_SER)
	ctags $(SRC_ALL) $(SRC_SIG) $(SRC_ZKT) $(SRC_SER)

clean:		## remove objectfiles and binaries
clean:
	rm -f $(OBJ_SIG) $(OBJ_ZKT) $(OBJ_SER) $(OBJ_ALL)

tar:	$(PROJECT)-$(VERSION).tar

man:	$(MAN_ZKT).html $(MAN_ZKT).pdf $(MAN_SIG).html $(MAN_SIG).pdf

$(MAN_ZKT).html: $(MAN_ZKT)
	groff -Thtml -man -mhtml $(MAN_ZKT) > $(MAN_ZKT).html
$(MAN_ZKT).pdf: $(MAN_ZKT)
	groff -Tps -man $(MAN_ZKT) | ps2pdf - $(MAN_ZKT).pdf
$(MAN_SIG).html: $(MAN_SIG)
	groff -Thtml -man -mhtml $(MAN_SIG) > $(MAN_SIG).html
$(MAN_SIG).pdf: $(MAN_SIG)
	groff -Tps -man $(MAN_SIG) | ps2pdf - $(MAN_SIG).pdf
	
	
$(PROJECT)-$(VERSION).tar:	$(SAVE)
	tar cvf $(PROJECT)-$(VERSION).tar $(SAVE)

depend:
	$(CC) -MM $(SRC_SIG) $(SRC_ZKT) $(SRC_SER) $(SRC_ALL)

help:
	@grep "^.*:[ 	]*##" Makefile

## all dependicies
#:r !make depend
#gcc -MM dnssec-signer.c zone.c ncparse.c zktr.c rollover.c dnssec-zkt.c strlist.c zkt.c dnssec-soaserial.c dki.c misc.c domaincmp.c zconf.c log.c
dnssec-signer.o: dnssec-signer.c config.h zconf.h debug.h misc.h \
  ncparse.h zone.h dki.h zktr.h rollover.h log.h
zone.o: zone.c config.h debug.h domaincmp.h misc.h zconf.h dki.h zone.h
ncparse.o: ncparse.c debug.h misc.h zconf.h log.h ncparse.h
zktr.o: zktr.c zktr.h
rollover.o: rollover.c config.h zconf.h debug.h misc.h zone.h dki.h \
  zktr.h log.h rollover.h
dnssec-zkt.o: dnssec-zkt.c config.h debug.h misc.h zconf.h strlist.h \
  dki.h zkt.h
strlist.o: strlist.c strlist.h
zkt.o: zkt.c config.h dki.h misc.h zconf.h strlist.h zkt.h
dnssec-soaserial.o: dnssec-soaserial.c config.h
dki.o: dki.c config.h debug.h domaincmp.h misc.h zconf.h dki.h
misc.o: misc.c config.h zconf.h log.h debug.h misc.h
domaincmp.o: domaincmp.c domaincmp.h
zconf.o: zconf.c config.h debug.h misc.h zconf.h dki.h
log.o: log.c config.h misc.h zconf.h debug.h log.h
