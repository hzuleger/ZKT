#################################################################
#
#	@(#) Makefile for dnssec zone key tool  (c) Mar 2005 hoz
#
#################################################################

INSTALL_DIR =	$$HOME/bin

CC	=	gcc

PROFILE =	# -pg
OPTIM	=	# -O3 -DNDEBUG

CFLAGS	=	#-DDBG
CFLAGS	+=	-Wmissing-prototypes
CFLAGS	+=	$(PROFILE) $(OPTIM)
LDFLAGS	+=	$(PROFILE)

PROJECT =	zkt
VERSION =	0.92

HEADER	=	dki.h misc.h domaincmp.h zconf.h config.h strlist.h \
		zone.h zkt.h debug.h ncparse.h zktr.h
SRC_ALL	=	dki.c misc.c domaincmp.c zconf.c
OBJ_ALL	=	$(SRC_ALL:.c=.o)

SRC_SIG	=	dnssec-signer.c zone.c ncparse.c zktr.c
OBJ_SIG	=	$(SRC_SIG:.c=.o)
MAN_SIG	=	dnssec-signer.8
PROG_SIG= dnssec-signer

SRC_ZKT	=	dnssec-zkt.c strlist.c zkt.c
OBJ_ZKT	=	$(SRC_ZKT:.c=.o)
MAN_ZKT	=	dnssec-zkt.8
PROG_ZKT= dnssec-zkt

MAN	=	$(MAN_ZKT) $(MAN_SIG)
OTHER	=	README BUGS LICENSE CHANGELOG tags Makefile examples
SAVE	=	$(HEADER) $(SRC_ALL) $(SRC_SIG) $(SRC_ZKT) $(MAN) $(OTHER)

all:	$(PROG_ZKT) $(PROG_SIG) 

$(PROG_SIG):	$(OBJ_SIG) $(OBJ_ALL) Makefile
	$(CC) $(LDFLAGS) $(OBJ_SIG) $(OBJ_ALL) -o $(PROG_SIG)

$(PROG_ZKT):	$(OBJ_ZKT) $(OBJ_ALL) Makefile
	$(CC) $(LDFLAGS) $(OBJ_ZKT) $(OBJ_ALL) -o $(PROG_ZKT)

install:	$(PROG_ZKT) $(PROG_SIG)
	cp $(PROG_ZKT) $(PROG_SIG) $(INSTALL_DIR)

tags:	$(SRC_ALL) $(SRC_SIG) $(SRC_ZKT)
	ctags $(SRC_ALL) $(SRC_SIG) $(SRC_ZKT)

clean:
	rm -f $(OBJ_SIG) $(OBJ_ZKT) $(OBJ_ALL)

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
	$(CC) -MM $(SRC_SIG) $(SRC_ZKT) $(SRC_ALL)

## all dependicies
#:r !make depend
#gcc -MM dnssec-signer.c zone.c ncparse.c zktr.c dnssec-zkt.c strlist.c zkt.c dki.c misc.c domaincmp.c zconf.c
dnssec-signer.o: dnssec-signer.c config.h zconf.h debug.h misc.h \
  ncparse.h zone.h dki.h zktr.h
zone.o: zone.c config.h debug.h misc.h zconf.h dki.h zone.h
ncparse.o: ncparse.c debug.h misc.h ncparse.h
zktr.o: zktr.c zktr.h
dnssec-zkt.o: dnssec-zkt.c config.h debug.h misc.h strlist.h zconf.h \
  dki.h
strlist.o: strlist.c strlist.h
zkt.o: zkt.c config.h dki.h zkt.h
dki.o: dki.c config.h debug.h misc.h zconf.h dki.h
misc.o: misc.c config.h zconf.h misc.h
domaincmp.o: domaincmp.c domaincmp.h
zconf.o: zconf.c config.h zconf.h dki.h
