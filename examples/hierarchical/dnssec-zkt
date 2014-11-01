#!/bin/sh
#
#	Shell script to start the dnssec-zkt command
#	out of the example directory
#

if test ! -f dnssec.conf
then
	echo Please start this skript out of the flat or hierarchical sub directory
	exit 1
fi
../../dnssec-zkt -c dnssec.conf "$@"
