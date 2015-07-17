ZKT -- Zone Key Tool
====================

A dnssec zone and key management toolset

(c) March 2005 - Aug 2014 by  Holger Zuleger  hznet
(c) domaincmp() Aug 2005 by Karle Boss & H. Zuleger (kaho)
(c) zconf.c by Jeroen Masar & Holger Zuleger

For more information about the DNSSEC Zone Key Tool please
have a look at "http://www.zonekeytool.de/"

You can subscribe to the zkt-users@sourceforge.net mailing list
on the following website: https://lists.sourceforge.net/lists/listinfo/zkt-users

The ZKT software is licenced under BSD (see LICENCE file)

## Install the software

ZKT is integrated into the BIND src package.  
You find it in the sub directory contrib/zkt-1.1.3

However, you can also download the tar file from the project page
or can get the latest version on github

	$ wget http://www.hznet.de/dns/zkt/zkt-1.3.tar.gz
		or 
	$ git clone https://github.com/hzuleger/ZKT/

Unpack
	$ tar xzvf zkt-1.3.tar.gz
	$ cd zkt-1.3

Configure ZKT with configure options..

	$ ./configure --help 2>&1 | grep able-
	  --disable-option-checking  ignore unrecognized --enable/--with options
	  --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
	  --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
	  --enable-bind_util_path=PATH
	  --disable-color-mode    zkt without colors
	  --enable-print-timezone print out timezone
	  --enable-print-age      print age with year
	  --enable-log-progname   log with progname
	  --disable-log-timestamp do not log with timestamp
	  --disable-log-level     do not log with level
	  --disable-ttl-in-keyfiles
	  --enable-ds-tracking    track DS record in parent zone (ksk-rollover)
	  --enable-configpath=PATH
	  --disable-tree          use single linked list instead of binary tree data

... and start run it
	$ ./configure

Compile and install the binaries
	$ make
	$ sudo make install
	# sudo make install-man

## Configure and setup ZKT

1. Install or rebuild the default dnssec.conf file 

	$ zkt-conf -d -w	# Install new file
		or
	$ zkt-conf -s -w	# rebuild existing file

The configuration file is named "/var/named/dnssec.conf" by default

2. (optional) Change the default parameters  
   To change the paremeters in the config file you can use a simple text  
   editor, or use the zkt-conf command

	$ zkt-conf -s -O "Zonedir: /var/named/zones" -w
	$ zkt-conf -s -O "Recursive: True" -w
		or use your prefered editor 
	$ vi /var/named/dnssec.conf

3. Prepare one of your zone for zkt

   * Change to the zone directory
	$ cd /var/named/zones/net/example.net
   * Copy and rename the existing zone file to `zone.db`
	$ cp <zonefile> zone.db
   * Create a local `dnssec.conf` file and include `dnskey.db` into the zone file
	$ zkt-conf -w zone.db		

4. Prepare for initial signing

	$ cd /var/named/zones/net/example.net
	$ touch zone.db.signed
	$ zkt-signer -v -v -o example.net	# -o is ORIGIN (i.e. zone name)

5. Publish your zone  
   You have to change your named zone configuration to use `zone.db.signed` as master  
   zone file.
   Then force a reload of the zones
	$ rndc reload example.net
		or
	$ zkt-signer -f -r -v -v

   Don't forget to send your DS Record to the parent.  
   You will find the DS record in the file `dsset-example.net.`.

