# Don't edit Makefile! Use ../conf-* for configuration.

SHELL=/bin/sh

default: one two 

https@.0: \
https@.1
	nroff -man https@.1 > https@.0

sslcat.0: \
sslcat.1
	nroff -man sslcat.1 > sslcat.0

sslclient.0: \
sslclient.1
	nroff -man sslclient.1 > sslclient.0

sslconnect.0: \
sslconnect.1
	nroff -man sslconnect.1 > sslconnect.0

sslhandle.0: \
sslhandle.1
	nroff -man sslhandle.1 > sslhandle.0

sslserver.0: \
sslserver.1
	nroff -man sslserver.1 > sslserver.0

clean: \
TARGETS
	rm -f `cat TARGETS`
	gzip -q -d *.gz

ucspi-tls.0: \
ucspi-tls.2
	nroff -man ucspi-tls.2 > ucspi-tls.0

one: \
https@.0 sslcat.0 sslclient.0 sslconnect.0 sslserver.0 sslhandle.0

two: \
ucspi-tls.0
