# Don't edit Makefile!  Use conf-* for configuration.

SHELL=/bin/sh

default: it

auto-str: \
load auto-str.o
	./load auto-str

auto-str.o: \
compile auto-str.c
	./compile auto-str.c

auto_cadir.c: \
auto-str ../conf-cadir
	./auto-str auto_cadir "`head -1 ../conf-cadir`" > auto_cadir.c

auto_cadir.o: \
compile auto_cadir.c
	./compile auto_cadir.c

auto_cafile.c: \
auto-str ../conf-cafile
	./auto-str auto_cafile "`head -1 ../conf-cafile`" > auto_cafile.c

auto_cafile.o: \
compile auto_cafile.c
	./compile auto_cafile.c

auto_ccafile.c: \
auto-str ../conf-ccafile
	./auto-str auto_ccafile "`head -1 ../conf-ccafile`" > auto_ccafile.c

auto_ccafile.o: \
compile auto_ccafile.c
	./compile auto_ccafile.c

auto_certchainfile.c: \
auto-str ../conf-certchainfile
	./auto-str auto_certchainfile "`head -1 ../conf-certchainfile`" > auto_certchainfile.c
  
auto_certchainfile.o: \
compile auto_certchainfile.c
	./compile auto_certchainfile.c

auto_certfile.c: \
auto-str ../conf-certfile
	./auto-str auto_certfile "`head -1 ../conf-certfile`" > auto_certfile.c

auto_certfile.o: \
compile auto_certfile.c
	./compile auto_certfile.c

auto_ciphers.c: \
auto-str ../conf-ciphers
	./auto-str auto_ciphers "`head -1 ../conf-ciphers`" > auto_ciphers.c

auto_ciphers.o: \
compile auto_ciphers.c
	./compile auto_ciphers.c

auto_dhfile.c: \
auto-str ../conf-dhfile
	./auto-str auto_dhfile "`head -1 ../conf-dhfile`" > auto_dhfile.c

auto_dhfile.o: \
compile auto_dhfile.c
	./compile auto_dhfile.c

auto_keyfile.c: \
auto-str ../conf-keyfile
	./auto-str auto_keyfile "`head -1 ../conf-keyfile`" > auto_keyfile.c

auto_keyfile.o: \
compile auto_keyfile.c
	./compile auto_keyfile.c

ccperl: \
../conf-ccperl ../conf-perl print-ccperl.sh
	rm -f ccperl
	sh print-ccperl.sh > ccperl

chkshsgr: \
load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: \
compile chkshsgr.c 
	./compile chkshsgr.c

choose: \
warn-auto.sh choose.sh
	rm -f choose
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> choose
	chmod 755 choose

coe.o: \
compile coe.c coe.h
	./compile coe.c

compile: \
../conf-cc ../conf-ssl print-cc.sh systype warn-auto.sh
	rm -f compile
	sh print-cc.sh > compile
	chmod 755 compile

hassgact.h: \
choose compile trysgact.c hassgact.h1 hassgact.h2
	./choose cl trysgact hassgact.h1 hassgact.h2 > hassgact.h

hassgprm.h: \
choose compile trysgprm.c hassgprm.h1 hassgprm.h2
	./choose cl trysgprm hassgprm.h1 hassgprm.h2 > hassgprm.h

hasshsgr.h: \
choose compile tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

https@: warn-auto.sh https@.sh
	rm -f https@
	cat warn-auto.sh https@.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> https@
	chmod 755 https@

it: it-sys it-base it-sslperl 

it-base: sslclient sslserver https@ sslcat sslconnect sslprint sslhandle

it-sslperl: sslperl

it-sys: sysdeps auto-str

load: \
../conf-ld print-ld.sh systype warn-auto.sh
	rm -f load
	sh print-ld.sh > load
	chmod 755 load	

makelib: \
print-ar.sh systype warn-auto.sh
	rm -f makelib
	sh print-ar.sh > makelib
	chmod 755 makelib

perlembed.lib: \
../conf-perl ../conf-ldperl print-perlembed.sh
	rm -f perlembed.lib
	sh print-ldperl.sh > perlembed.lib

remoteinfo.o: \
compile remoteinfo.c remoteinfo.h 
	./compile remoteinfo.c

rules.o: \
compile rules.c rules.h ip4_bit.c ip6_bit.c ip_bit.h
	./compile rules.c ip4_bit.c ip6_bit.c ip_bit.h

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

ssl.lib: \
../conf-ssllib print-dl.sh
	rm -f ssl.lib
	sh print-dl.sh > ssl.lib
	chmod 755 ssl.lib

ssl_ca.o: \
compile ssl_ca.c ucspissl.h
	./compile ssl_ca.c

ssl_cca.o: \
compile ssl_cca.c ucspissl.h
	./compile ssl_cca.c

ssl_chainfile.o: \
compile ssl_chainfile.c ucspissl.h
	./compile ssl_chainfile.c

ssl_certkey.o: \
compile ssl_certkey.c ucspissl.h
	./compile ssl_certkey.c

ssl_ciphers.o: \
compile ssl_ciphers.c ucspissl.h
	./compile ssl_ciphers.c

ssl_context.o: \
compile ssl_context.c ucspissl.h
	./compile ssl_context.c

ssl_env.o: \
compile ssl_env.c ucspissl.h
	./compile ssl_env.c

ssl_error.o: \
compile ssl_error.c ucspissl.h
	./compile ssl_error.c

ssl_io.o: \
compile ssl_io.c ucspissl.h 
	./compile ssl_io.c

ssl_new.o: \
compile ssl_new.c ucspissl.h
	./compile ssl_new.c

ssl_params.o: \
compile ssl_params.c ucspissl.h
	./compile ssl_params.c

ssl_timeout.o: \
compile ssl_timeout.c ucspissl.h 
	./compile ssl_timeout.c

ssl_verify.o: \
compile ssl_verify.c ucspissl.h 
	./compile ssl_verify.c

sslcat: \
warn-auto.sh sslcat.sh
	rm -f sslcat
	cat warn-auto.sh sslcat.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> sslcat
	chmod 755 sslcat

sslclient: \
load sslclient.o auto_cafile.o auto_cadir.o auto_ciphers.o \
remoteinfo.o ucspissl.a socket.lib ssl.lib
	./load sslclient auto_cafile.o auto_cadir.o auto_ciphers.o \
	 remoteinfo.o ucspissl.a \
	`cat socket.lib` `cat ssl.lib`

sslclient.o: \
compile sslclient.c auto_cadir.h auto_cafile.h auto_ciphers.h \
remoteinfo.h ucspissl.h
	./compile sslclient.c

sslconnect: \
warn-auto.sh sslconnect.sh
	rm -f sslconnect
	cat warn-auto.sh sslconnect.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> sslconnect
	chmod 755 sslconnect

sslhandle: \
load sslhandle.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_certchainfile.o auto_dhfile.o \
auto_certfile.o auto_keyfile.o auto_ciphers.o \
coe.o rules.o ip4_bit.o ip6_bit.o remoteinfo.o sslprint.o \
ucspissl.a socket.lib ssl.lib
	./load sslhandle auto_cafile.o auto_ccafile.o auto_cadir.o \
	auto_dhfile.o auto_ciphers.o \
	auto_certchainfile.o auto_certfile.o auto_keyfile.o \
	coe.o rules.o ip4_bit.o ip6_bit.o remoteinfo.o sslprint.o \
	ucspissl.a `cat socket.lib` `cat ssl.lib`

sslhandle.o: \
compile sslhandle.c auto_cadir.h auto_cafile.h auto_ccafile.h \
auto_certchainfile.h auto_certfile.h auto_ciphers.h \
auto_dhfile.h auto_keyfile.h rules.h ip_bit.h ucspissl.h coe.h \
remoteinfo.o rules.o ip4_bit.o ip6_bit.o ucspissl.a
	./compile sslhandle.c 

sslperl: \
load sslperl.o ucspissl.a sslhandle.o \
auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_dhfile.o auto_certfile.o auto_keyfile.o \
auto_ciphers.o auto_certchainfile.o \
coe.o rules.o remoteinfo.o ip4_bit.o ip6_bit.o \
socket.lib ssl.lib perlembed.lib
	./load sslperl auto_cafile.o auto_ccafile.o auto_cadir.o \
	auto_dhfile.o auto_certfile.o auto_keyfile.o \
	auto_ciphers.o auto_certchainfile.o ucspissl.a sslhandle.o \
	rules.o ip4_bit.o ip6_bit.o remoteinfo.o coe.o \
	ucspissl.a `cat socket.lib` `cat ssl.lib` `cat perlembed.lib` 

sslperl.o: \
compile ccperl sslperl.c sslperl.c ucspissl.h 
	./compile `cat ccperl` sslperl.c 

sslprint: \
load sslprint.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_dhfile.o auto_certfile.o auto_keyfile.o \
auto_ciphers.o auto_certchainfile.o coe.o sslhandle.o \
rules.o ip4_bit.o ip6_bit.o remoteinfo.o \
ucspissl.a socket.lib ssl.lib 
	./load sslprint auto_cafile.o auto_ccafile.o auto_cadir.o \
	auto_dhfile.o auto_certfile.o auto_keyfile.o \
	auto_ciphers.o auto_certchainfile.o \
	rules.o ip4_bit.o ip6_bit.o remoteinfo.o coe.o sslhandle.o \
	ucspissl.a `cat socket.lib` `cat ssl.lib` 

sslprint.o: \
compile sslprint.c 
	./compile sslprint.c

sslserver: \
load sslserver.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_certchainfile.o auto_dhfile.o \
auto_certfile.o auto_keyfile.o auto_ciphers.o \
rules.o ip4_bit.o ip6_bit.o remoteinfo.o \
ucspissl.a socket.lib ssl.lib
	./load sslserver auto_cafile.o auto_ccafile.o auto_cadir.o \
	auto_dhfile.o auto_ciphers.o \
	auto_certchainfile.o auto_certfile.o auto_keyfile.o \
	rules.o ip4_bit.o ip6_bit.o remoteinfo.o ucspissl.a \
	`cat socket.lib` `cat ssl.lib`

sslserver.o: \
compile sslserver.c auto_cadir.h auto_cafile.h auto_ccafile.h \
auto_certchainfile.h auto_certfile.h auto_ciphers.h \
auto_dhfile.h auto_keyfile.h \
remoteinfo.h rules.h ip_bit.h ucspissl.h 
	./compile sslserver.c 

sysdeps: \
systype compile load hassgact.h hassgprm.h
	rm -f sysdeps
	cat systype compile load >> sysdeps
	grep sysdep hassgact.h >> sysdeps
	grep sysdep hassgprm.h >> sysdeps

systype: \
find-systype.sh trycpp.c x86cpuid.c
	sh find-systype.sh > systype

ucspissl.a: \
makelib ssl_ca.o ssl_cca.o ssl_certkey.o ssl_chainfile.o ssl_ciphers.o \
ssl_context.o ssl_env.o ssl_error.o ssl_io.o ssl_new.o ssl_params.o \
ssl_timeout.o ssl_verify.o ucspissl.o 
	./makelib ucspissl.a ssl_ca.o ssl_cca.o ssl_certkey.o ssl_chainfile.o \
	ssl_ciphers.o ssl_context.o ssl_env.o ssl_error.o ssl_io.o ssl_new.o \
	ssl_params.o ssl_timeout.o ssl_verify.o ucspissl.o 
 
ucspissl.o: \
compile ucspissl.c ucspissl.h
	./compile ucspissl.c

clean: 
	rm -f `cat TARGETS`
