/* \mainpage

ucspi-ssl-0.13
==============

ucspi-ssl is a joined project of William Baxter 
(Copyright 2001 SuperScript Technology, Inc.) and me (FEHCom). 

ucspi-ssl home page 
-------------------

- https://www.superscript.com/
- https://www.fehcom.de/ipnet/ucspi-ssl.html

Requirements
------------

- OpenSSL or LibreSSL providing crypto services for TLS 1.3.
- fehQlibs(>=25) need to be installed (usually located at /usr/local)
  for network and DNS services.

Installation and Customization
------------------------------

- Read INSTALL for installation instructions.
- Read doc/CERTS for the X.509 certificates shipped.
- Read doc/CHAIN-SSL how to configure X.509 chaining support.

Changelog and Internals
-----------------------

- Read doc/CHANGES for changes and bug fixes. 
- Read doc/UCSPI-SSL to find some internal information.
- Read doc/TLS_1_3 how to use an OpenSSL/LibreSSL version providing TLS 1.3 support.
- Read doc/TLSVERSION_CIPHERSUITES how to tweak TLS version and cipher suites.
- Read doc/TODO what is missing still.

CDB rules file
--------------

- In order to generate the 'cdb' rules file ucspi-tcp(6) is required,
  providing the program 'tcprules'.
- Applying 'tcprules' from ucspi-tcp6 allows recognition of IPv6 addresses
  and usage in the common CIDR format for both IPv4 and IPv6 addresses.
- Old 'cdb' formats and their generating rules file are accepted unaltered.
- sslserver and sslhandle support the 'MAXCONIP' feature.
- sslserver is enabled to evaluate an early 'cdb' lookup before DNS resolution. 

Cryptomaterial and X.509 certs
------------------------------

- In the directory ./etc you will find some X.509 certificate, key files
  and other crypto material required for a first setup.
- All X.509 certificates use now ECC crypto instead of RSA.
- Read etc/README_CERTS.md.

Regression Testing
------------------

- ucspi-tcp6 has to be installed (under /usr/local/bin, or any accessible path).
- Run package/rts in ucspi-ssl's directory.
- The output should show up different SSL session IDs, but nothing else.
- Read doc/README_RTS.md for more information.


Erwin Hoffmann, September 2024.
