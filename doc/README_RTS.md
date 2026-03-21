Rudimentary Test System (RTS)
=============================

History
-------

Starting with ucspi-tcp, DJB introduced a script called 'rts.test'
to do some unit/system tests for the modules included in here.

This piece of software was never documented nor it's purpose was defined.
William Baxter modified it to work with ucspi-ssl.
DJB used it while providing djbdns in /slashpackage format.


Components
----------

Within /slashpackage 'rts' consists of the following pieces:

*  a) package/rts [component] is a generic shell script.
*  b) src/rts.[it], src/rts.[component] are the scripts containing the specific unit tests.
    src/rts.it is usually the supervising script, 
    while src/rts.base includes typically the 'basic' unit tests,
    src/rts.[compontent] is optional.
*  c) src/exp.[it], src.[bases] and perhaps src/exp.[component] 
    include the expected results (adapted).

While [it] and [base] are mandatory, any further [component] needs 
to be defined by the (slash)package installation.


Invocation
----------

'rts' is typically called after a successfull compilation and prior of installation.
The $PATH variable includes the current directory of the executed rts.it.
In order to test the included modules one calls:

```
  package/rts             --> all tests are done (including optional)
  package/rts base        --> basic unit tests
  package/rts [component] --> optional component test
```

Results
-------

The script rts.[component] is executed in

```
  ./compile/rts-tmp
```

to be raised upon call. The results are written to
  
```
  ./compile/out.[component]
``` 
and then diff'ed against exp.[component], cleaned up for trivial 
run dependencies (like port numbers), and the difference is displayed.

If there is no difference, nothing is displayed => working as expected.

However, even if differences are given, they may be due to environment/call 
dependencies (like process ids) resulting in some mangled output.

In case package/rts is called again, the previsous results are overwritten.


HOWTO
-----

* a) under ./compile execute sh ./rts.it 
* b) Check results.
* c) Adjust code/expectations.
* d) Verify its ok.
* e) run package/rts
* f) copy out.base -> ../src/exp.base, out.it -> ../src/exp.it
* g) Verify!


OPEN ISSUES
-----------

In some shells, reading a password from FD 3 seems not to be working.
This may inhibit reading a password protected key file for sslclient.
Therefore, this feature has been rmoved from the tests.


--eh (September, 2024).
