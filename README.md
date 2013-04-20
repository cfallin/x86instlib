Description
===========

x86instlib is a library for cracking x86-64 machine code (user-mode only) into
uops and executing them. The decoder and uop implementations are based on
PTLsim, but with some modifications. This distribution also includes a Pintool
which takes instruction traces and memory images of arbitrary programs in
Linux; these traces are suitable for use with a simulator based on x86instlib.
Eventually, this distribution will also include a simple functional
emulator/trace-reader which ties together the itrace functionality and the
instruction decoder.

How to Compile the Pintool
--------------------------

1. Install Pin (tested with 2.11 on Linux) and set PIN environment variable to
its home.

2. make

How to Run the Pintool
----------------------

    $ pin -t pin/itrace.so -o my.trace -- ./my_test_program arg1 arg2 ...

How to Compile x86instlib
-------------------------

1. make

License and Copyright
=====================

Original code written as a part of x86instlib is Copyright (c) 2012, 2013,
Chris Fallin <cfallin@c1f.net>. x86instlib is released under the GNU GPL v2 or
later.

x86instlib draws code from:

* instlib/decode/: PTLsim (x86 decoder), available under GPL v2
