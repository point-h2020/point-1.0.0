Blackadder
**********************

A Click-based implementation of the core ICN node in the POINT platform. It comprises a set of ICN elements, including:
- LocalRV: preforms the RV function
- LocalProxy: main process dispatcher
- Forwarder: performs the FW function
- GlobalConf: sets the global ICN configuration parameters

Dependencies:
============
- click
- autoconf
- automake

Installation
============

# autoconf
# ./configure --disable-linuxmodule
# make && sudo make install

See the ../doc/HowTo file for detailed information about configure and
install Blackadder.

Running
============

# sudo click /tmp/FILE_NAME.conf
