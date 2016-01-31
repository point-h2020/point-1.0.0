#!/bin/bash
# this is a simple script to recompile everything useful for basic testing
# useful for a quick start or after changing branches
# not a replacement for reading the HowTo!
set -x
set -e
sudo apt install `cat apt-get.txt`
cd src/
autoconf
./configure --disable-linuxmodule
make clean
make
sudo make install
cd ..
cd lib/
autoreconf -fi
./configure
make clean
make
sudo make install
cd ..
cd TopologyManager/
make
cd ..
cd examples/samples
make clean
make
cd ..
cd traffic_engineering/
make
cd ..
cd video_streaming/
make
cd ../../
cd deployment/
make clean
make
cd ..

