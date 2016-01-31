#!/bin/bash
# Author: Sebastian Robitzsch <sebastian.robitzsch@interdigital.com>
#
if [ "$1" == "--clean" ]; then
	CLEAN=1
else
	CLEAN=0
fi

if [ "$1" == "--nap" ]; then
	NAP_ONLY=1
else
	NAP_ONLY=0
fi

echo "Building NAP"
if [ $CLEAN -eq 1 ]; then
	make clean
fi
make
echo "Building proxy"
cd proxy/
if [ $CLEAN -eq 1 ]; then
	make clean
fi
make
echo "Done"
