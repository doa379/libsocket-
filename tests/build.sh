#! /bin/sh

cd ../
make clean && make -j3
cd tests/
make clean && make -j3 $@
