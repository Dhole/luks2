#!/bin/sh
set -ex

if [ ! -f pg100.txt ]; then
    bzip2 -d -k pg100.txt.bz2
fi

git submodule init
git submodule update

cd quick-vm
if [ ! -f alpine-unattended.iso ]; then
    ./setup-iso.sh
fi
if [ ! -f alpine.img ]; then
    ./install-vm.sh
fi
