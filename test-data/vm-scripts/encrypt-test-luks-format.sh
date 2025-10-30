#!/bin/sh

set -ex

doas apk add curl cryptsetup

cd /tmp/test-luks

IMG=test-luks-write2.img

printf "password" | doas cryptsetup luksOpen \
    $IMG test \
    --key-file -

sectors=$(doas fdisk -l /dev/mapper/test | grep -E -o "[0-9]+ sectors$" | grep -E -o "[0-9]+")
doas dd bs=512 count=$sectors if=pg100.txt of=/dev/mapper/test
doas cryptsetup luksClose test

