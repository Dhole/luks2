#!/bin/sh

set -ex

IMG=test-luks-pg100.img

doas apk add curl cryptsetup

cd /tmp/test-luks
dd if=/dev/zero bs=1M count=20 > $IMG
# Default parameters
printf "password" | cryptsetup luksFormat \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32 \
    $IMG \
    --key-file -

printf "password" | doas cryptsetup luksOpen \
    $IMG test \
    --key-file -

sectors=$(doas fdisk -l /dev/mapper/test | grep -E -o "[0-9]+ sectors$" | grep -E -o "[0-9]+")
doas dd bs=512 count=$sectors if=pg100.txt of=/dev/mapper/test
doas cryptsetup luksClose test

