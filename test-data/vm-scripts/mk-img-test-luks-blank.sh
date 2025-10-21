#!/bin/sh

set -ex


doas apk add curl cryptsetup

cd /tmp/test-luks

IMG=test-luks-blank.img

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

doas cryptsetup luksClose test
