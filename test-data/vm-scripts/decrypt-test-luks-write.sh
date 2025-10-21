#!/bin/sh

set -ex

doas apk add curl cryptsetup

cd /tmp/test-luks

IMG=test-luks-write.img

printf "password" | doas cryptsetup luksOpen \
    $IMG test \
    --key-file -

doas dd if=/dev/mapper/test of=pg100-decrypted.img

doas cryptsetup luksClose test

