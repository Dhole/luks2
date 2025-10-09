#!/bin/sh
set -ex

dd if=/dev/zero bs=1M count=20 > tests/test.iso
printf "password" | cryptsetup luksFormat \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32 \
    tests/test.iso \
    --key-file -
