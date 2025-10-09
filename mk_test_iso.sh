#!/bin/sh
set -ex

fallocate -l 16M tests/test.iso
printf "YES\npassword\npassword" | cryptsetup luksFormat \
    --force-password \
    --type luks2 \
    tests/test.iso
