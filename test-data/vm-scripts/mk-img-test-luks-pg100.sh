#!/bin/sh

set -ex


doas apk add curl cryptsetup

cd /tmp/test-luks

mk_img() {
    dd if=/dev/zero bs=1M count=20 > $IMG
    # Default parameters
    printf "password" | cryptsetup luksFormat \
        $@ \
        $IMG \
        --key-file -

    printf "password" | doas cryptsetup luksOpen \
        $IMG test \
        --key-file -

    sectors=$(doas fdisk -l /dev/mapper/test | grep -E -o "[0-9]+ sectors$" | grep -E -o "[0-9]+")
    doas dd bs=512 count=$sectors if=pg100.txt of=/dev/mapper/test
    doas cryptsetup luksClose test
}

NAME=test-luks-pg100

IMG=$NAME.0.img mk_img \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32

IMG=$NAME.1.img mk_img \
    --sector-size 512 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32

IMG=$NAME.2.img mk_img \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha1 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32

IMG=$NAME.3.img mk_img \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 512 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32

IMG=$NAME.4.img mk_img \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 512 \
    --pbkdf argon2id \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32

IMG=$NAME.5.img mk_img \
    --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --key-size 256 \
    --keyslot-cipher aes-xts-plain64 \
    --keyslot-key-size 256 \
    --pbkdf argon2i \
    --pbkdf-force-iterations=4 \
    --pbkdf-memory=32
