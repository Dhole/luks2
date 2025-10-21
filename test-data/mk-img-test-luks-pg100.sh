#!/bin/sh

set -ex

SSH_OPTS="-q -i id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
VM="user@localhost"
SSH="ssh $SSH_OPTS -p 2222 user@localhost"
SCP="scp $SSH_OPTS -P 2222"

cd quick-vm

./start-vm.sh
# Stop qemu on exit
trap "$SSH doas poweroff; (while [ -f qemu-pid.txt ]; do sleep 1; done); trap - EXIT; exit" EXIT INT HUP TERM
while ! (ncat -i 1s localhost 2222 | grep SSH); do sleep 2; done

$SSH mkdir -p /tmp/test-luks
$SCP ../vm-scripts/mk-img-test-luks-pg100.sh $VM:/tmp/test-luks
$SCP ../pg100.txt $VM:/tmp/test-luks
$SSH /tmp/test-luks/mk-img-test-luks-pg100.sh
$SCP $VM:/tmp/test-luks/test-luks-pg100.0.img ..
$SCP $VM:/tmp/test-luks/test-luks-pg100.1.img ..
$SCP $VM:/tmp/test-luks/test-luks-pg100.2.img ..
$SCP $VM:/tmp/test-luks/test-luks-pg100.3.img ..
$SCP $VM:/tmp/test-luks/test-luks-pg100.4.img ..
$SCP $VM:/tmp/test-luks/test-luks-pg100.5.img ..
