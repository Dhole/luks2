# Test framework

The reference implementation of luks is implemented for linux and lives between
the kernel and userspace.  This test framework allows testing the userspace
implementation against the reference implementation.  In order to keep the
development environment clean and to avoid dangerous operations, the reference
implementation is run under a VM.

# Setup

To setup the test framework run:
```
./setup.sh
```

This will prepare some testing artifacts and setup a fresh Alpine install using
qemu.

# Tests

## luks-pg100

Steps:
```
./mk-img-test-luks-pg100.sh
cargo test --test test_img_luks_pg100
```

The first script will create a luks image in the VM and encrypt the contents of
`pg100.txt` into it.

The rust tests will read the luks image to decode the headers as well as
decrypt the content and verify that it matches against the contents of
`pg100.txt`.
