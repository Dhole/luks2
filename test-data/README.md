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

## luks-pg100-read

Steps:
```
./mk-img-test-luks-pg100.sh
cargo test --test test_img_luks_pg100_read
```

The first script will create a luks image in the VM and encrypt the contents of
`pg100.txt` into it.

The rust tests will read the luks image to decode the headers as well as
decrypt the content and verify that it matches against the contents of
`pg100.txt`.

## luks-pg100-write

Steps:
```
./mk-img-test-luks-blank.sh
cargo test --test test_img_luks_pg100_write test_write_device
cargo test --test test_img_luks_pg100_write test_read_device
./decrypt-test-luks-write.sh
cargo test --test test_img_luks_pg100_write test_verify_decryption
```

The first script will create a luks image in a VM with garbage content.

The rust test will write from the `pg100.txt` file at various locations into
the luks segment, and at the same time it will write the same contents to a
file that will be used as expected content later.

Then we read the luks segment from the rust implementation and compare the read
data with the expected content.

Then we decrypt the entire luks segment from the VM and write the output to a file.

Finally in Rust we compare the VM decrypted content with the expected content.
