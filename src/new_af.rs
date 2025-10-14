use alloc::vec;
use alloc::vec::Vec;
use digest::{Digest, FixedOutputReset};

fn xor_block(src: &[u8], dst: &mut [u8], n: usize) {
    for j in 0..n {
        dst[j] = src[j] ^ dst[j];
    }
}

fn diffuse<H: Digest + FixedOutputReset>(buf: &mut [u8], size: usize) {
    let mut hash = H::new();
    let digest_size = <H as Digest>::output_size();
    let blocks = size / digest_size;
    let padding = size % digest_size;

    for i in 0..blocks {
        Digest::update(&mut hash, (i as u32).to_be_bytes()); // i is the iv

        let s = digest_size * i;
        let e = if (s + digest_size) > size {
            s + padding
        } else {
            s + digest_size
        };
        Digest::update(&mut hash, &buf[s..e]);
        buf[s..e].copy_from_slice(&hash.finalize_reset()[..]);
    }
}

/// Recovers information from data that was split with `cryptsetup`'s `afsplitter` implementation.
///
/// The blocksize and blocknumber values must be the same as when splitting the information.
/// Only SHA-256 is supported (which is was `cryptsetup` uses).
pub fn merge<H>(src: &[u8], blocksize: usize, blocknumbers: usize) -> Vec<u8>
where
    H: Digest + FixedOutputReset,
{
    let mut bufblock = vec![0; blocksize];

    for i in 0..blocknumbers {
        let s = blocksize * i;
        let e = s + blocksize;
        xor_block(&src[s..e], &mut bufblock, blocksize);
        if i < (blocknumbers - 1) {
            diffuse::<H>(&mut bufblock, blocksize);
        }
    }

    bufblock
}
