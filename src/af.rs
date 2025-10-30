use alloc::vec::Vec;
use digest::{Digest, FixedOutputReset};
use rand::prelude::*;

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
        let e = s + digest_size;
        Digest::update(&mut hash, &buf[s..e]);
        buf[s..e].copy_from_slice(&hash.finalize_reset()[..]);
    }
    if padding != 0 {
        Digest::update(&mut hash, (blocks as u32).to_be_bytes()); // i is the iv

        let s = digest_size * blocks;
        let e = s + padding;
        Digest::update(&mut hash, &buf[s..e]);
        buf[s..e].copy_from_slice(&hash.finalize_reset()[..padding]);
    }
}

/// Recovers information from data that was split with `cryptsetup`'s `afsplitter` implementation.
///
/// The blocksize and blocknumber values must be the same as when splitting the information.
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

pub fn split<H>(src: &[u8], blocksize: usize, blocknumbers: usize) -> Vec<u8>
where
    H: Digest + FixedOutputReset,
{
    let mut bufblock = vec![0; blocksize];
    let mut dst = vec![0; blocksize * blocknumbers];
    let mut rng = StdRng::from_os_rng();

    for i in 0..blocknumbers {
        let s = blocksize * i;
        let e = s + blocksize;
        if i < (blocknumbers - 1) {
            rng.fill_bytes(&mut dst[s..e]);
            xor_block(&dst[s..e], &mut bufblock, blocksize);
            diffuse::<H>(&mut bufblock, blocksize);
        } else {
            dst[s..e].copy_from_slice(&src);
            xor_block(&bufblock, &mut dst[s..e], blocksize);
        }
    }

    dst
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn test_af() {
        let key: Vec<u8> = (0..32).collect();
        let blocksize = 32;
        let blocknumbers = 4_000;
        let key_split = split::<Sha256>(&key, blocksize, blocknumbers);
        let key_merged = merge::<Sha256>(&key_split, blocksize, blocknumbers);
        assert_eq!(key, key_merged);
    }
}
