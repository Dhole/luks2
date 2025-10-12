use luks2::{BinHeader, BinHeaderRaw, Header};
use std::convert::TryFrom;
use std::{fs::File, io::Read};

#[test]
fn test_luks_header() {
    // create test.iso via `fallocate -l 16M test.iso && cryptsetup luksFormat test.iso` with the password "password"
    let path = format!("{}/tests/test.iso", env!("CARGO_MANIFEST_DIR"));
    let mut f = File::open(&path).expect("could not open test.iso; did you create it?");
    let mut h = vec![0; 4096];
    f.read_exact(&mut h).unwrap();
    let bin_header_raw = BinHeaderRaw::from_slice(&h).unwrap();
    println!("{:?}", bin_header_raw);
    let bin_header = BinHeader::try_from(&bin_header_raw).unwrap();
    println!("{}", bin_header);
    drop(f);

    let mut f = File::open(&path).expect("could not open test.iso; did you create it?");
    let header = Header::from_reader(&mut f).unwrap();
}
