use luks2::{LuksBinHeader, LuksHeader};
use std::{fs::File, io::Read};

#[test]
fn test_luks_header() {
    // create test.iso via `fallocate -l 16M test.iso && cryptsetup luksFormat test.iso` with the password "password"
    let path = format!("{}/tests/test.iso", env!("CARGO_MANIFEST_DIR"));
    let mut f = File::open(&path).expect("could not open test.iso; did you create it?");
    let mut h = vec![0; 4096];
    f.read_exact(&mut h).unwrap();
    let bin_header = LuksBinHeader::from_slice(&h).unwrap();
    println!("{}", bin_header);
    drop(f);

    let mut f = File::open(&path).expect("could not open test.iso; did you create it?");
    let header = LuksHeader::from_reader(&mut f).unwrap();
}
