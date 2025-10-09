use luks2::{LuksDevice, LuksHeader};
use std::{
    fs::File,
    io::{Cursor, Read},
};

#[test]
fn test_luks_device() {
    // create test.iso via `fallocate -l 16M test.iso && cryptsetup luksFormat test.iso` with the password "password"
    let path = format!("{}/tests/test.iso", env!("CARGO_MANIFEST_DIR"));
    let mut f = File::open(path).expect("could not open test.iso; did you create it?");
    let mut buf = vec![0; 16 * 1024 * 1024];
    f.read_exact(&mut buf)
        .expect("could not read from test.iso");
    let f = Cursor::new(buf);
    let _luks_device = LuksDevice::from_device(f, b"password", 512).unwrap();
}

#[test]
fn test_luks_header() {
    // create test.iso via `fallocate -l 16M test.iso && cryptsetup luksFormat test.iso` with the password "password"
    let path = format!("{}/tests/test.iso", env!("CARGO_MANIFEST_DIR"));
    let mut f = File::open(path).expect("could not open test.iso; did you create it?");
    let mut h = vec![0; 4096];
    f.read_exact(&mut h).unwrap();
    let header = LuksHeader::from_slice(&h).unwrap();
    println!("{:#?}", header);
    println!("{}", header);
}
