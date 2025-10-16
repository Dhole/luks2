//! To run these tests first create `test.img` with `mk_test_img.sh`.

use luks2::utils::{ascii_cstr_to_str, Bytes};
use luks2::{BinHeader, BinHeaderRaw, Header, JsonHeader, LuksDevice, LUKS_BIN_HEADER_LEN};
use std::convert::TryFrom;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

fn open_test_img() -> File {
    let path = format!("{}/tests/test.img", env!("CARGO_MANIFEST_DIR"));
    File::open(&path).expect("could not open test.img; did you create it?")
}

#[test]
fn test_read_bin_header() {
    let mut f = open_test_img();
    let mut h = vec![0; 4096];
    f.read_exact(&mut h).unwrap();
    let bin_header_raw = BinHeaderRaw::from_slice(&h).unwrap();
    println!("{:?}", bin_header_raw);
    let bin_header = BinHeader::try_from(&bin_header_raw).unwrap();
    println!("{}", bin_header);
}

#[test]
fn test_read_json_header() {
    let mut f = open_test_img();
    f.seek(SeekFrom::Start(4096)).unwrap();

    let mut json_header_bytes = vec![0; 16384 - LUKS_BIN_HEADER_LEN];
    f.read_exact(&mut json_header_bytes).unwrap();
    let json_header_str = ascii_cstr_to_str("json_header", &json_header_bytes).unwrap();
    let json_header = JsonHeader::from_slice(&json_header_str.as_bytes()).unwrap();
    println!("{}", json_header);

    let reencoded_str = serde_json::to_string(&json_header).unwrap();
    let reencoded_decoded_value: serde_json::Value = serde_json::from_str(&reencoded_str).unwrap();
    let decoded_value: serde_json::Value = serde_json::from_str(&json_header_str).unwrap();
    assert_eq!(decoded_value, reencoded_decoded_value);
}

#[test]
fn test_read_header() {
    let f = open_test_img();
    let header = Header::from_reader(f).unwrap();
    println!("{}", header);
}

#[test]
fn test_read_device() {
    let f = open_test_img();
    let mut d = LuksDevice::from_device(f, b"password").unwrap();
    let mut buf = vec![0; 4096];
    d.read_exact(&mut buf).unwrap();
    println!("buf: {:?}", &Bytes(&buf));
}
