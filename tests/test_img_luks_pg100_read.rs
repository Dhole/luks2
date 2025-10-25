//! These tests require the test artifacts made with `mk-img-test-luks-pg100.sh`.

use acid_io::Cursor;
use luks2::utils::ascii_cstr_to_str;
use luks2::{BinHeaderRaw, HeaderBin, HeaderJson, LuksDevice, LUKS_BIN_HEADER_LEN};
use std::convert::TryFrom;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

const SIZE: usize = 4 * 1024 * 1024;

fn open_test_img(i: usize) -> Box<File> {
    let path = format!(
        "{}/test-data/test-luks-pg100.{}.img",
        env!("CARGO_MANIFEST_DIR"),
        i
    );
    let mut f = File::open(&path).expect(&format!("could not open {path}; did you create it?"));
    let size = f.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(size, 20 * 1024 * 1024);
    f.seek(SeekFrom::Start(0)).unwrap();
    Box::new(f)
}

#[test]
fn test_read_bin_header() {
    let mut f = open_test_img(0);
    let mut h = vec![0; LUKS_BIN_HEADER_LEN];
    f.read_exact(&mut h).unwrap();
    let bin_header_raw = BinHeaderRaw::from_slice(&h).unwrap();
    println!("{:?}", bin_header_raw);
    let bin_header = HeaderBin::try_from(&bin_header_raw).unwrap();
    println!("{}", bin_header);
}

#[test]
fn test_read_json_header() {
    let mut f = open_test_img(0);
    f.seek(SeekFrom::Start(LUKS_BIN_HEADER_LEN as u64)).unwrap();

    let mut json_header_bytes = vec![0; 16384 - LUKS_BIN_HEADER_LEN];
    f.read_exact(&mut json_header_bytes).unwrap();
    let json_header_str = ascii_cstr_to_str("json_header", &json_header_bytes).unwrap();
    let json_header = HeaderJson::from_slice(&json_header_str.as_bytes()).unwrap();
    println!("{}", json_header);
    assert_eq!(json_header.segments[0].offset(), 16 * 1024 * 1024);

    let reencoded_str = serde_json::to_string(&json_header).unwrap();
    let reencoded_decoded_value: serde_json::Value = serde_json::from_str(&reencoded_str).unwrap();
    let decoded_value: serde_json::Value = serde_json::from_str(&json_header_str).unwrap();
    assert_eq!(decoded_value, reencoded_decoded_value);
}

#[test]
fn test_read_header() {
    let f = open_test_img(0);
    let header = LuksDevice::from_device(f).unwrap();
    println!("{}", header);
}

#[test]
fn test_activate_device() {
    for i in 0..=5 {
        let f = open_test_img(i);
        LuksDevice::from_device(f)
            .unwrap()
            .activate(false, b"password")
            .unwrap();
    }
}

#[test]
fn test_read_device_ok() {
    // The source file is 5.2M but the luks test segment only has 4M so we truncate the file after
    // reading it.
    let pg100_path = format!("{}/test-data/pg100.txt", env!("CARGO_MANIFEST_DIR"));
    let mut pg100 = File::open(&pg100_path).unwrap();
    let mut pg100_buf = Vec::new();
    pg100.read_to_end(&mut pg100_buf).unwrap();
    pg100_buf.truncate(SIZE);
    let mut pg100 = Cursor::new(pg100_buf);

    for i in 0..=5 {
        let f = open_test_img(i);
        let mut d = LuksDevice::from_device(f)
            .unwrap()
            .activate(false, b"password")
            .unwrap();

        for (len, seek) in &[
            (1_000, SeekFrom::Start(0)),
            (1_000, SeekFrom::Start(7_000)),
            (1_000, SeekFrom::End(-11_000)),
            (1_000, SeekFrom::Current(1_000)),
            (1_000, SeekFrom::Current(-10_000)),
        ] {
            let mut buf_src = vec![0; *len];
            pg100.seek(*seek).unwrap();
            pg100.read_exact(&mut buf_src).unwrap();

            let mut buf_dec = vec![0; *len];
            d.seek(*seek).unwrap();
            d.read_exact(&mut buf_dec).unwrap();

            assert_eq!(buf_src, buf_dec);
        }
    }
}

#[test]
fn test_read_device_edge() {
    let pg100_path = format!("{}/test-data/pg100.txt", env!("CARGO_MANIFEST_DIR"));
    let mut pg100 = File::open(&pg100_path).unwrap();
    let mut pg100_buf = Vec::new();
    pg100.read_to_end(&mut pg100_buf).unwrap();
    pg100_buf.truncate(SIZE);
    let mut pg100 = Cursor::new(pg100_buf);

    let f = open_test_img(0);
    let mut d = LuksDevice::from_device(f)
        .unwrap()
        .activate(false, b"password")
        .unwrap();

    let mut buf = vec![0; 128];

    let size = SIZE as u64;
    // Read at the end
    let o = pg100.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(size, o);
    let n = pg100.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let n = pg100.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let o = d.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(size, o);
    let n = d.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let n = d.read(&mut buf).unwrap();
    assert_eq!(0, n);

    // Read after the end
    let o = pg100.seek(SeekFrom::End(100)).unwrap();
    assert_eq!(size + 100, o);
    let n = pg100.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let o = d.seek(SeekFrom::End(100)).unwrap();
    assert_eq!(size + 100, o);
    let n = d.read(&mut buf).unwrap();
    assert_eq!(0, n);

    // Read and reach the end
    let o = pg100.seek(SeekFrom::Current(-10)).unwrap();
    assert_eq!(size + 90, o);
    let n = pg100.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let o = d.seek(SeekFrom::Current(-10)).unwrap();
    assert_eq!(size + 90, o);
    let n = d.read(&mut buf).unwrap();
    assert_eq!(0, n);
    let buf_dec = buf.clone();
    assert_eq!(buf[..10], buf_dec[..10]);

    // Seek to before the beginning from End
    let e = pg100.seek(SeekFrom::End(-20 * 1024 * 1024)).unwrap_err();
    assert_eq!(acid_io::ErrorKind::InvalidInput, e.kind());
    let e = d.seek(SeekFrom::End(-20 * 1024 * 1024)).unwrap_err();
    assert_eq!(acid_io::ErrorKind::InvalidInput, e.kind());

    let o = d.seek(SeekFrom::Current(0)).unwrap();
    assert_eq!(size + 90, o);
    let o = pg100.seek(SeekFrom::Current(0)).unwrap();
    assert_eq!(size + 90, o);

    // Seek to before the beginning from Cur
    pg100.seek(SeekFrom::Start(0)).unwrap();
    let e = pg100.seek(SeekFrom::Current(-1)).unwrap_err();
    assert_eq!(acid_io::ErrorKind::InvalidInput, e.kind());
    d.seek(SeekFrom::Start(0)).unwrap();
    let e = d.seek(SeekFrom::Current(-1)).unwrap_err();
    assert_eq!(acid_io::ErrorKind::InvalidInput, e.kind());
}
