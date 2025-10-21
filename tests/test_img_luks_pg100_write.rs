//! These tests require the test artifacts made with `mk-img-test-luks-blank.sh` and
//! `decrypt-test-luks-pg100-write.sh`

use acid_io::Cursor;
use luks2::LuksDevice;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

fn open_test_img() -> Box<File> {
    let path_src = format!(
        "{}/test-data/test-luks-blank.img",
        env!("CARGO_MANIFEST_DIR"),
    );
    let path_dst = format!(
        "{}/test-data/test-luks-write.img",
        env!("CARGO_MANIFEST_DIR"),
    );
    fs::copy(&path_src, &path_dst)
        .expect(&format!("could not open {path_src}; did you create it?"));
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path_dst)
        .unwrap();
    let size = f.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(size, 20 * 1024 * 1024);
    f.seek(SeekFrom::Start(0)).unwrap();
    Box::new(f)
}

/// Run after generating the artifacts with `mk-img-test-luks-blank.sh`
#[test]
fn test_write_device() {
    // The source file is 5.2M but the luks test segment only has 4M so we truncate the file after
    // reading it.
    let pg100_path = format!("{}/test-data/pg100.txt", env!("CARGO_MANIFEST_DIR"));
    let mut pg100 = File::open(&pg100_path).unwrap();
    let mut pg100_buf = Vec::new();
    pg100.read_to_end(&mut pg100_buf).unwrap();
    pg100_buf.truncate(4 * 1024 * 1024);
    let mut pg100 = Cursor::new(pg100_buf);

    let f = open_test_img();
    let mut d = LuksDevice::from_device(f)
        .unwrap()
        .activate(true, b"password")
        .unwrap();

    // write `d` with zeroes until the end
    let out = vec![0; 4 * 1024 * 1024];
    d.write_all(&out).unwrap();
    println!("write_all done");
    d.seek(SeekFrom::Start(0)).unwrap();

    // Write from `pg100.txt` to various locations in the Luks device and at the same time to a
    // plaintext file for later comparison.
    let mut out = Cursor::new(out);
    for (len, seek) in &[
        (1_000, SeekFrom::Start(0)),
        (1_000, SeekFrom::Start(7_000)),
        (1_000, SeekFrom::End(-11_000)),
        (1_000, SeekFrom::Current(1_000)),
        (1_000, SeekFrom::Current(-10_000)),
    ] {
        let mut buf = vec![0; *len];
        pg100.seek(*seek).unwrap();
        pg100.read_exact(&mut buf).unwrap();

        d.seek(*seek).unwrap();
        d.write_all(&buf).unwrap();

        out.seek(*seek).unwrap();
        out.write_all(&buf).unwrap();
    }

    let out_path = format!(
        "{}/test-data/pg100-expected.img",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::write(out_path, out.get_ref()).unwrap();
}

/// Run after `test_write_device`
#[test]
fn test_read_device() {
    let expected_path = format!(
        "{}/test-data/pg100-expected.img",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut expected = File::open(&expected_path).unwrap();
    let mut expected_buf = Vec::new();
    expected.read_to_end(&mut expected_buf).unwrap();

    let path = format!(
        "{}/test-data/test-luks-write.img",
        env!("CARGO_MANIFEST_DIR"),
    );
    let f = Box::new(File::open(&path).unwrap());

    let mut d = LuksDevice::from_device(f)
        .unwrap()
        .activate(true, b"password")
        .unwrap();

    let mut decrypted_buf = vec![0; 4 * 1024 * 1024];
    d.read_exact(&mut decrypted_buf).unwrap();

    assert_eq!(expected_buf, decrypted_buf);
}

/// Run after `test_write_device` and generating the artifacts with `decrypt-test-luks-pg100-write.sh`
#[test]
fn test_verify_decryption() {
    let expected_path = format!(
        "{}/test-data/pg100-expected.img",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut expected = File::open(&expected_path).unwrap();
    let mut expected_buf = Vec::new();
    expected.read_to_end(&mut expected_buf).unwrap();

    let decrypted_path = format!(
        "{}/test-data/pg100-decrypted.img",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut decrypted = File::open(&decrypted_path).unwrap();
    let mut decrypted_buf = Vec::new();
    decrypted.read_exact(&mut decrypted_buf).unwrap();

    assert_eq!(expected_buf, decrypted_buf);
}
