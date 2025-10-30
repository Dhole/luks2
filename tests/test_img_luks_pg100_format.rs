use acid_io::Cursor;
use luks2::LuksDevice;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

const FILE_SIZE: usize = 20 * 1024 * 1024;
const SIZE: usize = 4 * 1024 * 1024;

#[test]
fn test_format_device() {
    let path = format!(
        "{}/test-data/test-luks-blank2.img",
        env!("CARGO_MANIFEST_DIR"),
    );
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let zeroes = vec![0; FILE_SIZE];
    file.write_all(&zeroes).unwrap();

    let luks_device = LuksDevice::format_device(Box::new(file), b"password", 4096).unwrap();
    let _luks_device = luks_device.activate(false, b"password").unwrap();
}

/// Run after `encrypt-test-luks-format.sh`
#[test]
fn test_read_device() {
    let pg100_path = format!("{}/test-data/pg100.txt", env!("CARGO_MANIFEST_DIR"));
    let mut pg100 = File::open(&pg100_path).unwrap();
    let mut expected_buf = Vec::new();
    pg100.read_to_end(&mut expected_buf).unwrap();
    expected_buf.truncate(SIZE);

    let path = format!(
        "{}/test-data/test-luks-write2.img",
        env!("CARGO_MANIFEST_DIR"),
    );
    let f = Box::new(File::open(&path).unwrap());

    let mut d = LuksDevice::from_device(f)
        .unwrap()
        .activate(true, b"password")
        .unwrap();

    let mut decrypted_buf = Vec::new();
    d.read_to_end(&mut decrypted_buf).unwrap();

    assert_eq!(expected_buf, decrypted_buf);
}
