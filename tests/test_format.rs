use acid_io::Cursor;
use luks2::LuksDevice;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

#[test]
fn test_format_device() {
    let buf = vec![0; 20 * 1024 * 1024];
    let device = Box::new(Cursor::new(buf.into_boxed_slice()));
    let luks_device = LuksDevice::format_device(device, b"password", 4096).unwrap();

    let _luks_device = luks_device.activate(false, b"password").unwrap();
}
