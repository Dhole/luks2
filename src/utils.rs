use core::ffi::CStr;
use core::fmt::{self, Debug, Display};

use crate::error::{EncodeError, ParseError};

pub struct ByteStr<'a>(pub &'a [u8]);

impl<'a> Debug for ByteStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for b in self.0 {
            if b.is_ascii_graphic() {
                write!(f, "{}", char::from(*b))?;
            } else if *b == b'\t' {
                write!(f, "\\t")?;
            } else if *b == b'\n' {
                write!(f, "\\n")?;
            } else if *b == b'\r' {
                write!(f, "\\r")?;
            } else if *b == b' ' {
                write!(f, " ")?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        write!(f, "\"")?;
        Ok(())
    }
}

impl<'a> Display for ByteStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for b in self.0 {
            if *b == 0 {
                break;
            }
            if b.is_ascii_graphic() {
                write!(f, "{}", char::from(*b))?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        write!(f, "\"")?;
        Ok(())
    }
}

pub struct Bytes<'a>(pub &'a [u8]);

impl<'a> Debug for Bytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", *b)?;
        }
        Ok(())
    }
}

pub fn str_to_ascii_array<const N: usize>(
    ctx: &'static str,
    s: &str,
) -> Result<[u8; N], EncodeError> {
    if !s.is_ascii() {
        return Err(EncodeError::StringNotAscii { ctx });
    }
    let byte_str = s.as_bytes();
    if !(byte_str.len() < N) {
        return Err(EncodeError::StringTooLong { ctx, n: N });
    }
    let mut array = [0; N];
    array[..byte_str.len()].copy_from_slice(byte_str);
    Ok(array)
}

pub fn ascii_cstr_to_str<'a>(ctx: &'static str, s: &'a [u8]) -> Result<&'a str, ParseError> {
    if !s.is_ascii() {
        return Err(ParseError::StringNotAscii { ctx });
    }
    Ok(CStr::from_bytes_until_nul(s)
        .map_err(|_| ParseError::NoNullInCStr { ctx })?
        .to_str()
        .expect("ascii is subset of UTF-8"))
}

pub fn ascii_cstr_to_string(ctx: &'static str, s: &[u8]) -> Result<Option<String>, ParseError> {
    ascii_cstr_to_str(ctx, s).map(|s| if s == "" { None } else { Some(s.to_string()) })
}
