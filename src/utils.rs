use core::fmt::{self, Debug, Display};

pub(crate) struct ByteStr<'a>(pub &'a [u8]);

impl<'a> Debug for ByteStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for b in self.0 {
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

pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl<'a> Debug for Bytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", *b)?;
        }
        Ok(())
    }
}
