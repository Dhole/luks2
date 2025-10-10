use crate::utils::{ByteStr, Bytes};
use crate::{CSUM_ALG_LEN, CSUM_LEN};
use alloc::string::String;
use thiserror_no_std::Error;

/// Enum for errors arising during encoding.
#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("String in {ctx} is not ascii")]
    StringNotAscii { ctx: &'static str },

    #[error("String in {ctx} must be shorter than {n} bytes")]
    StringTooLong { ctx: &'static str, n: usize },
}

/// Enum for errors arising during parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Deserialization error: {0}")]
    BincodeError(#[from] bincode::error::DecodeError),

    #[error("Invalid magic value in header: must be \"LUKS\\xba\\xbe\" or \"SKUL\\xba\\xbe\"")]
    InvalidHeaderMagic,

    #[error("Invalid header version: only version 2 is supported, found {0}")]
    InvalidHeaderVersion(u16),

    #[error("JSON deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error(
        "Invalid stripes value in JSON: stripes value of the antiforensic splitter must be \
	4000"
    )]
    InvalidStripes,

    #[error("Invalid sector size in JSON: must be 512, 1024, 2048 or 4096")]
    InvalidSectorSize,

    #[error("Invalid keyslot size in JSON: must be aligned to 4096 bytes")]
    KeyslotNotAligned,

    #[error("Invalid reference in JSON: a nonexistent keyslot or segment was referenced")]
    InvalidReference,

    #[error("Missing null character in C-string {0}")]
    NoNullInCStr(&'static str),

    #[error("Invalid utf8 encoding in C-string {0}: {1}")]
    InvalidUtf8InCStr(&'static str, core::str::Utf8Error),

    #[error("Invalid checksum: calculated={:?}, found={:?}", &Bytes(.calculated), &Bytes(.found))]
    InvalidChecksum {
        calculated: [u8; CSUM_LEN],
        found: [u8; CSUM_LEN],
    },

    #[error("Unsupported checksum algorithm {}", &ByteStr(.0))]
    UnsupportedChecksumAlgorithm([u8; CSUM_ALG_LEN]),

    #[error("String in {ctx} is not ascii")]
    StringNotAscii { ctx: &'static str },

    #[error("MissingUuid from BinHeader")]
    MissingUuid,
}

/// Enum for errors arising during interaction with a [`LuksDevice`](crate::LuksDevice).
#[derive(Debug, Error)]
pub enum LuksError {
    #[error("IO error: {0}")]
    IoError(#[from] acid_io::Error),

    #[error("Parsing error: {0}")]
    ParseError(#[from] self::ParseError),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Unsupported hash function used by anti-forensic splitter: {0}")]
    UnsupportedAfHash(String),

    #[error("Unsupported hash function used by digest: {0}")]
    UnsupportedDigestHash(String),

    #[error("Unsupported key size: {0}")]
    UnsupportedKeySize(u32),

    #[error("Could not deserialize base64: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Could not apply hash function: {0}")]
    HashError(#[from] argon2::Error),

    #[error("Invalid key length: {0}. Valid lengths are 32 for AES-128-XTS or 64 for AES-256-XTS")]
    InvalidKeyLength(usize),

    #[cfg(feature = "std")]
    #[error("Error during password input: {0}")]
    PasswordError(#[from] crossterm::ErrorKind),
}
