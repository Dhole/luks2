use crate::utils::{ByteStr, Bytes};
use crate::{CSUM_ALG_LEN, CSUM_LEN};
use core::fmt;

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
#[derive(Error)]
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
	4000, found {0}"
    )]
    InvalidStripes(u16),

    #[error("Invalid keyslot priority value in JSON: must be 0, 1 or 2; found {0}")]
    InvalidPriority(u8),

    #[error("Invalid sector size in JSON: must be 512, 1024, 2048 or 4096; found {0}")]
    InvalidSectorSize(u16),

    #[error("Invalid keyslot size in JSON: must be aligned to 4096 bytes")]
    KeyslotNotAligned,

    #[error("Invalid reference in JSON: a nonexistent keyslot or segment was referenced")]
    InvalidReference,

    #[error("Invalid reference in JSON: keyslot {0} is nonexistent")]
    InvalidKeyslotReference(usize),

    #[error("Invalid reference in JSON: segment {0} is nonexistent")]
    InvalidSegmentReference(usize),

    #[error("Invalid string in {ctx}: missing null character")]
    NoNullInCStr { ctx: &'static str },

    #[error("Invalid header checksum: calculated={:?}, found={:?}", &Bytes(.calculated), &Bytes(.found))]
    InvalidChecksum {
        calculated: [u8; CSUM_LEN],
        found: [u8; CSUM_LEN],
    },

    #[error("Unsupported config requirement in JSON: {0}")]
    UnsupportedRequirement(String),

    #[error("Unsupported checksum algorithm: {}", &ByteStr(.0))]
    UnsupportedChecksumAlgorithm([u8; CSUM_ALG_LEN]),

    #[error("Invalid string in {ctx}: not ascii")]
    StringNotAscii { ctx: &'static str },

    #[error("Missing uuid from BinHeader")]
    MissingUuid,
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
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

    #[error("Unsupported hash function used by pbkdf2: {0}")]
    UnsupportedPbkdf2Hash(String),

    #[error("Unsupported hash function used by digest: {0}")]
    UnsupportedDigestHash(String),

    #[error("Unsupported key size for {0} encryption: {1}")]
    UnsupportedKeySize(&'static str, usize),

    #[error("Unsupported area encryption: {0}")]
    UnsupportedAreaEncryption(String),

    #[error("Unsupported segment encryption: {0}")]
    UnsupportedSegmentEncryption(String),

    #[error("Could not deserialize base64: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Could not apply hash function: {0}")]
    HashError(#[from] argon2::Error),

    #[error("Invalid key length: {0}. Valid lengths are 32 for AES-128-XTS or 64 for AES-256-XTS")]
    InvalidKeyLength(usize),

    #[error("Invalid segment size: {segment_size} not multiple of sector size: {sector_size}")]
    InvalidSegmentSize { segment_size: u64, sector_size: u64 },

    #[error("INvalid header offset: expected 0x{expected:x} but found 0x{found:x}")]
    InvalidHeaderOffset { expected: u64, found: u64 },

    #[cfg(feature = "std")]
    #[error("Error during password input: {0}")]
    PasswordError(#[from] crossterm::ErrorKind),

    #[error("No Keyslots")]
    NoKeyslots,

    #[error("No Segments")]
    NoSegments,

    #[error("No Digests")]
    NoDigests,

    #[error("No Digest for Segment 0")]
    NoDigestsSegment0,

    #[error(
        "Found existing header in device.  To format first clear the first segment of the device"
    )]
    FoundExistingHeader,
}
