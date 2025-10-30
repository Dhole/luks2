#![cfg_attr(not(feature = "std"), no_std)]

//! This crate defines data structures to interact with a LUKS2 partition.
//!
//! See the `examples/` folder for how to use this with a real partition
//! or an .iso file on Linux and Windows (all examples need to be modified
//! or require creating some files before they work correctly).
//!
//! You'll probably want to compile in release mode most of the time, or else
//! the master key extraction (which happens everytime a `LuksDevice` is
//! created) will take quite a long time.

extern crate alloc;

/// Recover information that was split antiforensically.
pub mod af;
/// Custom error types.
pub mod error;
/// Helper utilities
pub mod utils;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{
    convert::TryFrom,
    fmt::{Debug, Display},
    mem,
    str::FromStr,
};
use rand::prelude::*;
use uuid::Uuid;

use crate::error::{EncodeError, LuksError, ParseError};
use crate::utils::{ascii_cstr_to_str, ascii_cstr_to_string, str_to_ascii_array};

use acid_io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom, Write};
use aes::{cipher::KeyInit, Aes128, Aes256};
use bincode::{Decode, Encode};
use crypto_common::Output;
use digest;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use secrecy::{CloneableSecret, DebugSecret, ExposeSecret, Secret, Zeroize};
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize, Serializer,
};
use sha1::Sha1;
use sha2::Sha256;
use utils::Bytes;
use xts_mode::{get_tweak_default, Xts128};

pub const MAGIC_1ST: &[u8] = b"LUKS\xba\xbe";
pub const MAGIC_2ND: &[u8] = b"SKUL\xba\xbe";
pub const MAGIC_LEN: usize = 6;
pub const UUID_LEN: usize = 40;
pub const LABEL_LEN: usize = 48;
pub const SALT_LEN: usize = 64;
pub const CSUM_ALG_LEN: usize = 32;
pub const CSUM_LEN: usize = 64;
pub const LUKS_BIN_HEADER_LEN: usize = 4096;
pub const LUKS_HEADER_LEN: usize = 16 * 1024 * 1024;

/// Pairs of secondary header offset VS JSON area size
pub(crate) const PRIMARY_LEN_JSON_LEN: &[(usize, usize)] = &[
    (0x004000, 12 * 1024),
    (0x008000, 28 * 1024),
    (0x010000, 60 * 1024),
    (0x020000, 124 * 1024),
    (0x040000, 252 * 1024),
    (0x080000, 508 * 1024),
    (0x100000, 1020 * 1024),
    (0x200000, 2044 * 1024),
    (0x400000, 4092 * 1024),
];

#[derive(Debug, Clone, PartialEq)]
pub enum Magic {
    First,
    Second,
}

impl Magic {
    pub fn to_byte_array(&self) -> [u8; MAGIC_LEN] {
        let mut array = [0; MAGIC_LEN];
        array.copy_from_slice(match self {
            Self::First => MAGIC_1ST,
            Self::Second => MAGIC_2ND,
        });
        array
    }
    pub fn from_byte_array(s: &[u8; MAGIC_LEN]) -> Option<Self> {
        if s == MAGIC_1ST {
            Some(Self::First)
        } else if s == MAGIC_2ND {
            Some(Self::Second)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Checksum {
    Sha256(Output<Sha256>),
}

impl Display for Checksum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sha256(csum) => write!(f, "sha256:{:?}", &Bytes(csum.as_slice())),
        }
    }
}

impl Checksum {
    pub fn to_byte_arrays(&self) -> ([u8; CSUM_ALG_LEN], [u8; CSUM_LEN]) {
        let (s_csum_alg, s_csum) = match self {
            Self::Sha256(csum) => (b"sha256\0", csum.as_slice()),
        };
        let mut csum_alg = [0; CSUM_ALG_LEN];
        let mut csum = [0; CSUM_LEN];
        csum_alg[..s_csum_alg.len()].copy_from_slice(s_csum_alg);
        csum[..s_csum.len()].copy_from_slice(s_csum);
        (csum_alg, csum)
    }
    pub fn from_byte_arrays(csum_alg: &[u8; CSUM_ALG_LEN], csum: &[u8; CSUM_LEN]) -> Option<Self> {
        if csum_alg.starts_with(b"sha256\0") {
            Some(Self::Sha256(*Output::<Sha256>::from_slice(&csum[..32])))
        } else {
            None
        }
    }
}

/// Section 2.1
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderBin {
    pub magic: Magic,
    /// header size plus JSON area in bytes
    pub hdr_size: u64,
    /// sequence ID, increased on update
    pub seqid: u64,
    /// ASCII label or empty
    pub label: Option<String>,
    pub checksum: Checksum,
    /// salt, unique for every header
    pub salt: [u8; SALT_LEN],
    /// UUID of device
    pub uuid: String,
    /// owner subsystem label or empty
    pub subsystem: Option<String>,
    /// offset from device start in bytes
    pub hdr_offset: u64,
}

impl Display for HeaderBin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Luks BinHeader:")?;
        writeln!(f, "\tlocation: {:?}", self.magic)?;
        writeln!(f, "\tversion: 2")?;
        writeln!(f, "\thdr_size: {}", self.hdr_size)?;
        writeln!(f, "\tseqid: {}", self.seqid)?;
        writeln!(f, "\tlabel: {:?}", self.label)?;
        writeln!(f, "\tchecksum: {}", self.checksum)?;
        writeln!(f, "\tsalt: {:?}", &Bytes(&self.salt))?;
        writeln!(f, "\tuuid: {}", self.uuid)?;
        writeln!(f, "\tsubsystem: {:?}", self.subsystem)?;
        writeln!(f, "\thdr_offset: 0x{:016x}", self.hdr_offset)?;
        Ok(())
    }
}

impl TryFrom<&HeaderBin> for BinHeaderRaw {
    type Error = EncodeError;
    fn try_from(h: &HeaderBin) -> Result<Self, Self::Error> {
        fn opt_string_to_str(s: &Option<String>) -> &str {
            s.as_ref().map(|s| s.as_str()).unwrap_or("")
        }
        let (csum_alg, csum) = h.checksum.to_byte_arrays();
        Ok(Self {
            magic: h.magic.to_byte_array(),
            version: 2,
            hdr_size: h.hdr_size,
            seqid: h.seqid,
            label: str_to_ascii_array("BinHeader.label", opt_string_to_str(&h.label))?,
            csum_alg,
            salt: h.salt,
            uuid: str_to_ascii_array("BinHeader.uuid", &h.uuid)?,
            subsystem: str_to_ascii_array("BinHeader.subsystem", opt_string_to_str(&h.subsystem))?,
            hdr_offset: h.hdr_offset,
            _padding: [0; 184],
            csum,
            _padding4069: [0; 7 * 512],
        })
    }
}

impl TryFrom<&BinHeaderRaw> for HeaderBin {
    type Error = ParseError;
    fn try_from(h: &BinHeaderRaw) -> Result<Self, Self::Error> {
        // check header version
        if h.version != 2 {
            return Err(ParseError::InvalidHeaderVersion(h.version));
        }
        Ok(Self {
            magic: Magic::from_byte_array(&h.magic).ok_or(ParseError::InvalidHeaderMagic)?,
            hdr_size: h.hdr_size,
            seqid: h.seqid,
            label: ascii_cstr_to_string("BinHeader.label", &h.label)?,
            checksum: Checksum::from_byte_arrays(&h.csum_alg, &h.csum)
                .ok_or(ParseError::UnsupportedChecksumAlgorithm(h.csum_alg))?,
            salt: h.salt,
            uuid: ascii_cstr_to_string("BinHeader.uuid", &h.uuid)?
                .ok_or(ParseError::MissingUuid)?,
            subsystem: ascii_cstr_to_string("BinHeader.subsystem", &h.subsystem)?,
            hdr_offset: h.hdr_offset,
        })
    }
}

/// A LUKS2 header as described
/// [here](https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
/// Section 2.1
#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub struct BinHeaderRaw {
    /// must be `MAGIC_1ST` or `MAGIC_2ND`
    pub magic: [u8; MAGIC_LEN],
    /// Version 2
    pub version: u16,
    /// header size plus JSON area in bytes
    pub hdr_size: u64,
    /// sequence ID, increased on update
    pub seqid: u64,
    /// ASCII label or empty
    pub label: [u8; LABEL_LEN],
    /// checksum algorithm, "sha256"
    pub csum_alg: [u8; CSUM_ALG_LEN],
    /// salt, unique for every header
    pub salt: [u8; SALT_LEN],
    /// UUID of device
    pub uuid: [u8; UUID_LEN],
    /// owner subsystem label or empty
    pub subsystem: [u8; LABEL_LEN],
    /// offset from device start in bytes
    pub hdr_offset: u64,
    // must be zeroed
    _padding: [u8; 184],
    /// header checksum
    pub csum: [u8; CSUM_LEN],
    // Padding, must be zeroed
    _padding4069: [u8; 7 * 512],
}

impl BinHeaderRaw {
    /// Attempt to read a LUKS2 header from a reader.
    ///
    /// Note: a LUKS2 header is always exactly 4096 bytes long.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ParseError> {
        let options = bincode::config::legacy()
            .with_big_endian()
            .with_fixed_int_encoding();
        let h: Self = bincode::decode_from_slice(slice, options)?.0;
        Ok(h)
    }

    pub fn write_slice(&self, slice: &mut [u8]) -> Result<(), bincode::error::EncodeError> {
        let options = bincode::config::legacy()
            .with_big_endian()
            .with_fixed_int_encoding();
        bincode::encode_into_slice(self, slice, options).map(|_| ())
    }
}

pub(crate) mod bytes_base64 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = <&'de str>::deserialize(deserializer)?;
        base64::decode(s).map_err(de::Error::custom)
    }
}

pub(crate) mod type_str {
    use alloc::string::ToString;
    use core::fmt::Display;
    use core::str::FromStr;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T: ToString>(v: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&v.to_string())
    }

    // taken from https://github.com/serde-rs/json/issues/317#issuecomment-300251188
    pub fn deserialize<'de, T: FromStr, D>(deserializer: D) -> Result<T, D::Error>
    where
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        T::from_str(&s).map_err(de::Error::custom)
    }
}

pub(crate) mod list {
    use alloc::collections::BTreeMap;
    use serde::{de, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, T: Serialize>(
        list: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(list.len()))?;
        for (i, elem) in list.iter().enumerate() {
            map.serialize_entry(&i.to_string(), elem)?;
        }
        map.end()
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<T>, D::Error> {
        let mut map = BTreeMap::<String, T>::deserialize(deserializer)?;
        let mut list = Vec::with_capacity(map.len());
        for i in 0..map.len() {
            let elem = map.remove(&i.to_string()).ok_or_else(|| {
                de::Error::custom(format!("missing key \"{i}\" from JSON object list"))
            })?;
            list.push(elem);
        }
        Ok(list)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Encryption {
    AesXtsPlain64,
    Unknown(String),
}

impl Serialize for Encryption {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::AesXtsPlain64 => "aes-xts-plain64",
            Self::Unknown(s) => s.as_str(),
        })
    }
}

impl<'de> Deserialize<'de> for Encryption {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Encryption, D::Error> {
        match <&'de str>::deserialize(deserializer)? {
            "aes-xts-plain64" => Ok(Self::AesXtsPlain64),
            s => Ok(Self::Unknown(s.to_string())),
        }
    }
}

/// Only the `raw` type is currently used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AreaTypeData {
    Raw {
        /// The area encryption algorithm, in dm-crypt notation (e. g. "aes-xts-plain64").
        encryption: Encryption,
        /// The area encryption key size, in bytes.
        key_size: usize,
    },
}

/// Information on the allocated area in the binary keyslots area of a [`Keyslot`].
/// Section 3.2.3
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Area {
    #[serde(flatten)]
    type_data: AreaTypeData,
    /// The offset from the device start to the beginning of the binary area in bytes.
    #[serde(with = "type_str")]
    offset: u64,
    /// The area size in bytes.
    #[serde(with = "type_str")]
    size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Hash {
    Sha256,
    Sha1,
    Unknown(String),
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Unknown(s) => s.as_str(),
        })
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
        match <&'de str>::deserialize(deserializer)? {
            "sha256" => Ok(Self::Sha256),
            "sha1" => Ok(Self::Sha1),
            s => Ok(Self::Unknown(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stripes {}

impl Stripes {
    pub fn as_usize(&self) -> usize {
        4_000
    }
}

impl Serialize for Stripes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.as_usize() as u16)
    }
}

impl<'de> Deserialize<'de> for Stripes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Stripes, D::Error> {
        match u16::deserialize(deserializer)? {
            4_000 => Ok(Stripes {}),
            v => Err(de::Error::custom(ParseError::InvalidStripes(v))),
        }
    }
}

/// An anti-forensic splitter of a [`Keyslot`]. See
/// [the LUKS1 spec](https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification)
/// for more information.
/// Section 3.2.4
///
/// Only the `luks1` type compatible with LUKS1 is currently used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum Af {
    Luks1 {
        /// The number of stripes, for historical reasons only the 4000 value is supported.
        stripes: Stripes,
        /// The hash algorithm used.
        hash: Hash,
    },
}

/// Only the `raw` type is currently used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum KdfTypeData {
    Pbkdf2 {
        /// The hash algorithm for the PKBDF.
        hash: Hash,
        /// The PBKDF2 iterations count.
        iterations: u32,
    },
    Argon2i {
        /// The time cost (in fact the iterations).
        time: u32,
        /// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
        memory: u32,
        /// The required nuber of threads (CPU cores number cost). If not available, unlocking
        /// will be slower.
        cpus: u32,
    },
    Argon2id {
        /// The time cost (in fact the iterations).
        time: u32,
        /// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
        memory: u32,
        /// The required nuber of threads (CPU cores number cost). If not available, unlocking
        /// will be slower.
        cpus: u32,
    },
}

/// Stores information on the PBKDF type and parameters of a [`Keyslot`].
/// Section 3.2.5
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Kdf {
    #[serde(flatten)]
    type_data: KdfTypeData,
    /// The salt for the PBKDF in base64 (binary data).
    #[serde(with = "bytes_base64")]
    salt: Vec<u8>,
}

/// The priority of a [`Keyslot`].
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum Priority {
    /// The slot should be used only if explicitly stated.
    Ignore,
    /// Normal priority keyslot.
    #[default]
    Normal,
    /// Tried before normal priority keyslots.
    High,
}

impl Serialize for Priority {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::Ignore => 0,
            Self::Normal => 1,
            Self::High => 2,
        })
    }
}

impl<'de> Deserialize<'de> for Priority {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Priority, D::Error> {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Ignore),
            1 => Ok(Self::Normal),
            2 => Ok(Self::High),
            p => Err(de::Error::custom(ParseError::InvalidPriority(p))),
        }
    }
}

/// Section 3.2.1
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[serde(rename_all = "snake_case")]
pub enum KeyslotTypeData {
    Luks2 {
        /// The PBKDF type and parameters used.
        kdf: Kdf,
        /// The anti-forensic splitter.
        af: Af,
    },
}

/// A keyslot contains information about stored keys – areas, where binary keyslot data are located,
/// encryption and anti-forensic function used, password-based key derivation function (PBKDF) and
/// related parameters.
/// Section 3.2
///
/// Only the `luks2` type is currently used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[serde(rename_all = "snake_case")]
pub struct Keyslot {
    #[serde(flatten)]
    type_data: KeyslotTypeData,
    /// The size of the key stored in the slot, in bytes.
    key_size: usize,
    /// The allocated area in the binary keyslots area.
    area: Area,
    /// The keyslot priority (optional).
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<Priority>,
}

/// The size of a [`Segment`].
#[derive(Clone, Debug, PartialEq)]
pub enum SegmentSize {
    /// Signals that the size of the underlying device should be used (dynamic resize).
    Dynamic,
    /// The size in bytes.
    Fixed(u64),
}

impl Serialize for SegmentSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Dynamic => serializer.serialize_str("dynamic"),
            Self::Fixed(n) => serializer.serialize_str(&n.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for SegmentSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SegmentSize, D::Error> {
        match <&'de str>::deserialize(deserializer)? {
            "dynamic" => Ok(Self::Dynamic),
            s => Ok(Self::Fixed(u64::from_str(s).map_err(de::Error::custom)?)),
        }
    }
}

/// The LUKS2 user data integrity protection type, an experimental feature which is unsupported in
/// this implementation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Integrity {}

impl<'de> Deserialize<'de> for Integrity {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<Integrity, D::Error> {
        Err(de::Error::custom("crypt.integrity is unsupported"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SectorSize {
    B512,
    B1024,
    B2048,
    B4096,
}

impl SectorSize {
    pub fn as_u64(&self) -> u64 {
        match self {
            Self::B512 => 512,
            Self::B1024 => 1024,
            Self::B2048 => 2048,
            Self::B4096 => 4096,
        }
    }
    pub fn from_u16(v: u16) -> Result<Self, ParseError> {
        match v {
            512 => Ok(Self::B512),
            1024 => Ok(Self::B1024),
            2048 => Ok(Self::B2048),
            4096 => Ok(Self::B4096),
            _ => Err(ParseError::InvalidSectorSize(v)),
        }
    }
}

impl Serialize for SectorSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.as_u64() as u16)
    }
}

impl<'de> Deserialize<'de> for SectorSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SectorSize, D::Error> {
        Self::from_u16(u16::deserialize(deserializer)?).map_err(|e| de::Error::custom(e))
    }
}

/// Section 3.3.2
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum SegmentTypeData {
    Crypt {
        /// The starting offset for the Initialization Vector.
        #[serde(with = "type_str")]
        iv_tweak: u64,
        /// The segment encryption algorithm in dm-crypt notaton (e. g. "aes-xts-plain64").
        encryption: Encryption,
        /// The sector size for the segment (512, 1024, 2048, or 4096 bytes).
        sector_size: SectorSize,
        /// The LUKS2 user data integrity protection type (optional, unsupported).
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        integrity: Option<Integrity>,
    },
}

/// A segment contains a definition of encrypted areas on the disk containing user data
/// (in LUKS1 mentioned as the user data payload). For a normal LUKS device, there ist only
/// one data segment present.
/// Section 3.3
///
/// Only the `crypt` type is currently used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Segment {
    #[serde(flatten)]
    type_data: SegmentTypeData,
    /// The offset from the device start to the beginning of the segment in bytes.
    #[serde(with = "type_str")]
    offset: u64,
    /// The segment size, see [`SegmentSize`].
    size: SegmentSize,
    /// An array of strings marking the segment with additional information (optional).
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
}

impl Segment {
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

#[derive(Debug, Clone, PartialOrd, Eq, Ord, Deserialize, PartialEq, Serialize)]
pub struct Index(#[serde(with = "type_str")] pub usize);

// Section 3.4
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum DigestTypeData {
    Pbkdf2 {
        /// The hash algorithm used by PBKDF2.
        hash: Hash,
        /// The PBKDF2 iterations count.
        iterations: u32,
    },
}

/// A digest is used to verify that a key decrypted from a keyslot is correct. Digests are assigned
/// to keyslots and segments. If it is not assigned to a segment, then it is a digest for an unbound
/// key. Every keyslot must have one assigned digest. The key digest also specifies the exact key size
/// for the encryption algorithm of the segment.
/// Section 3.4
///
/// Only the `pbkdf2` type compatible with LUKS1 is used.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Digest {
    #[serde(flatten)]
    type_data: DigestTypeData,
    /// A list of keyslot numbers that are assigned to the digest.
    keyslots: Vec<Index>,
    /// A list of segment numbers that are assigned to the digest.
    segments: Vec<Index>,
    /// The binary salt for the digest, in base64.
    #[serde(with = "bytes_base64")]
    salt: Vec<u8>,
    /// The binary digest data, in base64.
    #[serde(with = "bytes_base64")]
    digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Requirement {}

impl<'de> Deserialize<'de> for Requirement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Requirement, D::Error> {
        let s = <&'de str>::deserialize(deserializer)?;
        Err(de::Error::custom(ParseError::UnsupportedRequirement(
            s.to_string(),
        )))
    }
}

/// Global attributes for the LUKS device.
/// Section 3.5
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Config {
    /// The JSON area size in bytes. Must match the binary header.
    #[serde(with = "type_str")]
    pub json_size: u64,
    /// The binary keyslot area size in bytes. Must be aligned to 4096 bytes.
    #[serde(with = "type_str")]
    pub keyslots_size: u64,
    /// An optional list of persistent flags for the device.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    /// An optional list of additional required features for the LUKS device.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Vec<Requirement>>,
}

/// A token is an object that can describe how to get a passphrase to unlock a particular keyslot.
/// It can also contain additional user-defined JSON metadata. No token types are implemented;
/// this is only included for parsing compatibility.
/// Section 3.6
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct Token {
    #[serde(rename = "type")]
    token_type: String,
    keyslots: Vec<Index>,
    #[serde(flatten)]
    type_data: BTreeMap<String, serde_json::Value>,
}

/// JSON metadata for the device as described
/// [here](https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
/// Section 3
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct HeaderJson {
    /// Objects describing encrypted keys storage areas.
    #[serde(with = "list")]
    pub keyslots: Vec<Keyslot>,
    /// Tokens can optionally include additional metadata. Only included for parsing compatibility.
    #[serde(with = "list")]
    pub tokens: Vec<Token>,
    /// Segments describe areas on disk that contain user encrypted data.
    #[serde(with = "list")]
    pub segments: Vec<Segment>,
    /// Digests are used to verify that keys decrypted from keyslots are correct. Uses the keys
    /// of keyslots and segments to reference them.
    #[serde(with = "list")]
    pub digests: Vec<Digest>,
    /// Persistent header configuration attributes.
    pub config: Config,
}

impl Display for HeaderJson {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Luks JsonHeader: {}",
            serde_json::to_string_pretty(&self).expect("valid json serialization")
        )
    }
}

impl HeaderJson {
    /// Attempt to read a LUKS2 JSON area from a reader. The reader must contain exactly the JSON data
    /// and nothing more.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ParseError> {
        let j: Self = serde_json::from_slice(slice)?;

        // check that keyslots size is aligned to 4096
        if (j.config.keyslots_size % 4096) != 0 {
            return Err(ParseError::KeyslotNotAligned);
        }

        // check that all segments/keyslots references are valid
        for digest in &j.digests {
            for keyslot_idx in &digest.keyslots {
                if keyslot_idx.0 >= j.keyslots.len() {
                    return Err(ParseError::InvalidKeyslotReference(keyslot_idx.0));
                }
            }
            for segment_idx in &digest.segments {
                if segment_idx.0 >= j.segments.len() {
                    return Err(ParseError::InvalidSegmentReference(segment_idx.0));
                }
            }
        }

        Ok(j)
    }
}

pub trait ReadSeek: Read + Seek + Debug {}
impl<T: ?Sized> ReadSeek for T where T: Read + Seek + Debug {}
pub trait ReadWriteSeek: Read + Write + Seek + Debug {}
impl<T: ?Sized> ReadWriteSeek for T where T: Read + Write + Seek + Debug {}

// Tries to decrypt the specified keyslot using the given password if successful, returns the
// master key
fn decrypt_keyslot(
    device: &mut dyn ReadSeek,
    digest: &Digest,
    keyslot: &Keyslot,
    password: &[u8],
) -> Result<SecretMasterKey, LuksError> {
    let keyslot_area = &keyslot.area;
    let AreaTypeData::Raw {
        encryption: keyslot_area_encryption,
        key_size: keyslot_area_key_size,
    } = &keyslot_area.type_data;
    let KeyslotTypeData::Luks2 {
        kdf: keyslot_kdf,
        af:
            Af::Luks1 {
                stripes: keyslot_af_stripes,
                hash: keyslot_af_hash,
            },
    } = &keyslot.type_data;

    // Read area of keyslot
    let mut master_key_split = vec![0; keyslot.key_size * keyslot_af_stripes.as_usize()];
    device.seek(SeekFrom::Start(keyslot_area.offset))?;
    device.read_exact(&mut master_key_split)?;

    // Apply key derivation function to password
    let mut password_key = vec![0; *keyslot_area_key_size];
    match &keyslot_kdf.type_data {
        KdfTypeData::Argon2i { time, memory, cpus } => {
            let params = argon2::Params::new(*memory, *time, *cpus, Some(*keyslot_area_key_size))?;
            let algorithm = argon2::Algorithm::Argon2i;
            let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
            argon.hash_password_into(password, &keyslot_kdf.salt, &mut password_key)?;
        }
        KdfTypeData::Argon2id { time, memory, cpus } => {
            let params = argon2::Params::new(*memory, *time, *cpus, Some(*keyslot_area_key_size))?;
            let algorithm = argon2::Algorithm::Argon2id;
            let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
            argon.hash_password_into(password, &keyslot_kdf.salt, &mut password_key)?;
        }
        KdfTypeData::Pbkdf2 { hash, iterations } => {
            let kdf_fn = match hash {
                Hash::Sha256 => pbkdf2::<Hmac<Sha256>>,
                Hash::Sha1 => pbkdf2::<Hmac<Sha1>>,
                Hash::Unknown(h) => return Err(LuksError::UnsupportedPbkdf2Hash(h.clone())),
            };
            kdf_fn(password, &keyslot_kdf.salt, *iterations, &mut password_key);
        }
    }

    // Make password_key a secret after hashing
    let password_key = Secret::new(password_key);

    // Decrypt keyslot area using the password derived key
    match keyslot_area_encryption {
        Encryption::AesXtsPlain64 => match keyslot_area_key_size {
            32 => {
                let key1 = Aes128::new_from_slice(&password_key.expose_secret()[..16]).unwrap();
                let key2 = Aes128::new_from_slice(&password_key.expose_secret()[16..]).unwrap();
                let xts = Xts128::<Aes128>::new(key1, key2);
                xts.decrypt_area(
                    &mut master_key_split,
                    LUKS_SECTOR_SIZE,
                    0,
                    get_tweak_default,
                );
            }
            64 => {
                let key1 = Aes256::new_from_slice(&password_key.expose_secret()[..32]).unwrap();
                let key2 = Aes256::new_from_slice(&password_key.expose_secret()[32..]).unwrap();
                let xts = Xts128::<Aes256>::new(key1, key2);
                xts.decrypt_area(
                    &mut master_key_split,
                    LUKS_SECTOR_SIZE,
                    0,
                    get_tweak_default,
                );
            }
            x => return Err(LuksError::UnsupportedKeySize("aes-xts-plain64", *x)),
        },
        Encryption::Unknown(e) => return Err(LuksError::UnsupportedAreaEncryption(e.clone())),
    }
    // Make master_key_split a secret after decryption
    let master_key_split = Secret::new(master_key_split);
    // Apply the AF merging to get the master key
    let master_key = match keyslot_af_hash {
        Hash::Sha256 => Secret::new(MasterKey(af::merge::<Sha256>(
            &master_key_split.expose_secret(),
            keyslot.key_size,
            keyslot_af_stripes.as_usize(),
        ))),
        Hash::Sha1 => Secret::new(MasterKey(af::merge::<Sha1>(
            &master_key_split.expose_secret(),
            keyslot.key_size,
            keyslot_af_stripes.as_usize(),
        ))),
        Hash::Unknown(h) => return Err(LuksError::UnsupportedAfHash(h.clone())),
    };

    // Calculate master key digest
    let DigestTypeData::Pbkdf2 {
        hash: digest_hash,
        iterations: digest_iterations,
    } = &digest.type_data;
    let mut digest_computed = vec![0; digest.digest.len()];
    let kdf_fn = match digest_hash {
        Hash::Sha256 => pbkdf2::<Hmac<Sha256>>,
        Hash::Sha1 => pbkdf2::<Hmac<Sha1>>,
        Hash::Unknown(h) => return Err(LuksError::UnsupportedDigestHash(h.clone())),
    };
    kdf_fn(
        &master_key.expose_secret().0,
        &digest.salt,
        *digest_iterations,
        &mut digest_computed,
    );

    // compare digests
    if digest_computed == digest.digest {
        Ok(master_key)
    } else {
        Err(LuksError::InvalidPassword)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    bin: HeaderBin,
    json: HeaderJson,
}

impl Display for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.bin, f)?;
        Display::fmt(&self.json, f)?;
        Ok(())
    }
}

impl Header {
    pub fn from_reader(r: &mut dyn Read) -> Result<Self, LuksError> {
        let mut bin_header_bytes = vec![0; LUKS_BIN_HEADER_LEN];
        r.read_exact(&mut bin_header_bytes)?;
        let bin_header_raw = BinHeaderRaw::from_slice(&bin_header_bytes)?;
        let bin_header = HeaderBin::try_from(&bin_header_raw)?;
        let mut json_header_bytes = vec![0; bin_header.hdr_size as usize - LUKS_BIN_HEADER_LEN];
        r.read_exact(&mut json_header_bytes)?;
        Self::verify_checksum(&bin_header, &json_header_bytes)?;
        let json_header_str = ascii_cstr_to_str("json_header", &json_header_bytes)?;
        let json_header = HeaderJson::from_slice(&json_header_str.as_bytes())?;
        Ok(Self {
            bin: bin_header,
            json: json_header,
        })
    }

    fn verify_checksum_generic<H: digest::Digest>(
        csum: &Output<H>,
        bin_header: &HeaderBin,
        json_area_bytes: &[u8],
    ) -> Result<(), ParseError> {
        let result = Self::calculate_checksum_generic::<H>(bin_header, json_area_bytes);
        if &result != csum {
            let (mut calculated, mut found) = ([0; CSUM_LEN], [0; CSUM_LEN]);
            calculated[..result.len()].copy_from_slice(&result);
            found[..csum.len()].copy_from_slice(&csum);
            Err(ParseError::InvalidChecksum { calculated, found })
        } else {
            Ok(())
        }
    }

    fn verify_checksum(bin_header: &HeaderBin, json_area_bytes: &[u8]) -> Result<(), ParseError> {
        match bin_header.checksum {
            Checksum::Sha256(ref csum) => {
                Self::verify_checksum_generic::<Sha256>(csum, &bin_header, json_area_bytes)
            }
        }
    }

    fn calculate_checksum_generic<H: digest::Digest>(
        bin_header: &HeaderBin,
        json_area_bytes: &[u8],
    ) -> Output<H> {
        let mut bin_header_raw = BinHeaderRaw::try_from(bin_header).expect("valid roundtrip");
        bin_header_raw.csum = [0; CSUM_LEN];
        let mut bin_header_bytes = vec![0; LUKS_BIN_HEADER_LEN];
        bin_header_raw
            .write_slice(&mut bin_header_bytes)
            .expect("bincode encode");

        let mut hasher = H::new();
        hasher.update(bin_header_bytes);
        hasher.update(json_area_bytes);
        hasher.finalize()
    }
}

#[derive(Debug)]
pub struct LuksDevice {
    device: Box<dyn ReadWriteSeek>,
    header: Header,
}

impl Display for LuksDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.header, f)
    }
}

impl LuksDevice {
    pub fn from_device(mut device: Box<dyn ReadWriteSeek>) -> Result<Self, LuksError> {
        let hdr_offset_expected = device.seek(SeekFrom::Start(0))?;
        let primary_header = Header::from_reader(&mut device)?;
        if primary_header.bin.hdr_offset != hdr_offset_expected {
            return Err(LuksError::InvalidHeaderOffset {
                expected: hdr_offset_expected,
                found: primary_header.bin.hdr_offset,
            });
        }
        let hdr_offset_expected = device.seek(SeekFrom::Current(0))?;
        let secondary_header = Header::from_reader(&mut device)?;
        if secondary_header.bin.hdr_offset != hdr_offset_expected {
            return Err(LuksError::InvalidHeaderOffset {
                expected: hdr_offset_expected,
                found: primary_header.bin.hdr_offset,
            });
        }
        let header = if primary_header.bin.seqid >= secondary_header.bin.seqid {
            primary_header
        } else {
            secondary_header
        };
        Ok(Self { device, header })
    }

    pub fn format_device(
        mut device: Box<dyn ReadWriteSeek>,
        password: &[u8],
        sector_size: u16,
    ) -> Result<Self, LuksError> {
        let sector_size = SectorSize::from_u16(sector_size)?;
        device.seek(SeekFrom::Start(0))?;
        // Safeguard to avoid formatting a Luks device by mistake
        let mut magic_buf = [0u8; MAGIC_LEN];
        device.read_exact(&mut magic_buf)?;
        let magic = Magic::from_byte_array(&magic_buf);
        if magic == Some(Magic::First) {
            return Err(LuksError::FoundExistingHeader);
        }
        // Safeguard to allow enough space for a 16 MiB header
        let device_size = device.seek(SeekFrom::End(0))?;
        if device_size <= LUKS_HEADER_LEN as u64 {
            return Err(LuksError::NotEnoughSpace(device_size));
        }
        device.seek(SeekFrom::Current(0))?;

        // defaults:
        let keyslot_area_key_size = 64;
        let keyslot_key_size = 64;
        let keyslot_af_stripes = Stripes {};
        let digest_iterations = 1000;
        // pbkdf defaults:
        let hash = Hash::Sha256;
        let time = 4;
        let memory = 1048576;
        let cpus = 4;

        let mut rng = StdRng::from_os_rng();

        // Generate a master key from a CSPRNG
        let master_key = {
            let mut master_key = vec![0; keyslot_key_size];
            rng.fill_bytes(&mut master_key);
            Secret::new(MasterKey(master_key.to_vec()))
        };

        // Calculate master key digest
        let mut master_key_digest = vec![0; 32];
        let digest_salt = {
            let mut salt = vec![0; 32];
            rng.fill_bytes(&mut salt);
            salt
        };
        pbkdf2::<Hmac<Sha256>>(
            &master_key.expose_secret().0,
            &digest_salt,
            digest_iterations,
            &mut master_key_digest,
        );

        // Apply key derivation function to password
        let keyslot_kdf_salt = {
            let mut salt = vec![0; 32];
            rng.fill_bytes(&mut salt);
            salt
        };
        let mut password_key = vec![0; keyslot_area_key_size];
        let params = argon2::Params::new(memory, time, cpus, Some(keyslot_area_key_size))?;
        let algorithm = argon2::Algorithm::Argon2id;
        let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
        argon.hash_password_into(password, &keyslot_kdf_salt, &mut password_key)?;
        let password_key = Secret::new(password_key);

        // Apply the AF splitting to the master key
        let mut master_key_split = af::split::<Sha256>(
            &master_key.expose_secret().0,
            keyslot_key_size,
            keyslot_af_stripes.as_usize(),
        );

        // Encrypt the master key split with the password derived key
        let key1 = Aes256::new_from_slice(&password_key.expose_secret()[..32]).unwrap();
        let key2 = Aes256::new_from_slice(&password_key.expose_secret()[32..]).unwrap();
        let xts = Xts128::<Aes256>::new(key1, key2);
        xts.encrypt_area(
            &mut master_key_split,
            LUKS_SECTOR_SIZE,
            0,
            get_tweak_default,
        );

        let digest = Digest {
            type_data: DigestTypeData::Pbkdf2 {
                hash: hash.clone(),
                iterations: digest_iterations,
            },
            keyslots: vec![Index(0)],
            segments: vec![Index(0)],
            salt: digest_salt,
            digest: master_key_digest,
        };

        let keyslot = Keyslot {
            type_data: KeyslotTypeData::Luks2 {
                kdf: Kdf {
                    type_data: KdfTypeData::Argon2id { time, memory, cpus },
                    salt: keyslot_kdf_salt,
                },
                af: Af::Luks1 {
                    stripes: keyslot_af_stripes,
                    hash,
                },
            },
            key_size: keyslot_key_size,
            area: Area {
                type_data: AreaTypeData::Raw {
                    encryption: Encryption::AesXtsPlain64,
                    key_size: keyslot_area_key_size,
                },
                offset: u64::MAX, // set it later
                size: (keyslot_af_stripes.as_usize() * keyslot_key_size).next_multiple_of(4096)
                    as u64,
            },
            priority: None,
        };

        let segment_offset = LUKS_HEADER_LEN as u64;
        let segment = Segment {
            type_data: SegmentTypeData::Crypt {
                iv_tweak: 0,
                encryption: Encryption::AesXtsPlain64,
                sector_size,
                integrity: None,
            },
            offset: segment_offset,
            size: SegmentSize::Dynamic,
            flags: vec![],
        };

        let config = Config {
            json_size: u64::MAX,     // set it later
            keyslots_size: u64::MAX, // set it later
            flags: None,
            requirements: None,
        };

        let mut header_json = HeaderJson {
            keyslots: vec![keyslot],
            tokens: vec![],
            segments: vec![segment],
            digests: vec![digest],
            config,
        };

        let json_size = {
            let buf = serde_json::to_vec(&header_json).expect("serialize");
            PRIMARY_LEN_JSON_LEN
                .iter()
                .find_map(|(_, json_size)| (buf.len() < *json_size).then_some(*json_size))
                .expect("size found") as u64
        };

        let keyslot_area_offset = 2 * (LUKS_BIN_HEADER_LEN as u64 + json_size);
        let keyslots_size = LUKS_HEADER_LEN as u64 - 2 * (LUKS_BIN_HEADER_LEN as u64 + json_size);
        header_json.config.json_size = json_size;
        header_json.config.keyslots_size = keyslots_size;
        header_json.keyslots[0].area.offset = keyslot_area_offset;

        let uuid = Uuid::new_v4();

        let salt_1: [u8; SALT_LEN] = rng.random();
        let salt_2: [u8; SALT_LEN] = rng.random();
        let header_size = LUKS_BIN_HEADER_LEN as u64 + json_size;
        let mut header_bin = HeaderBin {
            magic: Magic::First, // set it later
            hdr_size: header_size,
            seqid: 1,
            label: None,
            checksum: Checksum::Sha256(Output::<Sha256>::default()), // set it later
            salt: [0; SALT_LEN],                                     // set it later
            uuid: uuid.to_string(),
            subsystem: None,
            hdr_offset: u64::MAX, // set it later
        };

        // Write keyslot area
        device.seek(SeekFrom::Start(keyslot_area_offset))?;
        device.write_all(&master_key_split)?;
        // Write JSON area 2 & 1
        let mut json_header_bytes = Cursor::new(vec![0; json_size as usize]);
        serde_json::to_writer(&mut json_header_bytes, &header_json).expect("serialize");
        let json_area_bytes = json_header_bytes.into_inner();
        device.seek(SeekFrom::Start(header_size + LUKS_BIN_HEADER_LEN as u64))?;
        device.write_all(&json_area_bytes)?;
        device.seek(SeekFrom::Start(LUKS_BIN_HEADER_LEN as u64))?;
        device.write_all(&json_area_bytes)?;

        fn write_header_bin(
            device: &mut dyn ReadWriteSeek,
            header_bin: &HeaderBin,
            json_header_bytes: &[u8],
        ) -> Result<(), LuksError> {
            let mut header_bin_bytes = vec![0; LUKS_BIN_HEADER_LEN];
            let header_checksum =
                Header::calculate_checksum_generic::<Sha256>(&header_bin, json_header_bytes);
            let mut header_bin = header_bin.clone();
            header_bin.checksum = Checksum::Sha256(header_checksum);
            device.seek(SeekFrom::Start(header_bin.hdr_offset))?;
            BinHeaderRaw::try_from(&header_bin)
                .expect("into-raw")
                .write_slice(&mut header_bin_bytes)
                .expect("encode");
            device.write_all(&header_bin_bytes)?;
            Ok(())
        }

        // Write Binary header 2 & 1
        header_bin.magic = Magic::Second;
        header_bin.salt = salt_2;
        header_bin.hdr_offset = header_size;
        write_header_bin(&mut device, &header_bin, &json_area_bytes)?;

        header_bin.magic = Magic::First;
        header_bin.salt = salt_1;
        header_bin.hdr_offset = 0;
        write_header_bin(&mut device, &header_bin, &json_area_bytes)?;

        device.flush()?;

        Self::from_device(device)
    }

    // tries to decrypt the master key with the given password by trying all available keyslots
    fn decrypt_master_key(
        device: &mut dyn ReadSeek,
        digest: &Digest,
        keyslots: &[Keyslot],
        password: &[u8],
    ) -> Result<SecretMasterKey, LuksError> {
        let mut keyslots: Vec<&Keyslot> = keyslots.iter().collect();
        keyslots.sort_by_key(|&ks| ks.priority.unwrap_or_default());

        for ks in keyslots.iter().rev() {
            // reverse to get highest priority first
            match decrypt_keyslot(device, digest, ks, password) {
                Ok(mk) => return Ok(mk),
                Err(e) => match e {
                    LuksError::InvalidPassword => {}
                    _ => return Err(e),
                },
            }
        }

        Err(LuksError::InvalidPassword)
    }

    /// Creates a `LuksActiveDevice` from the first segment described in the headers.
    pub fn activate(
        self,
        write: bool,
        password: &[u8],
    ) -> Result<LuksActiveDevice, (Self, LuksError)> {
        self.activate_internal(write, PasswordOrMasterKey::Password(password))
    }

    pub fn activate_with_master_key(
        self,
        write: bool,
        master_key: SecretMasterKey,
    ) -> Result<LuksActiveDevice, (Self, LuksError)> {
        self.activate_internal(write, PasswordOrMasterKey::MasterKey(master_key))
    }

    fn try_activate(
        &mut self,
        password_or_master_key: PasswordOrMasterKey,
    ) -> Result<(SecretMasterKey, Segment, u64), LuksError> {
        let master_key = match password_or_master_key {
            PasswordOrMasterKey::Password(password) => {
                // Data validation
                if self.header.json.keyslots.len() == 0 {
                    return Err(LuksError::NoKeyslots);
                }
                let digest = self
                    .header
                    .json
                    .digests
                    .get(0)
                    .ok_or(LuksError::NoDigests)?;
                if !digest.segments.contains(&Index(0)) {
                    return Err(LuksError::NoDigestsSegment0);
                }
                Self::decrypt_master_key(
                    &mut self.device,
                    digest,
                    &self.header.json.keyslots,
                    password,
                )?
            }
            PasswordOrMasterKey::MasterKey(master_key) => master_key,
        };

        let active_segment = self
            .header
            .json
            .segments
            .get(0)
            .ok_or(LuksError::NoSegments)?
            .clone();

        let active_segment_size = match active_segment.size {
            SegmentSize::Fixed(s) => s,
            SegmentSize::Dynamic => {
                let end = self.device.seek(SeekFrom::End(0))?;
                end - active_segment.offset
            }
        };

        let Segment {
            type_data:
                SegmentTypeData::Crypt {
                    sector_size,
                    encryption,
                    ..
                },
            ..
        } = &active_segment;
        if active_segment_size % sector_size.as_u64() != 0 {
            // NOTE: Maybe instead of erroring we should just set active_segment_size to the
            // smallest closest multiple of sector_size?
            return Err(LuksError::InvalidSegmentSize {
                segment_size: active_segment_size,
                sector_size: sector_size.as_u64(),
            });
        }
        match encryption {
            Encryption::AesXtsPlain64 => match master_key.expose_secret().0.len() {
                32 | 64 => {}
                x => return Err(LuksError::UnsupportedKeySize("aes-xts-plain64", x)),
            },
            Encryption::Unknown(e) => {
                return Err(LuksError::UnsupportedSegmentEncryption(e.clone()))
            }
        }

        Ok((master_key, active_segment, active_segment_size))
    }

    fn activate_internal(
        mut self,
        write: bool,
        password_or_master_key: PasswordOrMasterKey,
    ) -> Result<LuksActiveDevice, (Self, LuksError)> {
        let (master_key, active_segment, active_segment_size) =
            match self.try_activate(password_or_master_key) {
                Ok(ok) => ok,
                Err(e) => return Err((self, e)),
            };

        let mut d = LuksActiveDevice {
            device: self.device,
            header: self.header,
            write,
            master_key,
            segment_size: active_segment_size,
            segment: active_segment,
            current_sector: Cursor::new(vec![].into_boxed_slice()),
            current_sector_num: u64::MAX,
            dirty: false,
        };
        match d.seek(SeekFrom::Start(0)) {
            Ok(_) => Ok(d),
            Err(e) => {
                let d = match d.deactivate() {
                    Ok(d) => d,
                    Err(_) => unreachable!("no write expected"),
                };
                Err((d, e.into()))
            }
        }
    }
}

#[derive(Clone)]
pub struct MasterKey(Vec<u8>);

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl DebugSecret for MasterKey {}

impl CloneableSecret for MasterKey {}

pub type SecretMasterKey = Secret<MasterKey>;

const LUKS_SECTOR_SIZE: usize = 512;

/// A struct representing a LUKS device.
/// WARNING: this struct internally stores the master key in *user-space* RAM. Please consider the
/// security implications this may have.
#[derive(Debug)]
pub struct LuksActiveDevice {
    device: Box<dyn ReadWriteSeek>,
    header: Header,
    write: bool,
    // Active fields
    master_key: SecretMasterKey,
    segment_size: u64,
    /// The segment used when reading from the device. Calls to `seek()` will be considered
    /// relative to `segment.offset` if seeking from the start or segment.size` if seeking from the
    /// end.
    pub segment: Segment,
    current_sector: Cursor<Box<[u8]>>,
    current_sector_num: u64,
    dirty: bool,
}

enum PasswordOrMasterKey<'a> {
    Password(&'a [u8]),
    MasterKey(SecretMasterKey),
}

impl LuksActiveDevice {
    pub fn deactivate(mut self) -> Result<LuksDevice, (Self, acid_io::Error)> {
        match self.flush() {
            Err(e) => return Err((self, e)),
            Ok(()) => {}
        }
        let mut device: Box<dyn ReadWriteSeek> = Box::new(Cursor::new(vec![]));
        // We can't move out the device because Self implements Drop, so insetead we replace it
        // with a dummy.  `drop` will call `flush` and return immediately because we just called
        // `flush` making the device is not dirty.
        mem::swap(&mut self.device, &mut device);
        Ok(LuksDevice {
            device,
            header: self.header.clone(),
        })
    }
    // updates the internal state so that current sector is the one with the given number
    // decrypts the sector, performs boundary checks (returns an error if sector_num too small,
    // goes to last sector if sector_num too big)
    fn go_to_sector(&mut self, sector_num: u64) -> acid_io::Result<()> {
        if self.dirty {
            self.flush()?;
        }
        let Segment {
            type_data:
                SegmentTypeData::Crypt {
                    iv_tweak,
                    sector_size,
                    encryption,
                    ..
                },
            ..
        } = &self.segment;
        let sector_size = sector_size.as_u64();
        if sector_num == self.current_sector_num {
            return Ok(());
        } else if sector_num < (self.segment.offset / sector_size as u64) {
            return Err(acid_io::Error::new(
                ErrorKind::InvalidInput,
                "tried to seek to position before active segment",
            ));
        }

        let max_sector = (self.segment.offset + self.segment_size) / sector_size - 1;
        if sector_num > max_sector {
            self.current_sector = Cursor::new(vec![].into_boxed_slice());
            self.current_sector_num = sector_num;
            return Ok(());
        }

        self.device
            .seek(SeekFrom::Start(sector_num * sector_size))?;
        let mut sector = vec![0; sector_size as usize].into_boxed_slice();

        self.device.read_exact(&mut sector)?;

        let iv = sector_num - (self.segment.offset / sector_size);
        // the iv isn't the index of sector_size sectors, but instead the index of 512-byte sectors
        let iv = iv * (sector_size / 512);
        let iv = get_tweak_default((iv + iv_tweak) as u128);
        let master_key = &self.master_key;
        match encryption {
            Encryption::AesXtsPlain64 => match master_key.expose_secret().0.len() {
                32 => {
                    let key1 = Aes128::new_from_slice(&master_key.expose_secret().0[..16]).unwrap();
                    let key2 = Aes128::new_from_slice(&master_key.expose_secret().0[16..]).unwrap();
                    let xts = Xts128::<Aes128>::new(key1, key2);
                    xts.decrypt_sector(&mut sector, iv);
                }
                64 => {
                    let key1 = Aes256::new_from_slice(&master_key.expose_secret().0[..32]).unwrap();
                    let key2 = Aes256::new_from_slice(&master_key.expose_secret().0[32..]).unwrap();
                    let xts = Xts128::<Aes256>::new(key1, key2);
                    xts.decrypt_sector(&mut sector, iv);
                }
                _ => unreachable!("validated in from_device_internal"),
            },
            Encryption::Unknown(_) => unreachable!("validated in from_device_internal"),
        }

        self.current_sector = Cursor::new(sector);
        self.current_sector_num = sector_num;

        Ok(())
    }
}

impl Read for LuksActiveDevice {
    fn read(&mut self, buf: &mut [u8]) -> acid_io::Result<usize> {
        let Segment {
            type_data: SegmentTypeData::Crypt { sector_size, .. },
            ..
        } = &self.segment;
        if self.current_sector.position() == sector_size.as_u64() {
            self.go_to_sector(self.current_sector_num + 1)?;
        }

        self.current_sector.read(buf)
    }
}

impl Seek for LuksActiveDevice {
    fn seek(&mut self, pos: SeekFrom) -> acid_io::Result<u64> {
        let Segment {
            type_data: SegmentTypeData::Crypt { sector_size, .. },
            ..
        } = &self.segment;
        let sector_size = sector_size.as_u64();
        let offset = match pos {
            SeekFrom::Start(p) => self.segment.offset + p,
            SeekFrom::End(p) => {
                let offset = (self.segment.offset as i64 + self.segment_size as i64 + p) as u64;
                if offset < self.segment.offset {
                    return Err(acid_io::Error::new(
                        ErrorKind::InvalidInput,
                        "tried to seek to negative sector",
                    ));
                }
                offset
            }
            SeekFrom::Current(p) => {
                let current_offset =
                    self.current_sector_num * sector_size + self.current_sector.position();
                let offset = (current_offset as i64 + p) as u64;
                if offset < self.segment.offset {
                    return Err(acid_io::Error::new(
                        ErrorKind::InvalidInput,
                        "tried to seek to negative sector",
                    ));
                }
                offset
            }
        };
        let sector = offset / sector_size;
        self.go_to_sector(sector)?;
        self.current_sector
            .seek(SeekFrom::Start(offset % sector_size))?;

        Ok(self.current_sector_num * sector_size - self.segment.offset
            + self.current_sector.position())
    }
}

impl Write for LuksActiveDevice {
    fn write(&mut self, buf: &[u8]) -> acid_io::Result<usize> {
        if !self.write {
            return Err(acid_io::Error::new(
                ErrorKind::Other,
                "tried to write in read-only mode",
            ));
        }
        let Segment {
            type_data: SegmentTypeData::Crypt { sector_size, .. },
            ..
        } = &self.segment;
        if self.current_sector.position() == sector_size.as_u64() {
            self.go_to_sector(self.current_sector_num + 1)?;
        }

        self.dirty = true;
        self.current_sector.write(buf)
    }

    fn flush(&mut self) -> acid_io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if !self.write {
            return Err(acid_io::Error::new(
                ErrorKind::Other,
                "tried to flush in read-only mode",
            ));
        }

        // If the current_sector size is 0 it means we've seeked past the max_sector, so we have
        // nothing to flush.
        if self.current_sector.get_ref().len() == 0 {
            self.dirty = false;
            return Ok(());
        }

        let Segment {
            type_data:
                SegmentTypeData::Crypt {
                    iv_tweak,
                    sector_size,
                    encryption,
                    ..
                },
            ..
        } = &self.segment;
        let sector_size = sector_size.as_u64();

        let mut sector = self.current_sector.get_ref().clone();

        let iv = self.current_sector_num - (self.segment.offset / sector_size);
        // the iv isn't the index of sector_size sectors, but instead the index of 512-byte sectors
        let iv = iv * (sector_size / 512);
        let iv = get_tweak_default((iv + iv_tweak) as u128);
        let master_key = &self.master_key;
        match encryption {
            Encryption::AesXtsPlain64 => match master_key.expose_secret().0.len() {
                32 => {
                    let key1 = Aes128::new_from_slice(&master_key.expose_secret().0[..16]).unwrap();
                    let key2 = Aes128::new_from_slice(&master_key.expose_secret().0[16..]).unwrap();
                    let xts = Xts128::<Aes128>::new(key1, key2);
                    xts.encrypt_sector(&mut sector, iv);
                }
                64 => {
                    let key1 = Aes256::new_from_slice(&master_key.expose_secret().0[..32]).unwrap();
                    let key2 = Aes256::new_from_slice(&master_key.expose_secret().0[32..]).unwrap();
                    let xts = Xts128::<Aes256>::new(key1, key2);
                    xts.encrypt_sector(&mut sector, iv);
                }
                _ => unreachable!("validated in from_device_internal"),
            },
            Encryption::Unknown(_) => unreachable!("validated in from_device_internal"),
        }

        self.device
            .seek(SeekFrom::Start(self.current_sector_num * sector_size))?;
        self.device.write_all(&mut sector)?;
        self.dirty = false;
        Ok(())
    }
}

impl Drop for LuksActiveDevice {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}
