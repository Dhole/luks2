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
    cmp::max,
    convert::TryFrom,
    fmt::{Debug, Display},
    str::FromStr,
};

use crate::error::{EncodeError, LuksError, ParseError};
use crate::utils::{ascii_cstr_to_str, ascii_cstr_to_string, str_to_ascii_array};

use acid_io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom};
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

#[derive(Debug, Clone)]
pub enum Magic {
    First,
    Second,
}

impl Magic {
    pub fn to_byte_array(&self) -> [u8; MAGIC_LEN] {
        let mut array = [0; MAGIC_LEN];
        array.copy_from_slice(match self {
            Self::First => MAGIC_1ST,
            Self::Second => MAGIC_1ST,
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

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct BinHeader {
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

impl Display for BinHeader {
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

impl TryFrom<&BinHeader> for BinHeaderRaw {
    type Error = EncodeError;
    fn try_from(h: &BinHeader) -> Result<Self, Self::Error> {
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

impl TryFrom<&BinHeaderRaw> for BinHeader {
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AreaTypeData {
    Raw {
        /// The area encryption algorithm, in dm-crypt notation (e. g. "aes-xts-plain64").
        encryption: Encryption,
        /// The area encryption key size.
        key_size: usize,
    },
}

/// Information on the allocated area in the binary keyslots area of a [`LuksKeyslot`].
/// Section 3.2.3
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
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

/// An anti-forensic splitter of a [`LuksKeyslot`]. See
/// [the LUKS1 spec](https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification)
/// for more information.
/// Section 3.2.4
///
/// Only the `luks1` type compatible with LUKS1 is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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

/// Stores information on the PBKDF type and parameters of a [`LuksKeyslot`].
/// Section 3.2.5
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Kdf {
    #[serde(flatten)]
    type_data: KdfTypeData,
    /// The salt for the PBKDF in base64 (binary data).
    #[serde(with = "bytes_base64")]
    salt: Vec<u8>,
}

/// The priority of a [`LuksKeyslot`].
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
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

/// The size of a [`LuksSegment`].
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
}

impl Serialize for SectorSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.as_u64() as u16)
    }
}

impl<'de> Deserialize<'de> for SectorSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SectorSize, D::Error> {
        match u16::deserialize(deserializer)? {
            512 => Ok(Self::B512),
            1024 => Ok(Self::B1024),
            2048 => Ok(Self::B2048),
            4096 => Ok(Self::B4096),
            s => Err(de::Error::custom(ParseError::InvalidSectorSize(s))),
        }
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
    /// The segment size, see [`LuksSegmentSize`].
    size: SegmentSize,
    /// An array of strings marking the segment with additional information (optional).
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
}

#[derive(Debug, PartialOrd, Eq, Ord, Deserialize, PartialEq, Serialize)]
pub struct Index(#[serde(with = "type_str")] pub usize);

// Section 3.4
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(Debug, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct JsonHeader {
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

impl Display for JsonHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Luks JsonHeader: {}",
            serde_json::to_string_pretty(&self).expect("valid json serialization")
        )
    }
}

impl JsonHeader {
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

#[derive(Debug)]
pub struct Header {
    bin: BinHeader,
    json: JsonHeader,
}

impl Display for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.bin, f)?;
        Display::fmt(&self.json, f)?;
        Ok(())
    }
}

impl Header {
    pub fn from_reader<R: Read>(mut r: R) -> Result<Self, LuksError> {
        let mut bin_header_bytes = vec![0; LUKS_BIN_HEADER_LEN];
        r.read_exact(&mut bin_header_bytes)?;
        let bin_header_raw = BinHeaderRaw::from_slice(&bin_header_bytes)?;
        let bin_header = BinHeader::try_from(&bin_header_raw)?;
        let mut json_header_bytes = vec![0; bin_header.hdr_size as usize - LUKS_BIN_HEADER_LEN];
        r.read_exact(&mut json_header_bytes)?;
        Self::verify_checksum(&bin_header, &json_header_bytes)?;
        let json_header_str = ascii_cstr_to_str("json_header", &json_header_bytes)?;
        let json_header = JsonHeader::from_slice(&json_header_str.as_bytes())?;
        Ok(Self {
            bin: bin_header,
            json: json_header,
        })
    }

    fn calculate_checksum_generic<H: digest::Digest>(
        bin_header: &BinHeader,
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

    fn verify_checksum_generic<H: digest::Digest>(
        csum: &Output<H>,
        bin_header: &BinHeader,
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

    fn verify_checksum(bin_header: &BinHeader, json_area_bytes: &[u8]) -> Result<(), ParseError> {
        match bin_header.checksum {
            Checksum::Sha256(ref csum) => {
                Self::verify_checksum_generic::<Sha256>(csum, &bin_header, json_area_bytes)
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
pub struct LuksDevice<T: Read + Seek> {
    device: T,
    header: Header,
    master_key: SecretMasterKey,
    current_sector: Cursor<Vec<u8>>,
    current_sector_num: u64,
    // /// The header read from the device.
    // pub header: BinHeaderRaw,
    // /// The JSON section read from the device.
    // pub json: LuksJson,
    // /// The sector size of the device.
    // pub sector_size: usize,
    active_segment_size: u64,
    // /// The segment used when reading from the device. Defaults to segment 0. Calls to `seek()` will
    // /// be considered relative to `active_segment.offset()` if seeking from the start or `active_segment.size()`
    // /// if seeking from the end.
    pub active_segment: Segment,
}

enum PasswordOrMasterKey<'a> {
    Password(&'a [u8]),
    MasterKey(SecretMasterKey),
}

impl<T: Read + Seek> LuksDevice<T> {
    /// Creates a `LuksDevice` from a device (i. e. any type that implements [`Read`] and [`Seek`]).
    pub fn from_device(device: T, password: &[u8]) -> Result<Self, LuksError> {
        Self::from_device_internal(device, PasswordOrMasterKey::Password(password))
    }

    pub fn from_device_with_master_key(
        device: T,
        master_key: SecretMasterKey,
    ) -> Result<Self, LuksError> {
        Self::from_device_internal(device, PasswordOrMasterKey::MasterKey(master_key))
    }

    fn from_device_internal(
        mut device: T,
        password_or_master_key: PasswordOrMasterKey,
    ) -> Result<Self, LuksError> {
        let header = Header::from_reader(&mut device)?;

        let master_key = match password_or_master_key {
            PasswordOrMasterKey::Password(password) => {
                // Data validation
                if header.json.keyslots.len() == 0 {
                    return Err(LuksError::NoKeyslots);
                }
                let digest = header.json.digests.get(0).ok_or(LuksError::NoDigests)?;
                if !digest.segments.contains(&Index(0)) {
                    return Err(LuksError::NoDigestsSegment0);
                }
                Self::decrypt_master_key(&mut device, digest, &header.json.keyslots, password)?
            }
            PasswordOrMasterKey::MasterKey(master_key) => master_key,
        };

        let active_segment = header
            .json
            .segments
            .get(0)
            .ok_or(LuksError::NoSegments)?
            .clone();

        let active_segment_size = match active_segment.size {
            SegmentSize::Fixed(s) => s,
            SegmentSize::Dynamic => {
                let end = device.seek(SeekFrom::End(0))?;
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

        let mut d = Self {
            device,
            header,
            master_key,
            current_sector: Cursor::new(vec![0; 256]),
            current_sector_num: u64::MAX,
            active_segment_size,
            active_segment,
        };
        d.seek(SeekFrom::Start(0))?;

        Ok(d)
    }

    // tries to decrypt the master key with the given password by trying all available keyslots
    fn decrypt_master_key(
        device: &mut T,
        digest: &Digest,
        keyslots: &[Keyslot],
        password: &[u8],
    ) -> Result<SecretMasterKey, LuksError>
    where
        T: Read + Seek,
    {
        let mut keyslots: Vec<&Keyslot> = keyslots.iter().collect();
        keyslots.sort_by_key(|&ks| ks.priority.unwrap_or_default());

        for ks in keyslots.iter().rev() {
            // reverse to get highest priority first
            match Self::decrypt_keyslot(device, digest, ks, password) {
                Ok(mk) => return Ok(mk),
                Err(e) => match e {
                    LuksError::InvalidPassword => {}
                    _ => return Err(e),
                },
            }
        }

        Err(LuksError::InvalidPassword)
    }

    // tries to decrypt the specified keyslot using the given password
    // if successful, returns the master key
    fn decrypt_keyslot(
        device: &mut T,
        digest: &Digest,
        keyslot: &Keyslot,
        password: &[u8],
    ) -> Result<SecretMasterKey, LuksError>
    where
        T: Read + Seek,
    {
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

        // read area of keyslot
        let mut k = vec![0; keyslot.key_size * keyslot_af_stripes.as_usize()];
        device.seek(SeekFrom::Start(keyslot_area.offset))?;
        device.read_exact(&mut k)?;

        // compute master key as hash of password
        let mut pw_hash = vec![0; *keyslot_area_key_size];
        match &keyslot_kdf.type_data {
            KdfTypeData::Argon2i { time, memory, cpus } => {
                let params =
                    argon2::Params::new(*memory, *time, *cpus, Some(*keyslot_area_key_size))?;
                let algorithm = argon2::Algorithm::Argon2i;
                let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
                argon.hash_password_into(password, &keyslot_kdf.salt, &mut pw_hash)?;
            }
            KdfTypeData::Argon2id { time, memory, cpus } => {
                let params =
                    argon2::Params::new(*memory, *time, *cpus, Some(*keyslot_area_key_size))?;
                let algorithm = argon2::Algorithm::Argon2id;
                let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
                argon.hash_password_into(password, &keyslot_kdf.salt, &mut pw_hash)?;
            }
            KdfTypeData::Pbkdf2 { hash, iterations } => {
                let kdf_fn = match hash {
                    Hash::Sha256 => pbkdf2::<Hmac<Sha256>>,
                    Hash::Sha1 => pbkdf2::<Hmac<Sha1>>,
                    Hash::Unknown(h) => return Err(LuksError::UnsupportedPbkdf2Hash(h.clone())),
                };
                kdf_fn(password, &keyslot_kdf.salt, *iterations, &mut pw_hash);
            }
        }

        // make pw_hash a secret after hashing
        let pw_hash = Secret::new(pw_hash);

        // decrypt keyslot area using the password hash as key
        match keyslot_area_encryption {
            Encryption::AesXtsPlain64 => match keyslot_area_key_size {
                32 => {
                    let key1 = Aes128::new_from_slice(&pw_hash.expose_secret()[..16]).unwrap();
                    let key2 = Aes128::new_from_slice(&pw_hash.expose_secret()[16..]).unwrap();
                    let xts = Xts128::<Aes128>::new(key1, key2);
                    xts.decrypt_area(&mut k, LUKS_SECTOR_SIZE, 0, get_tweak_default);
                }
                64 => {
                    let key1 = Aes256::new_from_slice(&pw_hash.expose_secret()[..32]).unwrap();
                    let key2 = Aes256::new_from_slice(&pw_hash.expose_secret()[32..]).unwrap();
                    let xts = Xts128::<Aes256>::new(key1, key2);
                    xts.decrypt_area(&mut k, LUKS_SECTOR_SIZE, 0, get_tweak_default);
                }
                x => return Err(LuksError::UnsupportedKeySize("aes-xts-plain64", *x)),
            },
            Encryption::Unknown(e) => return Err(LuksError::UnsupportedAreaEncryption(e.clone())),
        }
        // make k a secret after decryption
        let k = Secret::new(k);
        // merge and hash master key
        let master_key = match keyslot_af_hash {
            Hash::Sha256 => Secret::new(MasterKey(af::merge::<Sha256>(
                &k.expose_secret(),
                keyslot.key_size,
                keyslot_af_stripes.as_usize(),
            ))),
            Hash::Sha1 => Secret::new(MasterKey(af::merge::<Sha1>(
                &k.expose_secret(),
                keyslot.key_size,
                keyslot_af_stripes.as_usize(),
            ))),
            Hash::Unknown(h) => return Err(LuksError::UnsupportedAfHash(h.clone())),
        };

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

    // updates the internal state so that current sector is the one with the given number
    // decrypts the sector, performs boundary checks (returns an error if sector_num too small,
    // goes to last sector if sector_num too big)
    fn go_to_sector(&mut self, sector_num: u64) -> acid_io::Result<()> {
        let Segment {
            type_data:
                SegmentTypeData::Crypt {
                    iv_tweak,
                    sector_size,
                    encryption,
                    ..
                },
            ..
        } = &self.active_segment;
        let sector_size = sector_size.as_u64();
        if sector_num == self.current_sector_num {
            return Ok(());
        } else if sector_num < (self.active_segment.offset / sector_size as u64) {
            return Err(acid_io::Error::new(
                ErrorKind::InvalidInput,
                "tried to seek to position before active segment",
            ));
        }

        let max_sector = (self.active_segment.offset + self.active_segment_size) / sector_size - 1;
        if sector_num > max_sector {
            self.current_sector = Cursor::new(vec![]);
            self.current_sector_num = sector_num;
            return Ok(());
        }

        self.device
            .seek(SeekFrom::Start(sector_num * sector_size))?;
        let mut sector = vec![0; sector_size as usize];

        self.device.read_exact(&mut sector)?;

        let iv = sector_num - (self.active_segment.offset / sector_size);
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

impl<T: Read + Seek> Read for LuksDevice<T> {
    fn read(&mut self, buf: &mut [u8]) -> acid_io::Result<usize> {
        let Segment {
            type_data: SegmentTypeData::Crypt { sector_size, .. },
            ..
        } = &self.active_segment;
        if self.current_sector.position() == sector_size.as_u64() {
            self.go_to_sector(self.current_sector_num + 1)?;
        }

        self.current_sector.read(buf)
    }
}

impl<T: Read + Seek> Seek for LuksDevice<T> {
    fn seek(&mut self, pos: SeekFrom) -> acid_io::Result<u64> {
        let Segment {
            type_data: SegmentTypeData::Crypt { sector_size, .. },
            ..
        } = &self.active_segment;
        let sector_size = sector_size.as_u64();
        let offset = match pos {
            SeekFrom::Start(p) => self.active_segment.offset + p,
            SeekFrom::End(p) => {
                let p = max(0, p); // limit p to non-positive values (for p > 0 we seek to the end)
                let offset = (self.active_segment.offset as i64
                    + self.active_segment_size as i64
                    + p) as u64;
                if offset < self.active_segment.offset {
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
                if offset < self.active_segment.offset {
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

        Ok(self.current_sector_num * sector_size + self.current_sector.position())
    }
}
