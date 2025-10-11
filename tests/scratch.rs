use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub enum LuksPriority {
    /// The slot should be used only if explicitly stated.
    Ignore,
    /// Normal priority keyslot.
    Normal,
    /// Tried before normal priority keyslots.
    High,
}

/// A keyslot contains information about stored keys – areas, where binary keyslot data are located,
/// encryption and anti-forensic function used, password-based key derivation function (PBKDF) and
/// related parameters.
///
/// Only the `luks2` type is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksKeyslot {
    luks2 {
        /// The size of the key stored in the slot, in bytes.
        key_size: u16,
        /// The keyslot priority (optional).
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        priority: Option<LuksPriority>,
    },
}

#[test]
fn test_scratch_1() {
    let k = LuksKeyslot::luks2 {
        key_size: 42,
        priority: None,
    };
    let k_json = serde_json::to_string_pretty(&k).unwrap();
    println!("{}", k_json);

    let k = LuksKeyslot::luks2 {
        key_size: 42,
        priority: Some(LuksPriority::High),
    };
    let k_json = serde_json::to_string_pretty(&k).unwrap();
    println!("{}", k_json);
}
