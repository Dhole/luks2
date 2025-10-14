use pretty_assertions::assert_eq;
use serde::{de, Deserialize, Deserializer, Serialize};

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

#[test]
fn test_json_1() {
    #[derive(Debug, PartialEq, Serialize)]
    pub struct Unsupported {}

    impl<'de> Deserialize<'de> for Unsupported {
        fn deserialize<D>(_deserializer: D) -> Result<Unsupported, D::Error>
        where
            D: Deserializer<'de>,
        {
            Err(de::Error::custom("unsupported feature"))
        }
    }

    #[derive(Debug, Deserialize)]
    struct Foo {
        a: u64,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        b: Option<Unsupported>,
    }

    let s = r#"{"a": 2, "b": {}}"#;
    let f: Foo = serde_json::from_str(s).unwrap();
    println!("{:?}", f);
}

#[test]
fn test_json_2() {
    use luks2::Index;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct Foo {
        xs: Vec<Index>,
    }

    let f = Foo {
        xs: vec![Index(1), Index(2)],
    };
    let s = serde_json::to_string_pretty(&f).unwrap();
    println!("{}", s);
    let f2: Foo = serde_json::from_str(&s).unwrap();
    println!("{:#?}", f2);
}

#[test]
fn test_json_3() {
    use luks2::new_lib::LuksJson;

    let data = String::from_utf8(include_bytes!("test.json").to_vec()).unwrap();
    let parsed: LuksJson = serde_json::from_str(&data).unwrap();
    println!("{:?}", parsed);

    // Compare read JSON vs recovered JSON
    let value: serde_json::Value = serde_json::from_str(&data).unwrap();
    let value2: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(value, value2);
}
