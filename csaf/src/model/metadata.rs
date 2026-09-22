use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Distribution {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_url: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolie: Option<Rolie>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Rolie {
    #[serde(default)]
    pub categories: Vec<Url>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feeds: Vec<Feed>,
    #[serde(default)]
    pub services: Vec<Url>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Feed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(
        deserialize_with = "deserialize_tlp_label",
        serialize_with = "serialize_tlp_label"
    )]
    pub tlp_label: Option<TlpLabel>,
    pub url: Url,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    strum::Display,
    strum::EnumString,
    strum::VariantNames,
)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "lowercase")]
pub enum TlpLabel {
    White,
    Green,
    Amber,
    Red,
}

fn deserialize_tlp_label<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TlpLabel>, D::Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    enum Raw {
        Unlabeled,
        White,
        Green,
        Amber,
        Red,
    }

    Ok(match Raw::deserialize(deserializer)? {
        Raw::Unlabeled => None,
        Raw::White => Some(TlpLabel::White),
        Raw::Green => Some(TlpLabel::Green),
        Raw::Amber => Some(TlpLabel::Amber),
        Raw::Red => Some(TlpLabel::Red),
    })
}

fn serialize_tlp_label<S: Serializer>(
    value: &Option<TlpLabel>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        None => serializer.serialize_str("UNLABELED"),
        Some(TlpLabel::White) => serializer.serialize_str("WHITE"),
        Some(TlpLabel::Green) => serializer.serialize_str("GREEN"),
        Some(TlpLabel::Amber) => serializer.serialize_str("AMBER"),
        Some(TlpLabel::Red) => serializer.serialize_str("RED"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Key {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub url: Url,
}

impl<'a> From<&'a Key> for walker_common::validate::source::Key<'a> {
    fn from(value: &'a Key) -> Self {
        walker_common::validate::source::Key {
            fingerprint: value.fingerprint.as_deref(),
            url: &value.url,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Publisher {
    pub category: PublisherCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuing_authority: Option<String>,
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherCategory {
    Coordinator,
    Discoverer,
    Other,
    Translator,
    User,
    Vendor,
    #[serde(untagged)]
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum MetadataVersion {
    #[serde(rename = "2.0")]
    V2_0,
    #[serde(untagged)]
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProviderMetadata {
    pub canonical_url: Url,

    #[serde(default)]
    pub distributions: Vec<Distribution>,

    pub last_updated: DateTime<Utc>,

    #[serde(rename = "list_on_CSAF_aggregators")]
    #[serde(default)]
    pub list_on_csaf_aggregators: bool,

    pub metadata_version: MetadataVersion,

    #[serde(rename = "mirror_on_CSAF_aggregators")]
    #[serde(default)]
    pub mirror_on_csaf_aggregators: bool,

    #[serde(default)]
    pub public_openpgp_keys: Vec<Key>,

    pub publisher: Publisher,

    /// Contains the role of the issuing party according to section 7 in the CSAF standard.
    #[serde(default = "default_role")]
    pub role: Role,
}

const fn default_role() -> Role {
    Role::Provider
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum Role {
    #[serde(rename = "csaf_publisher")]
    Publisher,
    #[serde(rename = "csaf_provider")]
    Provider,
    #[serde(rename = "csaf_trusted_provider")]
    TrustedProvider,
}
