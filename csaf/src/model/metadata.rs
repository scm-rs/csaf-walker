use chrono::{DateTime, Utc};
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Feed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub tlp_label: TlpLabel,
    pub url: Url,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TlpLabel {
    Unlabeled,
    White,
    Green,
    Amber,
    Red,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherCategory {
    Coordinator,
    Discoverer,
    Other,
    Translator,
    User,
    Vendor,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum MetadataVersion {
    #[serde(rename = "2.0")]
    V2_0,
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
