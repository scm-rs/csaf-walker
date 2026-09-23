use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    /// A missing label is treated as [`TlpLabel::Unlabeled`].
    #[serde(default)]
    pub tlp_label: TlpLabel,
    pub url: Url,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
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
    #[default]
    Unlabeled,
    #[serde(alias = "WHITE")]
    #[strum(to_string = "clear", serialize = "white")]
    Clear,
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

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::unlabeled(Some("UNLABELED"), TlpLabel::Unlabeled)]
    #[case::clear(Some("CLEAR"), TlpLabel::Clear)]
    #[case::white(Some("WHITE"), TlpLabel::Clear)]
    #[case::red(Some("RED"), TlpLabel::Red)]
    #[case::missing(None, TlpLabel::Unlabeled)]
    fn tlp_label_deserialize(#[case] tlp_label: Option<&str>, #[case] expected: TlpLabel) {
        let mut feed = json!({"url": "https://example.com/feed.json"});
        if let Some(tlp_label) = tlp_label {
            feed["tlp_label"] = tlp_label.into();
        }
        let feed: Feed = serde_json::from_value(feed).expect("must deserialize");
        assert_eq!(feed.tlp_label, expected);
    }

    #[rstest]
    #[case::unlabeled(TlpLabel::Unlabeled, "UNLABELED")]
    #[case::clear(TlpLabel::Clear, "CLEAR")]
    fn tlp_label_serialize(#[case] label: TlpLabel, #[case] expected: &str) {
        assert_eq!(serde_json::to_value(label).unwrap(), json!(expected));
    }

    #[rstest]
    #[case::unlabeled(TlpLabel::Unlabeled, "unlabeled")]
    #[case::clear(TlpLabel::Clear, "clear")]
    fn tlp_label_display(#[case] label: TlpLabel, #[case] expected: &str) {
        assert_eq!(label.to_string(), expected);
    }

    #[rstest]
    #[case::unlabeled("unlabeled", TlpLabel::Unlabeled)]
    #[case::clear("clear", TlpLabel::Clear)]
    #[case::white("white", TlpLabel::Clear)]
    fn tlp_label_from_str(#[case] input: &str, #[case] expected: TlpLabel) {
        assert_eq!(input.parse::<TlpLabel>().unwrap(), expected);
    }
}
