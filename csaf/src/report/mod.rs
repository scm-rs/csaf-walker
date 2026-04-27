//! Reporting functionality

mod render;

pub use render::*;

use crate::discover::DiscoveredAdvisory;
use reqwest::StatusCode;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use url::Url;
use walker_common::utils::url::Urlify;

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub total: usize,
    pub duplicates: &'d Duplicates,
    pub errors: &'d BTreeMap<DocumentKey, String>,
    pub warnings: &'d BTreeMap<DocumentKey, Vec<Cow<'static, str>>>,
    /// Documents that could not be retrieved due to allowed client errors (e.g. 404).
    pub ignored_errors: &'d BTreeMap<DocumentKey, StatusCode>,
}

#[derive(Clone, Debug, Default)]
pub struct Duplicates {
    pub duplicates: BTreeMap<DocumentKey, usize>,
    pub known: HashSet<DocumentKey>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DocumentKey {
    /// the URL to the distribution folder
    pub distribution_url: Url,
    /// the URL to the document, relative to the `distribution_url`.
    pub url: String,
}

impl DocumentKey {
    pub fn for_document(advisory: &DiscoveredAdvisory) -> Self {
        Self {
            distribution_url: advisory.url.clone(),
            url: advisory.possibly_relative_url(),
        }
    }
}
