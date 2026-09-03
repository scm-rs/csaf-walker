//! Reporting functionality

mod collector;
mod file_collector;
mod render;

pub use collector::*;
pub use file_collector::*;
pub use render::*;

use crate::{check::CheckError, discover::DiscoveredAdvisory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use url::Url;
use walker_common::utils::url::Urlify;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSeverity {
    Error,
    Warning,
}

pub trait ReportCollector: Send {
    type View: ReportView;

    fn insert(
        &mut self,
        key: DocumentKey,
        severity: ReportSeverity,
        messages: Vec<CheckError>,
    ) -> anyhow::Result<()>;

    fn into_view(self) -> anyhow::Result<Self::View>;
}

pub trait ReportView {
    fn count(&self, severity: &ReportSeverity) -> usize;
    fn total(&self, severity: &ReportSeverity) -> usize;
    fn for_each(
        &self,
        severity: &ReportSeverity,
        f: &mut dyn FnMut(&DocumentKey, &[CheckError]) -> fmt::Result,
    ) -> fmt::Result;
}

pub struct ReportResult<'d> {
    pub total: usize,
    pub duplicates: &'d Duplicates,
    pub view: &'d dyn ReportView,
}

impl fmt::Debug for ReportResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportResult")
            .field("total", &self.total)
            .field("duplicates", &self.duplicates)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Duplicates {
    pub duplicates: BTreeMap<DocumentKey, usize>,
    pub known: HashSet<DocumentKey>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
