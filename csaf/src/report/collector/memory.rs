use super::super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
use crate::check::CheckError;
use std::{collections::BTreeMap, fmt};

pub struct InMemoryView {
    errors: BTreeMap<DocumentKey, Vec<CheckError>>,
    warnings: BTreeMap<DocumentKey, Vec<CheckError>>,
    infos: BTreeMap<DocumentKey, Vec<CheckError>>,
    error_total: usize,
    warning_total: usize,
    info_total: usize,
}

impl Default for InMemoryView {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryView {
    pub fn new() -> Self {
        Self {
            errors: BTreeMap::new(),
            warnings: BTreeMap::new(),
            infos: BTreeMap::new(),
            error_total: 0,
            warning_total: 0,
            info_total: 0,
        }
    }

    fn map_for(&self, severity: &ReportSeverity) -> &BTreeMap<DocumentKey, Vec<CheckError>> {
        match severity {
            ReportSeverity::Error => &self.errors,
            ReportSeverity::Warning => &self.warnings,
            ReportSeverity::Info => &self.infos,
        }
    }
}

impl ReportView for InMemoryView {
    fn count(&self, severity: &ReportSeverity) -> usize {
        self.map_for(severity).len()
    }

    fn total(&self, severity: &ReportSeverity) -> usize {
        match severity {
            ReportSeverity::Error => self.error_total,
            ReportSeverity::Warning => self.warning_total,
            ReportSeverity::Info => self.info_total,
        }
    }

    fn for_each(
        &self,
        severity: &ReportSeverity,
        f: &mut dyn FnMut(&DocumentKey, &[CheckError]) -> fmt::Result,
    ) -> fmt::Result {
        for (k, v) in self.map_for(severity) {
            f(k, v)?;
        }
        Ok(())
    }
}

pub struct InMemoryCollector {
    view: InMemoryView,
}

impl InMemoryCollector {
    pub fn new() -> Self {
        Self {
            view: InMemoryView::new(),
        }
    }
}

impl Default for InMemoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportCollector for InMemoryCollector {
    type View = InMemoryView;

    async fn insert(
        &mut self,
        key: DocumentKey,
        severity: ReportSeverity,
        messages: Vec<CheckError>,
        total: usize,
    ) -> anyhow::Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        match severity {
            ReportSeverity::Error => {
                self.view.errors.entry(key).or_default().extend(messages);
                self.view.error_total += total;
            }
            ReportSeverity::Warning => {
                self.view.warnings.entry(key).or_default().extend(messages);
                self.view.warning_total += total;
            }
            ReportSeverity::Info => {
                self.view.infos.entry(key).or_default().extend(messages);
                self.view.info_total += total;
            }
        }
        Ok(())
    }

    async fn into_view(self) -> anyhow::Result<Self::View> {
        Ok(self.view)
    }
}
