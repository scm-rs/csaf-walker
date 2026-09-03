use super::super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
use crate::check::CheckError;
use std::{collections::BTreeMap, fmt};

pub struct InMemoryView {
    errors: BTreeMap<DocumentKey, Vec<CheckError>>,
    warnings: BTreeMap<DocumentKey, Vec<CheckError>>,
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
        }
    }

    fn map_for(&self, severity: &ReportSeverity) -> &BTreeMap<DocumentKey, Vec<CheckError>> {
        match severity {
            ReportSeverity::Error => &self.errors,
            ReportSeverity::Warning => &self.warnings,
        }
    }
}

impl ReportView for InMemoryView {
    fn count(&self, severity: &ReportSeverity) -> usize {
        self.map_for(severity).len()
    }

    fn total(&self, severity: &ReportSeverity) -> usize {
        self.map_for(severity).values().map(|v| v.len()).sum()
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

    fn insert(
        &mut self,
        key: DocumentKey,
        severity: ReportSeverity,
        messages: Vec<CheckError>,
    ) -> anyhow::Result<()> {
        if messages.is_empty() {
            return Ok(());
        }
        let map = match severity {
            ReportSeverity::Error => &mut self.view.errors,
            ReportSeverity::Warning => &mut self.view.warnings,
        };
        match severity {
            ReportSeverity::Error => {
                map.insert(key, messages);
            }
            ReportSeverity::Warning => {
                map.entry(key).or_default().extend(messages);
            }
        }
        Ok(())
    }

    fn into_view(self) -> anyhow::Result<Self::View> {
        Ok(self.view)
    }
}
