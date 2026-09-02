use super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
use crate::verification::check::CheckError;
use std::collections::BTreeMap;
use std::fmt;

pub struct InMemoryView {
    errors: BTreeMap<DocumentKey, Vec<CheckError>>,
    warnings: BTreeMap<DocumentKey, Vec<CheckError>>,
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

#[cfg(test)]
mod test {
    use super::super::{DocumentKey, FileBackedCollector, ReportCollector, ReportSeverity, ReportView};
    use super::InMemoryCollector;
    use crate::verification::check::CheckError;
    use std::sync::Arc;
    use url::Url;

    fn key(name: &str) -> DocumentKey {
        DocumentKey {
            distribution_url: Url::parse("https://example.com/").unwrap(),
            url: name.to_string(),
        }
    }

    fn check(msg: &str) -> CheckError {
        CheckError {
            message: Arc::from(msg),
        }
    }

    fn assert_collector_behavior(mut collector: impl ReportCollector) {
        collector
            .insert(
                key("b.json"),
                ReportSeverity::Warning,
                vec![check("warn1"), check("warn2")],
            )
            .unwrap();
        collector
            .insert(
                key("a.json"),
                ReportSeverity::Warning,
                vec![check("warn3")],
            )
            .unwrap();
        // append more warnings to b.json
        collector
            .insert(
                key("b.json"),
                ReportSeverity::Warning,
                vec![check("warn4")],
            )
            .unwrap();

        collector
            .insert(
                key("c.json"),
                ReportSeverity::Error,
                vec![check("err1")],
            )
            .unwrap();
        // overwrite error for c.json
        collector
            .insert(
                key("c.json"),
                ReportSeverity::Error,
                vec![check("err2")],
            )
            .unwrap();

        // empty insert should be a no-op
        collector
            .insert(key("d.json"), ReportSeverity::Warning, vec![])
            .unwrap();

        let view = collector.into_view().unwrap();

        // warning counts
        assert_eq!(view.count(&ReportSeverity::Warning), 2);
        assert_eq!(view.total(&ReportSeverity::Warning), 4);

        // error counts
        assert_eq!(view.count(&ReportSeverity::Error), 1);
        assert_eq!(view.total(&ReportSeverity::Error), 1);

        // warnings iteration is sorted by key
        let mut warning_keys = Vec::new();
        let mut warning_messages = Vec::new();
        view.for_each(&ReportSeverity::Warning, &mut |k, msgs| {
            warning_keys.push(k.url.clone());
            warning_messages.push(
                msgs.iter().map(|m| m.message.to_string()).collect::<Vec<_>>(),
            );
            Ok(())
        })
        .unwrap();

        assert_eq!(warning_keys, vec!["a.json", "b.json"]);
        assert_eq!(warning_messages[0], vec!["warn3"]);
        assert_eq!(warning_messages[1], vec!["warn1", "warn2", "warn4"]);

        // errors iteration — should have overwritten value
        let mut error_messages = Vec::new();
        view.for_each(&ReportSeverity::Error, &mut |_k, msgs| {
            error_messages.push(
                msgs.iter().map(|m| m.message.to_string()).collect::<Vec<_>>(),
            );
            Ok(())
        })
        .unwrap();

        assert_eq!(error_messages, vec![vec!["err2"]]);
    }

    #[test]
    fn in_memory_collector() {
        assert_collector_behavior(InMemoryCollector::new());
    }

    #[test]
    fn file_backed_collector() {
        assert_collector_behavior(FileBackedCollector::new().unwrap());
    }
}
