mod file;
mod memory;

pub use file::*;
pub use memory::*;

#[cfg(test)]
mod test {
    use super::super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
    use super::{FileBackedCollector, InMemoryCollector};
    use crate::check::CheckError;
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
            id: Arc::from("test"),
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
            .insert(key("a.json"), ReportSeverity::Warning, vec![check("warn3")])
            .unwrap();
        // append more warnings to b.json
        collector
            .insert(key("b.json"), ReportSeverity::Warning, vec![check("warn4")])
            .unwrap();

        collector
            .insert(key("c.json"), ReportSeverity::Error, vec![check("err1")])
            .unwrap();
        // overwrite error for c.json
        collector
            .insert(key("c.json"), ReportSeverity::Error, vec![check("err2")])
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
                msgs.iter()
                    .map(|m| m.message.to_string())
                    .collect::<Vec<_>>(),
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
                msgs.iter()
                    .map(|m| m.message.to_string())
                    .collect::<Vec<_>>(),
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
