use super::super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
use crate::check::CheckError;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{BufRead, BufReader, Seek, SeekFrom},
};
use tokio::io::{AsyncWriteExt, BufWriter};

#[derive(Serialize, Deserialize)]
struct Record {
    key: DocumentKey,
    severity: ReportSeverity,
    messages: Vec<CheckError>,
}

/// File-backed report collector.
///
/// Writes report data to an anonymous temp file during collection, keeping
/// memory usage low. The file is automatically cleaned up when dropped.
///
/// Compared to [`super::InMemoryCollector`], this collector has the following
/// limitations:
///
/// - Output is not sorted by document key
/// - Warnings for the same document may appear in separate entries
/// - Error overwrites for the same key are not applied
pub struct FileBackedCollector {
    writer: BufWriter<tokio::fs::File>,
    error_count: usize,
    error_total: usize,
    warning_count: usize,
    warning_total: usize,
    info_count: usize,
    info_total: usize,
}

impl FileBackedCollector {
    pub fn new() -> anyhow::Result<Self> {
        let std_file = tempfile::tempfile()?;
        let tokio_file = tokio::fs::File::from_std(std_file);
        Ok(Self {
            writer: BufWriter::new(tokio_file),
            error_count: 0,
            error_total: 0,
            warning_count: 0,
            warning_total: 0,
            info_count: 0,
            info_total: 0,
        })
    }
}

impl ReportCollector for FileBackedCollector {
    type View = FileBackedView;

    async fn insert(
        &mut self,
        key: DocumentKey,
        severity: ReportSeverity,
        messages: Vec<CheckError>,
    ) -> anyhow::Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        let count = messages.len();
        match severity {
            ReportSeverity::Error => {
                self.error_count += 1;
                self.error_total += count;
            }
            ReportSeverity::Warning => {
                self.warning_count += 1;
                self.warning_total += count;
            }
            ReportSeverity::Info => {
                self.info_count += 1;
                self.info_total += count;
            }
        }

        let record = Record {
            key,
            severity,
            messages,
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        self.writer.write_all(&line).await?;

        Ok(())
    }

    async fn into_view(mut self) -> anyhow::Result<Self::View> {
        self.writer.flush().await?;
        let tokio_file = self.writer.into_inner();
        let mut std_file = tokio_file.into_std().await;
        std_file.seek(SeekFrom::Start(0))?;

        Ok(FileBackedView {
            file: std_file,
            error_count: self.error_count,
            error_total: self.error_total,
            warning_count: self.warning_count,
            warning_total: self.warning_total,
            info_count: self.info_count,
            info_total: self.info_total,
        })
    }
}

pub struct FileBackedView {
    file: std::fs::File,
    error_count: usize,
    error_total: usize,
    warning_count: usize,
    warning_total: usize,
    info_count: usize,
    info_total: usize,
}

impl ReportView for FileBackedView {
    fn count(&self, severity: &ReportSeverity) -> usize {
        match severity {
            ReportSeverity::Error => self.error_count,
            ReportSeverity::Warning => self.warning_count,
            ReportSeverity::Info => self.info_count,
        }
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
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0)).map_err(|_| fmt::Error)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(|_| fmt::Error)?;
            if line.is_empty() {
                continue;
            }
            let record: Record = serde_json::from_str(&line).map_err(|_| fmt::Error)?;
            if &record.severity == severity {
                f(&record.key, &record.messages)?;
            }
        }
        Ok(())
    }
}
