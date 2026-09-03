use super::super::{DocumentKey, ReportCollector, ReportSeverity, ReportView};
use crate::check::CheckError;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
};

#[derive(Serialize, Deserialize)]
struct Record {
    messages: Vec<CheckError>,
}

struct IndexEntry {
    offsets: Vec<u64>,
    total: usize,
}

pub struct FileBackedCollector {
    writer: BufWriter<std::fs::File>,
    error_index: BTreeMap<DocumentKey, IndexEntry>,
    warning_index: BTreeMap<DocumentKey, IndexEntry>,
}

impl FileBackedCollector {
    pub fn new() -> anyhow::Result<Self> {
        let file = tempfile::tempfile()?;
        Ok(Self {
            writer: BufWriter::new(file),
            error_index: BTreeMap::new(),
            warning_index: BTreeMap::new(),
        })
    }

    fn index_for(&mut self, severity: &ReportSeverity) -> &mut BTreeMap<DocumentKey, IndexEntry> {
        match severity {
            ReportSeverity::Error => &mut self.error_index,
            ReportSeverity::Warning => &mut self.warning_index,
        }
    }
}

impl ReportCollector for FileBackedCollector {
    type View = FileBackedView;

    fn insert(
        &mut self,
        key: DocumentKey,
        severity: ReportSeverity,
        messages: Vec<CheckError>,
    ) -> anyhow::Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        let offset = self.writer.stream_position()?;
        let count = messages.len();

        let record = Record { messages };
        serde_json::to_writer(&mut self.writer, &record)?;
        writeln!(&mut self.writer)?;

        let index = self.index_for(&severity);
        if matches!(severity, ReportSeverity::Error) {
            let entry = index.entry(key).or_insert_with(|| IndexEntry {
                offsets: Vec::new(),
                total: 0,
            });
            entry.offsets.clear();
            entry.total = count;
            entry.offsets.push(offset);
        } else {
            let entry = index.entry(key).or_insert_with(|| IndexEntry {
                offsets: Vec::new(),
                total: 0,
            });
            entry.total += count;
            entry.offsets.push(offset);
        }

        Ok(())
    }

    fn into_view(mut self) -> anyhow::Result<Self::View> {
        self.writer.flush()?;
        let file = self.writer.into_inner()?;

        Ok(FileBackedView {
            file,
            error_index: self.error_index,
            warning_index: self.warning_index,
        })
    }
}

pub struct FileBackedView {
    file: std::fs::File,
    error_index: BTreeMap<DocumentKey, IndexEntry>,
    warning_index: BTreeMap<DocumentKey, IndexEntry>,
}

impl FileBackedView {
    fn index_for(&self, severity: &ReportSeverity) -> &BTreeMap<DocumentKey, IndexEntry> {
        match severity {
            ReportSeverity::Error => &self.error_index,
            ReportSeverity::Warning => &self.warning_index,
        }
    }

    fn read_record(&self, offset: u64) -> Result<Record, fmt::Error> {
        let mut file = &self.file;
        file.seek(SeekFrom::Start(offset)).map_err(|_| fmt::Error)?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| fmt::Error)?;
        serde_json::from_str(&line).map_err(|_| fmt::Error)
    }
}

impl ReportView for FileBackedView {
    fn count(&self, severity: &ReportSeverity) -> usize {
        self.index_for(severity).len()
    }

    fn total(&self, severity: &ReportSeverity) -> usize {
        self.index_for(severity).values().map(|e| e.total).sum()
    }

    fn for_each(
        &self,
        severity: &ReportSeverity,
        f: &mut dyn FnMut(&DocumentKey, &[CheckError]) -> fmt::Result,
    ) -> fmt::Result {
        for (key, entry) in self.index_for(severity) {
            let mut all_messages = Vec::with_capacity(entry.total);
            for &offset in &entry.offsets {
                let record = self.read_record(offset)?;
                all_messages.extend(record.messages);
            }
            f(key, &all_messages)?;
        }
        Ok(())
    }
}
