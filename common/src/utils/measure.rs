//! Measuring the time of operations

use crate::utils::time::Human;
use std::time::{Duration, SystemTime};

pub struct MeasureTime(SystemTime);

impl MeasureTime {
    pub fn new() -> Self {
        Self(SystemTime::now())
    }
}

impl Default for MeasureTime {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MeasureTime {
    fn drop(&mut self) {
        match self.0.elapsed() {
            Ok(duration) => {
                // truncate to seconds, good enough
                let duration = Duration::from_secs(duration.as_secs());
                log::info!("Processing took {}", Human(duration))
            }
            Err(err) => log::warn!("Unable to measure processing time: {err}"),
        }
    }
}
