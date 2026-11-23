//! Working with durations and timestamps

use jiff::{Span, SpanRound, Timestamp, Unit, ZonedDateTime};
use std::{
    fmt::{self, Display, Formatter},
    time::{Duration, SystemTime},
};

/// Extension functions for [`Span`].
pub trait SpanExt {
    /// Resolve to an absolute, non-negative duration.
    ///
    /// Calendar units (like months or years) are resolved relative to now.
    fn to_std_duration(&self) -> anyhow::Result<Duration>;
}

impl SpanExt for Span {
    fn to_std_duration(&self) -> anyhow::Result<Duration> {
        Ok(Duration::try_from(
            self.to_duration(&ZonedDateTime::now())?,
        )?)
    }
}

/// Wrapper for displaying values in a human-readable form.
///
/// ```
/// use std::time::Duration;
/// use walker_common::utils::time::Human;
///
/// assert_eq!(Human(Duration::from_secs(90)).to_string(), "1m 30s");
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Human<T>(pub T);

impl Display for Human<SystemTime> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match Timestamp::try_from(self.0).and_then(|ts| ts.round(Unit::Second)) {
            Ok(ts) => Display::fmt(&ts, f),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

impl Display for Human<Duration> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let span = Span::try_from(self.0)
            .and_then(|span| span.round(SpanRound::new().largest(Unit::Day).days_are_24_hours()));
        match span {
            Ok(span) => write!(f, "{span:#}"),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

impl Display for Human<Span> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("5s", 5)]
    #[case("1h 30m", 90 * 60)]
    #[case("2d", 2 * 24 * 60 * 60)]
    #[case("1w", 7 * 24 * 60 * 60)]
    #[case("PT5S", 5)]
    fn to_std_duration(#[case] input: &str, #[case] expected: u64) {
        let span: Span = input.parse().expect("must parse");
        assert_eq!(
            span.to_std_duration().expect("must convert"),
            Duration::from_secs(expected)
        );
    }

    #[test]
    fn to_std_duration_calendar() {
        let span: Span = "1mo".parse().expect("must parse");
        let duration = span.to_std_duration().expect("must convert");
        assert!(duration >= Duration::from_secs(28 * 24 * 60 * 60));
        assert!(duration <= Duration::from_secs(31 * 24 * 60 * 60));
    }

    #[test]
    fn to_std_duration_negative() {
        let span: Span = "-1s".parse().expect("must parse");
        assert!(span.to_std_duration().is_err());
    }

    #[test]
    fn invalid() {
        assert!("foo".parse::<Span>().is_err());
    }

    #[rstest]
    #[case(0, "0s")]
    #[case(90, "1m 30s")]
    #[case(26 * 60 * 60 + 3, "1d 2h 3s")]
    fn human_duration(#[case] secs: u64, #[case] expected: &str) {
        assert_eq!(Human(Duration::from_secs(secs)).to_string(), expected);
    }

    #[test]
    fn human_system_time() {
        let time = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_400);
        assert_eq!(Human(time).to_string(), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn human_span() {
        let span: Span = "P1DT2H".parse().expect("must parse");
        assert_eq!(Human(span).to_string(), "1d 2h");
    }
}
