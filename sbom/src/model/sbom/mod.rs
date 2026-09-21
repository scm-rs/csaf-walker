//! SBOM Model

#[cfg(feature = "serde-cyclonedx")]
pub mod serde_cyclonedx;

mod json;

pub use json::JsonPayload;

use anyhow::{anyhow, bail};
use serde_json::Value;
use std::fmt::{Debug, Display, Formatter};

pub enum Parser {
    CycloneDxJson,
    CycloneDxXml,
}

/// A tool to work with multiple SBOM formats and versions
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Sbom {
    #[cfg(feature = "spdx-rs")]
    Spdx(spdx_rs::models::SPDX),
    #[cfg(feature = "cyclonedx-bom")]
    #[deprecated(
        since = "0.12.0",
        note = "Replaced with serde_cyclonedx and the SerdeCycloneDx variant"
    )]
    CycloneDx(cyclonedx_bom::prelude::Bom),
    #[cfg(feature = "serde-cyclonedx")]
    SerdeCycloneDx(serde_cyclonedx::Sbom<'static>),
}

#[derive(Default, Debug)]
pub struct ParseAnyError(pub Vec<(ParserKind, anyhow::Error)>);

impl std::error::Error for ParseAnyError {}

impl From<(ParserKind, anyhow::Error)> for ParseAnyError {
    fn from(value: (ParserKind, anyhow::Error)) -> Self {
        Self(vec![value])
    }
}

impl ParseAnyError {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn add(mut self, kind: ParserKind, error: anyhow::Error) -> Self {
        self.0.push((kind, error));
        self
    }
}

impl Display for ParseAnyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to parse SBOM:")?;
        if self.0.is_empty() {
            write!(f, "failed to parse SBOM: no parser configured")?;
        } else if self.0.len() == 1 {
            write!(f, "{}: {}", self.0[0].0, self.0[0].1)?;
        } else {
            writeln!(f)?;
            for (kind, err) in &self.0 {
                writeln!(f, "  {kind}: {err}")?;
            }
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParserKind {
    Cyclone13DxJson,
    Cyclone13DxXml,
    Spdx23Json,
    Spdx23Tag,
}

impl Display for ParserKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cyclone13DxJson => write!(f, "CycloneDX 1.3 JSON"),
            Self::Cyclone13DxXml => write!(f, "CycloneDX 1.3 XML"),
            Self::Spdx23Json => write!(f, "SPDX 2.3 JSON"),
            Self::Spdx23Tag => write!(f, "SPDX 2.3 tagged"),
        }
    }
}

impl Sbom {
    /// test if the file is a CycloneDX document, returning the file version
    pub fn is_cyclondx_json(json: &Value) -> anyhow::Result<&str> {
        let format = json["bomFormat"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing field 'bomFormat'"))?;

        if format != "CycloneDX" {
            bail!("Unknown CycloneDX 'bomFormat' value: {format}");
        }

        let spec_version = json["specVersion"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing field 'specVersion'"))?;

        Ok(spec_version)
    }

    /// test if the file is a SPDX document, returning the file version
    pub fn is_spdx_json(json: &Value) -> anyhow::Result<&str> {
        let version = json["spdxVersion"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing field 'spdxVersion'"))?;

        Ok(version)
    }

    pub fn try_parse_any_json(json: Value) -> Result<Self, ParseAnyError> {
        let err = ParseAnyError::new();

        #[cfg(feature = "serde-cyclonedx")]
        let err = match Self::is_cyclondx_json(&json) {
            Ok("1.4" | "1.5" | "1.6" | "1.7") => {
                return Self::try_serde_cyclonedx_json(JsonPayload::Value(json)).map_err(|e| {
                    // drop any previous error, as we know what format and version it is
                    ParseAnyError::from((ParserKind::Cyclone13DxJson, e.into()))
                });
            }
            Ok(version) => {
                // We can stop here, and drop any previous error, as we know what the format is.
                // But we disagree with the version.
                return Err(ParseAnyError::from((
                    ParserKind::Cyclone13DxJson,
                    anyhow!("Unsupported CycloneDX version: {version}"),
                )));
            }
            // failed to detect as CycloneDX, record error and move on
            Err(e) => err.add(ParserKind::Cyclone13DxJson, e),
        };

        #[cfg(feature = "cyclonedx-bom")]
        let err = match Self::is_cyclondx_json(&json) {
            Ok("1.2" | "1.3" | "1.4") => {
                return Self::try_cyclonedx_json(JsonPayload::Value(json)).map_err(|e| {
                    // drop any previous error, as we know what format and version it is
                    ParseAnyError::from((ParserKind::Cyclone13DxJson, e.into()))
                });
            }
            Ok(version) => {
                // We can stop here, and drop any previous error, as we know what the format is.
                // But we disagree with the version.
                return Err(ParseAnyError::from((
                    ParserKind::Cyclone13DxJson,
                    anyhow!("Unsupported CycloneDX version: {version}"),
                )));
            }
            // failed to detect as CycloneDX, record error and move on
            Err(e) => err.add(ParserKind::Cyclone13DxJson, e),
        };

        #[cfg(feature = "spdx-rs")]
        let err = match Self::is_spdx_json(&json) {
            Ok("SPDX-2.2" | "SPDX-2.3") => {
                return Self::try_spdx_json(JsonPayload::Value(json)).map_err(|e| {
                    // drop any previous error, as we know what format and version it is
                    ParseAnyError::from((ParserKind::Spdx23Json, e.into()))
                });
            }
            Ok(version) => {
                // We can stop here, and drop any previous error, as we know what the format is.
                // But we disagree with the version.
                return Err(ParseAnyError::from((
                    ParserKind::Spdx23Json,
                    anyhow!("Unsupported SPDX version: {version}"),
                )));
            }
            Err(e) => err.add(ParserKind::Spdx23Json, e),
        };

        // mark as unused for clippy
        let _json = json;
        Err(err)
    }

    /// try parsing with all possible kinds that make sense.
    pub fn try_parse_any(data: &[u8]) -> Result<Self, ParseAnyError> {
        #[allow(unused)]
        if let Ok(json) = serde_json::from_slice(data) {
            // try to parse this as JSON, which eliminates e.g. the "tag" format, which seems to just parse anything

            Self::try_parse_any_json(json)
        } else {
            // it is not JSON, it could be XML or "tagged"
            let err = ParseAnyError::new();

            #[cfg(feature = "cyclonedx-bom")]
            let err = match Self::try_cyclonedx_xml(data) {
                Ok(doc) => return Ok(doc),
                Err(e) => err.add(ParserKind::Cyclone13DxXml, e.into()),
            };

            #[cfg(feature = "spdx-rs")]
            use anyhow::Context;

            #[cfg(feature = "spdx-rs")]
            let err = match std::str::from_utf8(data)
                .context("unable to interpret bytes as string")
                .and_then(|data| Self::try_spdx_tag(data).map_err(|err| err.into()))
            {
                Ok(doc) => return Ok(doc),
                Err(e) => err.add(ParserKind::Spdx23Tag, e),
            };

            Err(err)
        }
    }

    #[cfg(feature = "spdx-rs")]
    pub fn try_spdx_json(data: JsonPayload) -> Result<Self, serde_json::Error> {
        Ok(Self::Spdx(data.parse()?))
    }

    #[cfg(feature = "spdx-rs")]
    pub fn try_spdx_tag(data: &str) -> Result<Self, spdx_rs::error::SpdxError> {
        Ok(Self::Spdx(spdx_rs::parsers::spdx_from_tag_value(data)?))
    }

    #[cfg(feature = "cyclonedx-bom")]
    #[allow(deprecated)]
    pub fn try_cyclonedx_json<'a>(
        data: impl Into<JsonPayload<'a>>,
    ) -> Result<Self, cyclonedx_bom::errors::JsonReadError> {
        use cyclonedx_bom::prelude::Bom;

        match data.into() {
            JsonPayload::Value(json) => Ok(Self::CycloneDx(Bom::parse_json_value(json)?)),
            JsonPayload::Bytes(data) => Ok(Self::CycloneDx(Bom::parse_from_json(data)?)),
        }
    }

    #[cfg(feature = "cyclonedx-bom")]
    #[allow(deprecated)]
    pub fn try_cyclonedx_xml(data: &[u8]) -> Result<Self, cyclonedx_bom::errors::XmlReadError> {
        Ok(Self::CycloneDx(
            cyclonedx_bom::prelude::Bom::parse_from_xml_v1_3(data)?,
        ))
    }

    #[cfg(feature = "serde-cyclonedx")]
    pub fn try_serde_cyclonedx_json<'a>(
        data: impl Into<JsonPayload<'a>>,
    ) -> Result<Self, serde_json::Error> {
        match data.into() {
            JsonPayload::Value(json) => Ok(Self::SerdeCycloneDx(serde_json::from_value(json)?)),
            JsonPayload::Bytes(data) => Ok(Self::SerdeCycloneDx(serde_json::from_slice(data)?)),
        }
    }
}
