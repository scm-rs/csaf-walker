use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum Sbom<'a> {
    V1_4(Cow<'a, serde_cyclonedx::cyclonedx::v_1_4::CycloneDx>),
    V1_5(Cow<'a, serde_cyclonedx::cyclonedx::v_1_5::CycloneDx>),
    V1_6(Cow<'a, serde_cyclonedx::cyclonedx::v_1_6::CycloneDx>),
    V1_7(Cow<'a, serde_cyclonedx::cyclonedx::v_1_7::CycloneDx>),
}

impl Serialize for Sbom<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::V1_4(sbom) => sbom.serialize(serializer),
            Self::V1_5(sbom) => sbom.serialize(serializer),
            Self::V1_6(sbom) => sbom.serialize(serializer),
            Self::V1_7(sbom) => sbom.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Sbom<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        // peek into the version, and select the correct version
        let json = serde_json::Value::deserialize(deserializer)?;

        let version = json["specVersion"]
            .as_str()
            .ok_or_else(|| D::Error::missing_field("specVersion"))?
            .to_string();

        match version.as_str() {
            "1.4" => serde_json::from_value(json).map(|s| Self::V1_4(Cow::Owned(s))),
            "1.5" => serde_json::from_value(json).map(|s| Self::V1_5(Cow::Owned(s))),
            "1.6" => serde_json::from_value(json).map(|s| Self::V1_6(Cow::Owned(s))),
            "1.7" => serde_json::from_value(json).map(|s| Self::V1_7(Cow::Owned(s))),
            version => {
                return Err(D::Error::custom(format!(
                    "Unsupported CycloneDX version: {version}"
                )));
            }
        }
        .map_err(D::Error::custom)
    }
}

macro_rules! attribute {
    ($name:ident ref => | $v:ident -> $ret:ty | $access:expr) => {
        pub fn $name(&'a self) -> $ret {
            attribute!(@impl self, $v, $access)
        }
    };
    ($name:ident => | $v:ident -> $ret:ty | $access:expr) => {
        pub fn $name(&self) -> $ret {
            attribute!(@impl self, $v, $access)
        }
    };

    (@impl $self:ident, $v:ident, $access:expr) => {
        match $self {
            Self::V1_4($v) => $access,
            Self::V1_5($v) => $access,
            Self::V1_6($v) => $access,
            Self::V1_7($v) => $access,
        }
    };
}

macro_rules! from {
    ( $($lt:lifetime,)? $src:ident, $name:ty) => {
        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_4::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_4::$src) -> Self {
                Self::V1_4(value)
            }
        }

        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_5::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_5::$src) -> Self {
                Self::V1_5(value)
            }
        }

        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_6::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_6::$src) -> Self {
                Self::V1_6(value)
            }
        }

        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_7::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_7::$src) -> Self {
                Self::V1_7(value)
            }
        }
    };
}

macro_rules! r#type {
    ($name:ident) => {
        #[derive(Copy, Clone, Debug, PartialEq)]
        #[non_exhaustive]
        pub enum $name<'a> {
            V1_4(&'a serde_cyclonedx::cyclonedx::v_1_4::$name),
            V1_5(&'a serde_cyclonedx::cyclonedx::v_1_5::$name),
            V1_6(&'a serde_cyclonedx::cyclonedx::v_1_6::$name),
            V1_7(&'a serde_cyclonedx::cyclonedx::v_1_7::$name),
        }
    };
}

/// Collect `bom-ref`s, recursing into sub-element
pub trait BomRefCollection<'a> {
    fn bom_refs_to(&self, refs: &mut HashMap<&'a str, usize>);

    fn bom_refs(&self) -> HashMap<&'a str, usize> {
        let mut result = HashMap::new();
        self.bom_refs_to(&mut result);
        result
    }
}

macro_rules! bom_refs {
    ($name:ident -> | $v:ident | $access:expr ) => {
        impl<'a> BomRefCollection<'a> for $name<'a> {
            fn bom_refs_to(&self, refs: &mut HashMap<&'a str, usize>) {
                if let Some(r#ref) = self.bom_ref() {
                    *refs.entry(r#ref).or_default() += 1;
                }

                let $v = self;

                for child in ($access).into_iter().flatten() {
                    child.bom_refs_to(refs);
                }
            }
        }
    };
}

impl<'a> Sbom<'a> {
    attribute!(metadata ref => |sbom -> Option<Metadata<'a>> | sbom.metadata.as_ref().map(Metadata::from));

    attribute!(components ref => |sbom -> Option<Vec<Component<'a>>> | sbom
                .components
                .as_ref()
                .map(|c| c.iter().map(Into::into).collect()));

    attribute!(services ref => |sbom -> Option<Vec<Service<'a>>> | sbom
                .services
                .as_ref()
                .map(|c| c.iter().map(Into::into).collect()));

    attribute!(dependencies ref => |sbom -> Option<Vec<Dependency<'a>>> | sbom
                .dependencies
                .as_ref()
                .map(|c| c.iter().map(Into::into).collect()));

    pub fn bom_refs(&self) -> HashMap<&str, usize> {
        let mut refs = HashMap::new();

        if let Some(metadata) = self.metadata() {
            metadata.bom_refs_to(&mut refs);
        }

        for component in self.components().into_iter().flatten() {
            component.bom_refs_to(&mut refs);
        }

        for service in self.services().into_iter().flatten() {
            service.bom_refs_to(&mut refs);
        }

        refs
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_4::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_4::CycloneDx) -> Self {
        Self::V1_4(Cow::Owned(value))
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_5::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_5::CycloneDx) -> Self {
        Self::V1_5(Cow::Owned(value))
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_6::CycloneDx) -> Self {
        Self::V1_6(Cow::Owned(value))
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_7::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_7::CycloneDx) -> Self {
        Self::V1_7(Cow::Owned(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_4::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_4::CycloneDx) -> Self {
        Self::V1_4(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_5::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_5::CycloneDx) -> Self {
        Self::V1_5(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_6::CycloneDx) -> Self {
        Self::V1_6(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_7::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_7::CycloneDx) -> Self {
        Self::V1_7(Cow::Borrowed(value))
    }
}

// metadata

r#type!(Metadata);
from!('a, Metadata,  Metadata<'a>);

impl<'a> Metadata<'a> {
    attribute!(component => |c -> Option<Component<'a>> | c.component.as_ref().map(Into::into));
}

impl<'a> BomRefCollection<'a> for Metadata<'a> {
    fn bom_refs_to(&self, refs: &mut HashMap<&'a str, usize>) {
        if let Some(component) = self.component() {
            component.bom_refs_to(refs);
        }
    }
}

// component

r#type!(Component);
from!('a, Component,  Component<'a>);
bom_refs!(Component -> |c| c.components());

impl<'a> Component<'a> {
    attribute!(bom_ref => |c -> Option<&'a str> | c.bom_ref.as_deref());
    attribute!(components => |c -> Option<Vec<Component<'a>>> | c.components.as_ref().map(|c| c.iter().map(Into::into).collect()));
}

// service

r#type!(Service);
from!('a, Service,  Service<'a>);
bom_refs!(Service -> |c| c.services());

impl<'a> Service<'a> {
    attribute!(bom_ref => |s -> Option<&'a str> | s.bom_ref.as_deref());
    attribute!(services => |s -> Option<Vec<Service<'a>>> | s.services.as_ref().map(|s| s.iter().map(Into::into).collect()));
}

// dependency

r#type!(Dependency);
from!('a, Dependency,  Dependency<'a>);

impl Dependency<'_> {
    pub fn r#ref(&self) -> &str {
        match self {
            Self::V1_4(dep) => &dep.ref_,
            Self::V1_5(dep) => dep.ref_.as_str().unwrap_or_default(),
            Self::V1_6(dep) => &dep.ref_,
            Self::V1_7(dep) => &dep.ref_,
        }
    }

    pub fn dependencies(&self) -> Option<Vec<&str>> {
        match self {
            Self::V1_4(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().map(|s| s.as_str()).collect()),
            Self::V1_5(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().flat_map(|s| s.as_str()).collect()),
            Self::V1_6(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().map(|s| s.as_str()).collect()),
            Self::V1_7(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().map(|s| s.as_str()).collect()),
        }
    }
}
