use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod arc_str_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    pub fn serialize<S: Serializer>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arc<str>, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Arc::from(s.as_str()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckError {
    #[serde(with = "arc_str_serde")]
    pub id: Arc<str>,
    #[serde(with = "arc_str_serde")]
    pub message: Arc<str>,
}

impl From<&str> for CheckError {
    fn from(s: &str) -> Self {
        CheckError {
            id: Arc::from(""),
            message: Arc::from(s),
        }
    }
}

impl From<String> for CheckError {
    fn from(s: String) -> Self {
        CheckError {
            id: Arc::from(""),
            message: Arc::from(s.as_str()),
        }
    }
}
