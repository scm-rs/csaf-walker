use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::vec;

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

#[derive(Clone, Default, Debug)]
pub struct Capped {
    /// The recorded items
    pub items: Vec<CheckError>,
    /// The total number
    ///
    /// This may be more than the items, as this would mean it was capped.
    pub total: usize,
}

impl FromIterator<CheckError> for Capped {
    fn from_iter<T: IntoIterator<Item = CheckError>>(iter: T) -> Self {
        let items = Vec::from_iter(iter);
        let total = items.len();
        Self { items, total }
    }
}

impl IntoIterator for Capped {
    type Item = CheckError;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn err(msg: &str) -> CheckError {
        CheckError {
            id: Arc::from("test"),
            message: Arc::from(msg),
        }
    }

    #[test]
    fn capped_default_is_empty() {
        let capped = Capped::default();
        assert!(capped.items.is_empty());
        assert_eq!(capped.total, 0);
    }

    #[test]
    fn capped_from_iter() {
        let capped: Capped = vec![err("a"), err("b"), err("c")].into_iter().collect();
        assert_eq!(capped.items.len(), 3);
        assert_eq!(capped.total, 3);
        assert_eq!(&*capped.items[0].message, "a");
        assert_eq!(&*capped.items[2].message, "c");
    }

    #[test]
    fn capped_into_iter() {
        let capped: Capped = vec![err("x"), err("y")].into_iter().collect();
        let messages: Vec<_> = capped.into_iter().map(|e| e.message.to_string()).collect();
        assert_eq!(messages, vec!["x", "y"]);
    }

    #[test]
    fn check_error_from_str() {
        let e = CheckError::from("hello");
        assert_eq!(&*e.id, "");
        assert_eq!(&*e.message, "hello");
    }

    #[test]
    fn check_error_from_string() {
        let e = CheckError::from("world".to_string());
        assert_eq!(&*e.id, "");
        assert_eq!(&*e.message, "world");
    }
}
