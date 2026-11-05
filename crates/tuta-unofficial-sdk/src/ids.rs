//! Compound ids: `list/element`, both parts base64url-ish, as Tuta names a
//! mail, a folder, a label or a draft.

use crate::{Error, Result};
use serde::{Serialize, Serializer};
use std::{fmt, str::FromStr};
use tutasdk::{GeneratedId, IdTupleGenerated};

/// A mail's, folder's, label's or draft's compound id, `list/element`.
///
/// Parsing checks the shape only: two non-empty parts of ASCII letters,
/// digits, `-` and `_`. Its string form is exactly what was parsed.
#[derive(Clone, PartialEq, Eq)]
pub struct Id(IdTupleGenerated);

impl Id {
    /// Parse `list/element`; anything else is [`Error::InvalidId`].
    pub fn parse(value: &str) -> Result<Self> {
        tuple(value).map(Id)
    }

    /// The list part.
    pub fn list(&self) -> &str {
        self.0.list_id.as_str()
    }

    /// The element part.
    pub fn element(&self) -> &str {
        self.0.element_id.as_str()
    }

    pub(crate) fn from_tuple(tuple: IdTupleGenerated) -> Self {
        Id(tuple)
    }

    pub(crate) fn tuple(&self) -> &IdTupleGenerated {
        &self.0
    }

    pub(crate) fn into_tuple(self) -> IdTupleGenerated {
        self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.0.list_id, self.0.element_id)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl FromStr for Id {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        Id::parse(value)
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

pub(crate) fn tuple(value: &str) -> Result<IdTupleGenerated> {
    let (list, element) = value.split_once('/').ok_or(Error::InvalidId)?;
    if [list, element].iter().any(|p| {
        p.is_empty()
            || !p
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return Err(Error::InvalidId);
    }
    Ok(IdTupleGenerated::new(
        GeneratedId(list.into()),
        GeneratedId(element.into()),
    ))
}

pub(crate) fn id(value: &IdTupleGenerated) -> String {
    format!("{}/{}", value.list_id, value.element_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_preserve_both_components() {
        assert_eq!(id(&tuple("list_1/mail-2").unwrap()), "list_1/mail-2");
        for value in ["mail", "/mail", "list/", "a/b/c", "a/../b", "a/é"] {
            assert_eq!(tuple(value).err(), Some(Error::InvalidId), "{value}");
        }
    }

    #[test]
    fn the_public_id_round_trips_its_text() {
        let parsed: Id = "list_1/mail-2".parse().unwrap();
        assert_eq!(parsed.to_string(), "list_1/mail-2");
        assert_eq!((parsed.list(), parsed.element()), ("list_1", "mail-2"));
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::json!("list_1/mail-2")
        );
        assert_eq!(Id::parse("nope").err(), Some(Error::InvalidId));
    }
}
