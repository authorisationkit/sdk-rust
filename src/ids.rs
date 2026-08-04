//! Strongly-typed identifiers used by the Authorisationkit API.
//!
//! The ids the HTTP API speaks are generated from the OpenAPI document and
//! live in [`crate::types`]. What remains here is [`OrgId`], which the API
//! never carries in a request or response — it arrives inside a *token*, as
//! the `org_id` claim on [`crate::Claims`], so nothing in the document
//! describes it.
//!
//! The wire format is unchanged: the newtype is `#[serde(transparent)]`, so an
//! `OrgId` serializes and deserializes as the same UUID string a raw `Uuid`
//! would.
//!
//! # Construction
//!
//! - From a [`Uuid`]: `let id: OrgId = my_uuid.into();` or
//!   [`OrgId::new(my_uuid)`](OrgId::new).
//! - From a string: `let id: OrgId = "00000000-0000-0000-0000-000000000000".parse()?;`

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_newtype {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[doc = concat!("Construct a [`", stringify!($name), "`] from a [`Uuid`].")]
            #[must_use]
            pub const fn new(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Borrow the underlying [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consume `self` and return the underlying [`Uuid`].
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self)
            }
        }
    };
}

id_newtype! {
    /// Identifier for an Authorisationkit organisation.
    ///
    /// `OrgId` is a thin newtype around [`Uuid`]. It appears in JWT claims
    /// (`org_id`) and in the OAuth Authorization Server well-known URL path.
    /// Server-issued `org_id` values are always UUIDs.
    OrgId
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIL: Uuid = Uuid::nil();
    const NIL_STR: &str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn from_uuid_and_back() {
        let id = OrgId::from(NIL);
        assert_eq!(id.into_uuid(), NIL);
        assert_eq!(*id.as_uuid(), NIL);
    }

    #[test]
    fn new_constructor_is_const() {
        const ID: OrgId = OrgId::new(Uuid::nil());
        assert_eq!(*ID.as_uuid(), NIL);
    }

    #[test]
    fn parse_from_string() {
        let id: OrgId = NIL_STR.parse().expect("parse");
        assert_eq!(*id.as_uuid(), NIL);
    }

    #[test]
    fn parse_from_string_rejects_garbage() {
        let err = "not-a-uuid".parse::<OrgId>().unwrap_err();
        // uuid::Error doesn't expose a stable kind; just check it's an error.
        assert!(err.to_string().contains("uuid") || !err.to_string().is_empty());
    }

    #[test]
    fn display_matches_uuid_format() {
        let id = OrgId::new(NIL);
        assert_eq!(id.to_string(), NIL_STR);
    }

    #[test]
    fn debug_includes_type_name() {
        let id = OrgId::new(NIL);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("OrgId("));
        assert!(dbg.contains(NIL_STR));
    }

    #[test]
    fn serde_is_transparent() {
        let id = OrgId::new(NIL);
        let json = serde_json::to_string(&id).expect("serialize");
        // Same shape as serializing the inner Uuid directly.
        assert_eq!(json, format!("\"{NIL_STR}\""));

        let parsed: OrgId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }
}
