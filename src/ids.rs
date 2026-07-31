//! Strongly-typed identifiers used by the Authorisationkit API.
//!
//! Each id wraps a [`uuid::Uuid`] in a distinct newtype so the compiler
//! catches mistakes like passing a session id where the API expects a
//! consumer id. The wire format is unchanged — newtypes are
//! `#[serde(transparent)]`, so a `ConsumerId` serializes and
//! deserializes as the same UUID string a raw `Uuid` would.
//!
//! # Construction
//!
//! - From a [`Uuid`]: `let id: ConsumerId = my_uuid.into();` or
//!   [`ConsumerId::new(my_uuid)`](ConsumerId::new).
//! - From a string: `let id: ConsumerId = "00000000-0000-0000-0000-000000000000".parse()?;`
//!
//! All client methods accept `impl Into<ConsumerId>` (or `impl
//! Into<SessionId>`), so you can keep passing raw `Uuid` values where
//! that's more convenient — the conversion is free.

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
    /// Stable identifier for a consumer (end user) record.
    ///
    /// `ConsumerId` is a thin newtype around [`Uuid`] that prevents
    /// accidental mix-ups with other id types like [`SessionId`].
    ConsumerId
}

id_newtype! {
    /// Identifier for an active consumer session.
    ///
    /// `SessionId` is a thin newtype around [`Uuid`] that prevents
    /// accidental mix-ups with other id types like [`ConsumerId`].
    SessionId
}

id_newtype! {
    /// Identifier for an OAuth client registered with Authorisationkit.
    ///
    /// `OAuthClientId` is a thin newtype around [`Uuid`]. One is minted per
    /// dynamic client registration, so an MCP client that registers twice
    /// appears under two ids.
    OAuthClientId
}

id_newtype! {
    /// Identifier for an Authorisationkit organisation.
    ///
    /// `OrgId` is a thin newtype around [`Uuid`]. It appears in JWT
    /// claims (`org_id`) and in the OAuth Authorization Server
    /// well-known URL path. Server-issued `org_id` values are always
    /// UUIDs.
    OrgId
}

#[cfg(test)]
mod tests {
    use super::*;

    const NIL: Uuid = Uuid::nil();
    const NIL_STR: &str = "00000000-0000-0000-0000-000000000000";

    #[test]
    fn from_uuid_and_back() {
        let id = ConsumerId::from(NIL);
        assert_eq!(id.into_uuid(), NIL);
        assert_eq!(*id.as_uuid(), NIL);
    }

    #[test]
    fn new_constructor_is_const() {
        const ID: ConsumerId = ConsumerId::new(Uuid::nil());
        assert_eq!(*ID.as_uuid(), NIL);
    }

    #[test]
    fn parse_from_string() {
        let id: ConsumerId = NIL_STR.parse().expect("parse");
        assert_eq!(*id.as_uuid(), NIL);
    }

    #[test]
    fn parse_from_string_rejects_garbage() {
        let err = "not-a-uuid".parse::<ConsumerId>().unwrap_err();
        // uuid::Error doesn't expose a stable kind; just check it's an error.
        assert!(err.to_string().contains("uuid") || !err.to_string().is_empty());
    }

    #[test]
    fn display_matches_uuid_format() {
        let id = ConsumerId::new(NIL);
        assert_eq!(id.to_string(), NIL_STR);
    }

    #[test]
    fn debug_includes_type_name() {
        let id = ConsumerId::new(NIL);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("ConsumerId("));
        assert!(dbg.contains(NIL_STR));
    }

    #[test]
    fn serde_is_transparent() {
        let id = ConsumerId::new(NIL);
        let json = serde_json::to_string(&id).expect("serialize");
        // Same shape as serializing the inner Uuid directly.
        assert_eq!(json, format!("\"{NIL_STR}\""));

        let parsed: ConsumerId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn consumer_and_session_ids_are_distinct_types() {
        // This test exists primarily to document the type-safety property
        // — if anyone ever changes the macro to share a type, this would
        // catch it. The actual compile-time check is that the following
        // line would NOT compile if uncommented:
        //
        //     let _: ConsumerId = SessionId::new(Uuid::nil());
        //
        // Compile-time tests are awkward in Rust without trybuild, so we
        // assert the type names instead.
        let c = ConsumerId::new(NIL);
        let s = SessionId::new(NIL);
        assert!(format!("{c:?}").starts_with("ConsumerId"));
        assert!(format!("{s:?}").starts_with("SessionId"));
    }
}
