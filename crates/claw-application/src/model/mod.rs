//! Value types shared by application ports and their adapters.

pub mod approval;
pub mod goal;
pub mod ids;
pub mod message;
pub mod session;
pub mod time;

/// Serde support for [`claw_domain::SessionId`], which is defined without serde derives.
pub(crate) mod session_id_serde {
    use claw_domain::SessionId;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(value: &SessionId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<SessionId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        SessionId::new(raw).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use claw_domain::SessionId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Holder {
        #[serde(with = "super::session_id_serde")]
        session_id: SessionId,
    }

    #[test]
    fn session_ids_round_trip_through_the_serde_adapter() {
        let holder = Holder {
            session_id: SessionId::new("session-77").expect("valid session id"),
        };
        let encoded = serde_json::to_string(&holder).expect("holder serialises");

        assert_eq!(encoded, "{\"session_id\":\"session-77\"}");
        assert_eq!(
            serde_json::from_str::<Holder>(&encoded).expect("holder deserialises"),
            holder
        );
    }

    #[test]
    fn the_serde_adapter_enforces_the_domain_invariant() {
        let error = serde_json::from_str::<Holder>("{\"session_id\":\"  \"}")
            .expect_err("blank session ids must be rejected");

        assert_eq!(
            error.to_string(),
            "invalid session id: must not be empty at line 1 column 19"
        );
    }
}
