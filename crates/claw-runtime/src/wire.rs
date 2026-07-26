//! Serde adapters for the application layer's value types.
//!
//! `claw-application` is deliberately free of any serialization framework, so the crates that put
//! its values on a wire own the mapping. These adapters are that mapping for `claw-runtime`, and
//! they reproduce byte for byte the encoding the runtime's public types had when the derives lived
//! in the application layer.
//!
//! Every adapter goes through the constructor that enforces the value's invariant, so a decoded
//! identifier is as trustworthy as one built in process.

/// Serde support for [`claw_application::model::goal::GoalStatus`].
pub(crate) mod goal_status {
    use claw_application::model::goal::GoalStatus;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(value: &GoalStatus, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.label())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<GoalStatus, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        GoalStatus::ALL
            .into_iter()
            .find(|status| status.label() == raw)
            .ok_or_else(|| D::Error::custom(format!("unknown goal status: {raw}")))
    }
}

/// Serde support for [`claw_application::model::ids::ToolCallId`].
pub(crate) mod tool_call_id {
    use claw_application::model::ids::ToolCallId;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(value: &ToolCallId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<ToolCallId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        ToolCallId::new(raw).map_err(|error| D::Error::custom(error.to_string()))
    }
}

/// Serde support for [`claw_application::model::message::ToolCall`].
pub(crate) mod tool_call {
    use claw_application::model::ids::ToolCallId;
    use claw_application::model::message::ToolCall;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize, Serialize)]
    struct Wire {
        call_id: String,
        name: String,
        arguments: String,
    }

    pub(crate) fn serialize<S>(value: &ToolCall, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Wire {
            call_id: value.call_id.as_str().to_owned(),
            name: value.name.clone(),
            arguments: value.arguments.clone(),
        }
        .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<ToolCall, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Wire::deserialize(deserializer)?;
        Ok(ToolCall {
            call_id: ToolCallId::new(wire.call_id)
                .map_err(|error| D::Error::custom(error.to_string()))?,
            name: wire.name,
            arguments: wire.arguments,
        })
    }
}

/// Serde support for [`claw_application::model::message::AssistantMessage`].
pub(crate) mod assistant_message {
    use claw_application::model::ids::ToolCallId;
    use claw_application::model::message::{AssistantMessage, ToolCall};
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize, Serialize)]
    struct WireCall {
        call_id: String,
        name: String,
        arguments: String,
    }

    #[derive(Deserialize, Serialize)]
    struct Wire {
        text: String,
        reasoning: String,
        tool_calls: Vec<WireCall>,
    }

    pub(crate) fn serialize<S>(value: &AssistantMessage, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Wire {
            text: value.text.clone(),
            reasoning: value.reasoning.clone(),
            tool_calls: value
                .tool_calls
                .iter()
                .map(|call| WireCall {
                    call_id: call.call_id.as_str().to_owned(),
                    name: call.name.clone(),
                    arguments: call.arguments.clone(),
                })
                .collect(),
        }
        .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<AssistantMessage, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Wire::deserialize(deserializer)?;
        let mut tool_calls = Vec::with_capacity(wire.tool_calls.len());
        for call in wire.tool_calls {
            tool_calls.push(ToolCall {
                call_id: ToolCallId::new(call.call_id)
                    .map_err(|error| D::Error::custom(error.to_string()))?,
                name: call.name,
                arguments: call.arguments,
            });
        }
        Ok(AssistantMessage {
            text: wire.text,
            reasoning: wire.reasoning,
            tool_calls,
        })
    }
}

#[cfg(test)]
mod tests {
    use claw_application::model::goal::GoalStatus;
    use claw_application::model::ids::ToolCallId;
    use claw_application::model::message::{AssistantMessage, ToolCall};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Holder {
        #[serde(with = "super::goal_status")]
        status: GoalStatus,
        #[serde(with = "super::tool_call_id")]
        call_id: ToolCallId,
        #[serde(with = "super::tool_call")]
        call: ToolCall,
        #[serde(with = "super::assistant_message")]
        message: AssistantMessage,
    }

    fn holder() -> Holder {
        Holder {
            status: GoalStatus::Superseded,
            call_id: ToolCallId::new("call-1").expect("the test call id is valid"),
            call: ToolCall {
                call_id: ToolCallId::new("call-2").expect("the test call id is valid"),
                name: "read_file".to_owned(),
                arguments: "{\"path\":\"a.txt\"}".to_owned(),
            },
            message: AssistantMessage {
                text: "done".to_owned(),
                reasoning: "because".to_owned(),
                tool_calls: vec![ToolCall {
                    call_id: ToolCallId::new("call-3").expect("the test call id is valid"),
                    name: "write_file".to_owned(),
                    arguments: "{}".to_owned(),
                }],
            },
        }
    }

    #[test]
    fn the_adapters_encode_the_same_shape_the_derives_did() {
        let encoded = serde_json::to_string(&holder()).expect("the holder serialises");

        assert_eq!(
            encoded,
            "{\"status\":\"superseded\",\"call_id\":\"call-1\",\
\"call\":{\"call_id\":\"call-2\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"},\
\"message\":{\"text\":\"done\",\"reasoning\":\"because\",\
\"tool_calls\":[{\"call_id\":\"call-3\",\"name\":\"write_file\",\"arguments\":\"{}\"}]}}"
        );
        assert_eq!(
            serde_json::from_str::<Holder>(&encoded).expect("the holder deserialises"),
            holder()
        );
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct StatusHolder {
        #[serde(with = "super::goal_status")]
        status: GoalStatus,
    }

    #[test]
    fn every_goal_status_survives_a_round_trip_through_its_label() {
        for status in GoalStatus::ALL {
            let encoded =
                serde_json::to_string(&StatusHolder { status }).expect("the holder serialises");

            assert_eq!(encoded, format!("{{\"status\":\"{}\"}}", status.label()));
            assert_eq!(
                serde_json::from_str::<StatusHolder>(&encoded)
                    .expect("the holder deserialises")
                    .status,
                status
            );
        }
    }

    #[test]
    fn an_unknown_goal_status_label_is_rejected() {
        let error = serde_json::from_str::<StatusHolder>("{\"status\":\"retired\"}")
            .expect_err("an unknown label must not decode");

        assert_eq!(
            error.to_string(),
            "unknown goal status: retired at line 1 column 20"
        );
    }

    #[test]
    fn a_blank_tool_call_id_is_rejected_by_the_domain_invariant() {
        let error = serde_json::from_str::<Holder>(
            "{\"status\":\"active\",\"call_id\":\"   \",\"call\":{\"call_id\":\"c\",\
\"name\":\"n\",\"arguments\":\"{}\"},\
\"message\":{\"text\":\"\",\"reasoning\":\"\",\"tool_calls\":[]}}",
        )
        .expect_err("a blank identifier must not decode");

        assert_eq!(
            error.to_string(),
            "invalid tool call id: must not be empty at line 1 column 34"
        );
    }
}
