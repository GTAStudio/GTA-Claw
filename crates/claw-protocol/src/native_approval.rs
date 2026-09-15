//! Native GTA Claw approval display contract, independent of upstream fixtures.

use serde_json::Value;

fn bounded_text(value: &Value, maximum_bytes: usize) -> Option<&str> {
    value.as_str().filter(|text| {
        !text.is_empty()
            && text.len() <= maximum_bytes
            && !text.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
            })
    })
}

/// Builds the visible identity and resource header from bounded native metadata.
/// Returns `None` when the authenticated context is incomplete or ambiguous.
#[must_use]
pub fn bound_approval_context_header(preview: &Value) -> Option<String> {
    let caller = preview.get("caller")?.as_object()?;
    let source = bounded_text(caller.get("source")?, 16)?;
    if !matches!(source, "Gateway" | "Http" | "Mcp" | "Channel") {
        return None;
    }
    let subject = bounded_text(caller.get("subject")?, 256)?;
    let account = match caller.get("account")? {
        Value::Null => "none",
        account => bounded_text(account, 256)?,
    };
    let generation = caller.get("permissionGeneration")?.as_u64()?;
    let access = if caller.get("owner")?.as_bool()? {
        "owner"
    } else {
        "execute"
    };
    let publication = bounded_text(preview.get("toolPublication")?, 256)?;
    let revision = preview
        .get("toolRevision")?
        .as_u64()
        .filter(|revision| *revision > 0)?;
    let resource = bounded_text(preview.get("resourceScope")?, 2048)?;
    Some(format!(
        "Caller: {source} / {subject}\nAccount: {account}\nAccess: {access}\nPermission generation: {generation}\nTool publication: {publication} (revision {revision})\nResource: {resource}\n"
    ))
}

/// Validates a complete native approval display without authenticating its transport.
/// Callers must separately verify the token fingerprint and connection epoch.
#[must_use]
pub fn checked_bound_approval_prompt(preview: &Value, maximum_bytes: usize) -> Option<&str> {
    if preview.get("previewComplete")? != &Value::Bool(true) {
        return None;
    }
    bounded_text(preview.get("id")?, 128)?;
    bounded_text(preview.get("sessionId")?, 256)?;
    let tool = bounded_text(preview.get("tool")?, 256)?;
    for field in ["bindingToken", "previewFingerprint"] {
        let token = bounded_text(preview.get(field)?, 64)?;
        if token.len() != 64
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
    }
    let prompt = preview.get("prompt")?.as_str()?;
    if prompt.len() > maximum_bytes.min(32 * 1024) {
        return None;
    }
    let header = bound_approval_context_header(preview)?;
    let body = prompt
        .strip_prefix(&header)?
        .strip_prefix(tool)?
        .strip_prefix('\n')?;
    serde_json::from_str::<Value>(body).ok()?;
    Some(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn preview() -> Value {
        let mut preview = json!({
            "id": "approval-1", "sessionId": "session-1", "tool": "fs_write", "previewComplete": true,
            "bindingToken": "a".repeat(64), "previewFingerprint": "b".repeat(64),
            "toolPublication": "workspace-publication", "toolRevision": 1, "resourceScope": "workspace: result.txt",
            "caller": {"source": "Http", "subject": "verified-actor", "account": null, "permissionGeneration": 2, "owner": true}
        });
        preview["prompt"] = json!(format!(
            "{}fs_write\n{{\"path\":\"result.txt\",\"content\":\"native\"}}",
            bound_approval_context_header(&preview).expect("complete context")
        ));
        preview
    }

    #[test]
    fn native_approval_requires_all_displayed_context_and_a_complete_json_body() {
        let preview = preview();
        assert!(checked_bound_approval_prompt(&preview, 32 * 1024).is_some());
        for field in [
            "id",
            "sessionId",
            "tool",
            "bindingToken",
            "previewFingerprint",
            "toolPublication",
            "toolRevision",
            "resourceScope",
            "caller",
            "previewComplete",
            "prompt",
        ] {
            let mut missing = preview.clone();
            missing.as_object_mut().expect("preview").remove(field);
            assert!(
                checked_bound_approval_prompt(&missing, 32 * 1024).is_none(),
                "missing {field}"
            );
        }
        let mut incomplete = preview;
        incomplete["prompt"] = json!(
            incomplete["prompt"]
                .as_str()
                .expect("prompt")
                .trim_end_matches('}')
        );
        assert!(checked_bound_approval_prompt(&incomplete, 32 * 1024).is_none());
    }

    #[test]
    fn native_approval_rejects_changed_hidden_context_and_ambiguous_identity() {
        let preview = preview();
        for (field, value) in [
            ("source", json!("unknown")),
            ("subject", json!("different-actor")),
            ("subject", json!("hidden\u{202e}actor")),
            ("account", json!("other-account")),
            ("owner", json!(false)),
            ("permissionGeneration", json!(3)),
        ] {
            let mut changed = preview.clone();
            changed["caller"][field] = value;
            assert!(
                checked_bound_approval_prompt(&changed, 32 * 1024).is_none(),
                "changed {field}"
            );
        }
        for (field, value) in [
            ("toolRevision", json!(0)),
            ("toolPublication", json!("other-publication")),
            ("resourceScope", json!("workspace: another.txt")),
        ] {
            let mut changed = preview.clone();
            changed[field] = value;
            assert!(
                checked_bound_approval_prompt(&changed, 32 * 1024).is_none(),
                "changed {field}"
            );
        }
        assert!(checked_bound_approval_prompt(&preview, 24).is_none());
    }
}
