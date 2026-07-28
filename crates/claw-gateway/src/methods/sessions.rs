//! Session CRUD and session event subscription handlers.

use std::sync::Arc;

use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

use crate::dispatch::{MethodContext, MethodFuture, MethodHandler, MethodRegistry};
use crate::error::DispatchError;
use crate::events::{EventDraft, TopicGroup};
use crate::store::{SessionDraft, SessionPatch, SessionRecord};

use super::{MAX_TEXT_BYTES, bounded_text, identity, params_of};

pub(super) fn install(registry: &mut MethodRegistry) -> Result<(), DispatchError> {
    registry.register("sessions.create", Arc::new(Create))?;
    registry.register("sessions.list", Arc::new(List))?;
    registry.register("sessions.get", Arc::new(Get))?;
    registry.register("sessions.describe", Arc::new(Describe))?;
    registry.register("sessions.patch", Arc::new(Patch))?;
    registry.register("sessions.delete", Arc::new(Delete))?;
    registry.register(
        "sessions.subscribe",
        Arc::new(Subscribe {
            group: TopicGroup::SessionLifecycle,
        }),
    )?;
    registry.register(
        "sessions.unsubscribe",
        Arc::new(Unsubscribe {
            group: TopicGroup::SessionLifecycle,
        }),
    )?;
    registry.register(
        "sessions.messages.subscribe",
        Arc::new(Subscribe {
            group: TopicGroup::SessionMessages,
        }),
    )?;
    registry.register(
        "sessions.messages.unsubscribe",
        Arc::new(Unsubscribe {
            group: TopicGroup::SessionMessages,
        }),
    )?;
    Ok(())
}

/// Renders one stored session as its response shape.
fn render(record: &SessionRecord) -> Value {
    json!({
        "id": record.id,
        "agentId": record.agent_id,
        "title": record.title,
        "createdAtMs": record.created_at_ms,
        "updatedAtMs": record.updated_at_ms,
        "revision": record.revision,
        "archived": record.archived,
    })
}

/// Distinguishes an absent field from an explicit JSON `null`.
#[expect(
    clippy::option_option,
    reason = "the outer layer is presence and the inner layer is the value: `None` leaves the \
              title untouched while `Some(None)` clears it, which is the wire contract \
              `sessions.patch` and `SessionPatch` already encode and a flattened option \
              cannot express"
)]
fn explicit_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

fn publish_changed(
    context: &MethodContext<'_>,
    change: &str,
    record: &SessionRecord,
) -> Result<(), DispatchError> {
    let draft = EventDraft::broadcast(
        "sessions.changed",
        &json!({ "change": change, "session": render(record) }),
    )
    .map_err(|error| DispatchError::InvalidParams {
        method: context.method.to_owned(),
        detail: error.to_string(),
    })?
    .with_session(record.id.clone());
    context.events.publish(draft);
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateParams {
    id: String,
    agent_id: String,
    #[serde(default)]
    title: Option<String>,
}

/// `sessions.create` — creates one session; the identity must be unused.
#[derive(Debug)]
struct Create;

impl MethodHandler for Create {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: CreateParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            identity(context.method, "agentId", &request.agent_id)?;
            if let Some(title) = request.title.as_deref() {
                bounded_text(context.method, "title", title, MAX_TEXT_BYTES)?;
            }
            let record = context
                .store
                .create_session(SessionDraft {
                    id: request.id,
                    agent_id: request.agent_id,
                    title: request.title,
                    created_at_ms: context.clock.unix_millis(),
                })
                .await?;
            publish_changed(&context, "created", &record)?;
            Ok(render(&record))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// `sessions.list` — every stored session ordered by identity.
#[derive(Debug)]
struct List;

impl MethodHandler for List {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let sessions = context.store.list_sessions().await?;
            Ok(json!({
                "sessions": sessions.iter().map(render).collect::<Vec<_>>(),
                "count": sessions.len(),
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct IdParams {
    id: String,
}

/// `sessions.get` — one session or an explicit null.
#[derive(Debug)]
struct Get;

impl MethodHandler for Get {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: IdParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            let record = context.store.get_session(&request.id).await?;
            Ok(json!({ "session": record.as_ref().map(render) }))
        })
    }
}

/// `sessions.describe` — one session, or a typed not-found failure.
#[derive(Debug)]
struct Describe;

impl MethodHandler for Describe {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: IdParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            let record = context
                .store
                .get_session(&request.id)
                .await?
                .ok_or_else(|| DispatchError::NotFound {
                    kind: "session",
                    id: request.id.clone(),
                })?;
            let subscribed_sessions = {
                let filter = context
                    .filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                filter.sessions().iter().cloned().collect::<Vec<_>>()
            };
            Ok(json!({
                "session": render(&record),
                "subscribedSessions": subscribed_sessions,
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PatchParams {
    id: String,
    #[serde(default, deserialize_with = "explicit_option")]
    #[expect(
        clippy::option_option,
        reason = "absent leaves the title alone, an explicit JSON null clears it; collapsing \
                  the two would silently make `\"title\": null` a no-op"
    )]
    title: Option<Option<String>>,
    #[serde(default)]
    archived: Option<bool>,
}

/// `sessions.patch` — partial update; an explicit `null` title clears it.
#[derive(Debug)]
struct Patch;

impl MethodHandler for Patch {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: PatchParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            if request.title.is_none() && request.archived.is_none() {
                return Err(DispatchError::InvalidParams {
                    method: context.method.to_owned(),
                    detail: "at least one of `title` or `archived` must be present".to_owned(),
                });
            }
            if let Some(Some(title)) = request.title.as_ref() {
                bounded_text(context.method, "title", title, MAX_TEXT_BYTES)?;
            }
            let record = context
                .store
                .patch_session(
                    &request.id,
                    SessionPatch {
                        title: request.title,
                        archived: request.archived,
                        updated_at_ms: context.clock.unix_millis(),
                    },
                )
                .await?
                .ok_or_else(|| DispatchError::NotFound {
                    kind: "session",
                    id: request.id.clone(),
                })?;
            publish_changed(&context, "patched", &record)?;
            Ok(render(&record))
        })
    }
}

/// `sessions.delete` — removes one session.
#[derive(Debug)]
struct Delete;

impl MethodHandler for Delete {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: IdParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            let record = context
                .store
                .get_session(&request.id)
                .await?
                .ok_or_else(|| DispatchError::NotFound {
                    kind: "session",
                    id: request.id.clone(),
                })?;
            let deleted = context.store.delete_session(&request.id).await?;
            if !deleted {
                return Err(DispatchError::NotFound {
                    kind: "session",
                    id: request.id.clone(),
                });
            }
            publish_changed(&context, "deleted", &record)?;
            Ok(json!({ "id": request.id, "deleted": true }))
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SubscriptionParams {
    #[serde(default)]
    sessions: Vec<String>,
}

const fn group_identity(group: TopicGroup) -> &'static str {
    match group {
        TopicGroup::SessionLifecycle => "session-lifecycle",
        TopicGroup::SessionMessages => "session-messages",
    }
}

/// `sessions.subscribe` / `sessions.messages.subscribe`.
#[derive(Debug)]
struct Subscribe {
    group: TopicGroup,
}

impl MethodHandler for Subscribe {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: SubscriptionParams = params_of(context.method, params)?;
            for session in &request.sessions {
                identity(context.method, "sessions[]", session)?;
            }
            let sessions = {
                let mut filter = context
                    .filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                filter.subscribe(self.group, request.sessions);
                filter.sessions().iter().cloned().collect::<Vec<_>>()
            };
            Ok(json!({
                "group": group_identity(self.group),
                "subscribed": true,
                "sessions": sessions,
            }))
        })
    }
}

/// `sessions.unsubscribe` / `sessions.messages.unsubscribe`.
///
/// With no `sessions` the whole group is unsubscribed; with `sessions` only
/// those identities leave the allowlist.
#[derive(Debug)]
struct Unsubscribe {
    group: TopicGroup,
}

impl MethodHandler for Unsubscribe {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: SubscriptionParams = params_of(context.method, params)?;
            for session in &request.sessions {
                identity(context.method, "sessions[]", session)?;
            }
            let group_dropped = request.sessions.is_empty();
            let sessions = {
                let mut filter = context
                    .filter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                filter.unsubscribe(self.group, &request.sessions);
                filter.sessions().iter().cloned().collect::<Vec<_>>()
            };
            Ok(json!({
                "group": group_identity(self.group),
                "subscribed": !group_dropped,
                "sessions": sessions,
            }))
        })
    }
}
