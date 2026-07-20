use claw_domain::SessionId;

use crate::StateError;

const MAX_ID_BYTES: usize = 128;
const MAX_PAGE_SIZE: u32 = 100;

macro_rules! text_id {
    ($name:ident, $field:literal) => {
        #[doc = concat!("A validated ", $field, ".")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated ", $field, ".")]
            pub fn new(value: impl Into<String>) -> Result<Self, StateError> {
                let value = value.into();
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(StateError::InvalidValue {
                        field: $field,
                        reason: "must not be empty",
                    });
                }
                if trimmed.len() > MAX_ID_BYTES {
                    return Err(StateError::InvalidValue {
                        field: $field,
                        reason: "is too long",
                    });
                }
                if trimmed.chars().any(char::is_control) {
                    return Err(StateError::InvalidValue {
                        field: $field,
                        reason: "must not contain control characters",
                    });
                }
                Ok(Self(trimmed.to_owned()))
            }

            #[doc = concat!("Returns the ", $field, " as text.")]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

text_id!(DeviceId, "device id");
text_id!(AuthenticationId, "authentication id");
text_id!(TaskId, "task id");

/// A non-negative Unix timestamp in milliseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimestampMs(i64);

impl TimestampMs {
    /// Creates a timestamp from non-negative Unix milliseconds.
    pub fn new(value: i64) -> Result<Self, StateError> {
        if value < 0 {
            return Err(StateError::InvalidValue {
                field: "timestamp",
                reason: "must not be negative",
            });
        }
        Ok(Self(value))
    }

    /// Returns Unix milliseconds.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Cursor for deterministic `(created_at, id)` ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor {
    created_at: TimestampMs,
    id: String,
}

impl PageCursor {
    /// Creates a cursor returned by a previous page.
    pub fn new(created_at: TimestampMs, id: impl Into<String>) -> Result<Self, StateError> {
        let id = id.into();
        if id.is_empty() {
            return Err(StateError::InvalidValue {
                field: "page cursor id",
                reason: "must not be empty",
            });
        }
        Ok(Self { created_at, id })
    }

    /// Returns the cursor timestamp.
    #[must_use]
    pub const fn created_at(&self) -> TimestampMs {
        self.created_at
    }

    /// Returns the cursor identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// A bounded cursor-pagination request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    limit: u32,
    after: Option<PageCursor>,
}

impl PageRequest {
    /// Creates a request with a limit between 1 and 100.
    pub fn new(limit: u32, after: Option<PageCursor>) -> Result<Self, StateError> {
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(StateError::InvalidValue {
                field: "page limit",
                reason: "must be between 1 and 100",
            });
        }
        Ok(Self { limit, after })
    }

    pub(crate) fn query_limit(&self) -> i64 {
        i64::from(self.limit) + 1
    }

    pub(crate) const fn limit(&self) -> u32 {
        self.limit
    }

    pub(crate) fn after_parts(&self) -> (i64, &str) {
        self.after
            .as_ref()
            .map_or((-1, ""), |cursor| (cursor.created_at.get(), cursor.id()))
    }
}

/// A stable page and continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    /// Records in stable ascending order.
    pub items: Vec<T>,
    /// Cursor for the next page, if more records exist.
    pub next: Option<PageCursor>,
}

pub(crate) fn finish_page<T>(
    mut items: Vec<T>,
    limit: u32,
    cursor: impl Fn(&T) -> PageCursor,
) -> Page<T> {
    let has_more = items.len() > limit as usize;
    if has_more {
        items.pop();
    }
    let next = has_more && !items.is_empty();
    Page {
        next: next.then(|| cursor(items.last().expect("page is known to be non-empty"))),
        items,
    }
}

/// Durable session lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    /// Session accepts work.
    Active,
    /// Session is retained but closed to new work.
    Archived,
}

impl SessionStatus {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Archived => "archived",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self, StateError> {
        match value {
            "active" => Ok(Self::Active),
            "archived" => Ok(Self::Archived),
            _ => Err(invalid_stored("session status")),
        }
    }
}

/// A durable conversation session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Domain session identifier.
    pub id: SessionId,
    /// Current lifecycle state.
    pub status: SessionStatus,
    /// Creation time.
    pub created_at: TimestampMs,
    /// Last durable change.
    pub updated_at: TimestampMs,
    /// Optimistic concurrency version.
    pub version: i64,
}

impl SessionRecord {
    /// Creates a new active session at version one.
    #[must_use]
    pub const fn new(id: SessionId, created_at: TimestampMs) -> Self {
        Self {
            id,
            status: SessionStatus::Active,
            created_at,
            updated_at: created_at,
            version: 1,
        }
    }
}

/// A durable client device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    /// Device identifier.
    pub id: DeviceId,
    /// Human-readable device name.
    pub display_name: String,
    /// Creation time.
    pub created_at: TimestampMs,
    /// Last durable change.
    pub updated_at: TimestampMs,
    /// Optimistic concurrency version.
    pub version: i64,
}

impl DeviceRecord {
    /// Creates a new device at version one.
    pub fn new(
        id: DeviceId,
        display_name: impl Into<String>,
        created_at: TimestampMs,
    ) -> Result<Self, StateError> {
        let display_name = validate_text("device display name", display_name.into())?;
        Ok(Self {
            id,
            display_name,
            created_at,
            updated_at: created_at,
            version: 1,
        })
    }
}

/// Durable authentication lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationStatus {
    /// Authorization has not completed.
    Pending,
    /// The provider confirmed an account subject.
    Authorized,
    /// Credentials are no longer valid.
    Revoked,
}

impl AuthenticationStatus {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Revoked => "revoked",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self, StateError> {
        match value {
            "pending" => Ok(Self::Pending),
            "authorized" => Ok(Self::Authorized),
            "revoked" => Ok(Self::Revoked),
            _ => Err(invalid_stored("authentication status")),
        }
    }
}

/// A provider authentication associated with a durable device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRecord {
    /// Authentication identifier.
    pub id: AuthenticationId,
    /// Owning device.
    pub device_id: DeviceId,
    /// Stable provider key.
    pub provider: String,
    /// Provider account subject, present only when authorized.
    pub subject: Option<String>,
    /// Current lifecycle state.
    pub status: AuthenticationStatus,
    /// Creation time.
    pub created_at: TimestampMs,
    /// Last durable change.
    pub updated_at: TimestampMs,
    /// Optimistic concurrency version.
    pub version: i64,
}

impl AuthenticationRecord {
    /// Creates a pending authentication at version one.
    pub fn pending(
        id: AuthenticationId,
        device_id: DeviceId,
        provider: impl Into<String>,
        created_at: TimestampMs,
    ) -> Result<Self, StateError> {
        Ok(Self {
            id,
            device_id,
            provider: validate_text("authentication provider", provider.into())?,
            subject: None,
            status: AuthenticationStatus::Pending,
            created_at,
            updated_at: created_at,
            version: 1,
        })
    }
}

/// Durable task lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskStatus {
    /// Task awaits execution.
    Pending,
    /// Task is executing.
    Running,
    /// Task completed successfully.
    Succeeded,
    /// Task completed unsuccessfully.
    Failed,
    /// Task was cancelled.
    Cancelled,
}

impl TaskStatus {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn from_db(value: &str) -> Result<Self, StateError> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invalid_stored("task status")),
        }
    }
}

/// A durable unit of work associated with a session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecord {
    /// Task identifier.
    pub id: TaskId,
    /// Owning session.
    pub session_id: SessionId,
    /// Application-defined task kind.
    pub kind: String,
    /// Opaque application payload.
    pub payload: String,
    /// Current lifecycle state.
    pub status: TaskStatus,
    /// Creation time.
    pub created_at: TimestampMs,
    /// Last durable change.
    pub updated_at: TimestampMs,
    /// Optimistic concurrency version.
    pub version: i64,
}

impl TaskRecord {
    /// Creates a pending task at version one.
    pub fn new(
        id: TaskId,
        session_id: SessionId,
        kind: impl Into<String>,
        payload: impl Into<String>,
        created_at: TimestampMs,
    ) -> Result<Self, StateError> {
        Ok(Self {
            id,
            session_id,
            kind: validate_text("task kind", kind.into())?,
            payload: payload.into(),
            status: TaskStatus::Pending,
            created_at,
            updated_at: created_at,
            version: 1,
        })
    }
}

pub(crate) fn validate_text(field: &'static str, value: String) -> Result<String, StateError> {
    if value.contains('\0') {
        return Err(StateError::InvalidValue {
            field,
            reason: "must not contain NUL characters",
        });
    }
    if value.trim().is_empty() {
        return Err(StateError::InvalidValue {
            field,
            reason: "must not be empty",
        });
    }
    Ok(value)
}

pub(crate) const fn invalid_stored(field: &'static str) -> StateError {
    StateError::InvalidValue {
        field,
        reason: "persisted value is not supported",
    }
}
