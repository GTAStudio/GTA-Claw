//! Minimal audited access to SQLite file-control operations.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
/// Failure returned by SQLite while inspecting its open main database file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileControlError {
    /// SQLx could not lock its live SQLite handle.
    Handle(String),
    /// SQLite rejected the file-control request.
    SQLite(i32),
}

impl FileControlError {
    /// Returns SQLite's result code.
    #[must_use]
    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Handle(_) => None,
            Self::SQLite(code) => Some(*code),
        }
    }
}

impl Display for FileControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handle(message) => write!(formatter, "failed to lock SQLite handle: {message}"),
            Self::SQLite(code) => {
                write!(
                    formatter,
                    "SQLite file-control operation failed with code {code}"
                )
            }
        }
    }
}

impl Error for FileControlError {}

/// Returns whether SQLite reports that its open main database was moved or replaced.
pub async fn main_database_has_moved(
    connection: &mut sqlx::SqliteConnection,
) -> Result<bool, FileControlError> {
    let mut database = connection
        .lock_handle()
        .await
        .map_err(|error| FileControlError::Handle(error.to_string()))?;
    let mut moved = 0_i32;
    // SAFETY: SQLx's locked handle guarantees a live SQLite connection for this
    // call. The schema name is NUL-terminated and `moved` remains valid.
    let result = unsafe {
        libsqlite3_sys::sqlite3_file_control(
            database.as_raw_handle().as_ptr(),
            c"main".as_ptr(),
            libsqlite3_sys::SQLITE_FCNTL_HAS_MOVED,
            (&raw mut moved).cast(),
        )
    };
    if result == libsqlite3_sys::SQLITE_OK {
        Ok(moved != 0)
    } else {
        Err(FileControlError::SQLite(result))
    }
}
