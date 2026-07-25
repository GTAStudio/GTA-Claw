//! Filesystem tools. Every path argument is resolved through
//! [`crate::sandbox::Sandbox`] before any operation touches the disk.

mod basic;
mod glob;
mod patch;
mod search;

pub use basic::{FsListTool, FsReadTool, FsWriteTool};
pub use glob::{FsGlobTool, GlobError, GlobPattern};
pub use patch::{FsPatchTool, PatchError, UnifiedPatch};
pub use search::FsSearchTool;

use crate::error::ToolError;
use crate::sandbox::RelativePath;
use crate::schema::Arguments;
use crate::tool::ToolContext;

/// Inclusive maximum byte length accepted for a path argument.
pub(crate) const PATH_MAX_BYTES: usize = 1024;
/// Inclusive maximum byte length accepted for file content arguments.
pub(crate) const CONTENT_MAX_BYTES: usize = 1024 * 1024;

/// Validates a required path argument into a sandbox-relative path.
pub(crate) fn required_path(
    arguments: &Arguments,
    context: &ToolContext<'_>,
    name: &'static str,
) -> Result<RelativePath, ToolError> {
    let raw = arguments.required_text(name)?;
    Ok(context.sandbox.relative(raw)?)
}

/// Validates an optional path argument, defaulting to the workspace root.
pub(crate) fn optional_path(
    arguments: &Arguments,
    context: &ToolContext<'_>,
    name: &'static str,
) -> Result<RelativePath, ToolError> {
    match arguments.text(name) {
        Some(raw) => Ok(context.sandbox.relative(raw)?),
        None => Ok(context.sandbox.resolve_root().relative().clone()),
    }
}

/// Decodes bytes that a tool is about to hand to a model.
pub(crate) fn decode_utf8(bytes: Vec<u8>) -> Result<String, ToolError> {
    String::from_utf8(bytes)
        .map_err(|_| ToolError::Sandbox(crate::sandbox::SandboxError::BinaryContent))
}
