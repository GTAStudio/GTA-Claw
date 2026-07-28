//! Read, write, and list tools.

use serde_json::{Value, json};

use crate::error::ToolError;
use crate::fs::{CONTENT_MAX_BYTES, PATH_MAX_BYTES, decode_utf8, optional_path, required_path};
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::sandbox::WriteMode;
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum number of lines returned by one read.
const MAX_READ_LINES: u64 = 10_000;
/// Inclusive maximum number of entries returned by one listing.
const MAX_LIST_ENTRIES: u64 = 2_000;

const READ_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "path",
        description: "Workspace-relative file path",
        required: true,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "start_line",
        description: "1-based first line to return",
        required: false,
        ty: FieldType::Count { max: 4_294_967_295 },
    },
    Field {
        name: "line_count",
        description: "Maximum number of lines to return",
        required: false,
        ty: FieldType::Count {
            max: MAX_READ_LINES,
        },
    },
])
.recording(&["path", "start_line", "line_count"]);

const WRITE_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "path",
        description: "Workspace-relative file path",
        required: true,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "content",
        description: "Complete new file content",
        required: true,
        ty: FieldType::Blob {
            max_bytes: CONTENT_MAX_BYTES,
        },
    },
    Field {
        name: "mode",
        description: "`create` fails when the file exists; `overwrite` replaces it",
        required: false,
        ty: FieldType::Choice {
            values: &["create", "overwrite"],
        },
    },
])
.recording(&["path", "mode"]);

const LIST_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "path",
        description: "Workspace-relative directory, defaulting to the workspace root",
        required: false,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "max_entries",
        description: "Maximum number of entries to return",
        required: false,
        ty: FieldType::Count {
            max: MAX_LIST_ENTRIES,
        },
    },
])
.recording(&["path", "max_entries"]);

/// Reads a UTF-8 text file inside the workspace sandbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsReadTool;

impl Tool for FsReadTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_read",
            title: "Read file",
            description: "Reads a UTF-8 text file from the workspace. Paths are workspace-relative; \
                          traversal, links, and absolute paths are refused.",
            schema: READ_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::FilesystemRead,
                risk: RiskLevel::Low,
                requires_approval: false,
                gateway_scope: "operator.read",
            },
        }
    }

    fn resource(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        Ok(Resource::Path(
            required_path(arguments, context, "path")?
                .as_str()
                .to_owned(),
        ))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let path = required_path(arguments, context, "path")?;
        let text = decode_utf8(context.sandbox.read_file(&path)?)?;
        let start = arguments
            .count("start_line")
            .unwrap_or(1)
            .max(1)
            .saturating_sub(1);
        let start = usize::try_from(start).unwrap_or(usize::MAX);
        let requested = arguments.count("line_count").unwrap_or(MAX_READ_LINES);
        let limit = usize::try_from(requested.min(MAX_READ_LINES)).unwrap_or(0);
        // One traversal, not two. `total_lines` is reported, so the whole file
        // has to be scanned regardless; counting and selecting in the same pass
        // avoids walking the skipped prefix a second time, which on a
        // 200 000-line file was a third of the call. Only the requested window
        // is materialized: returning a prefix must not cost one pointer per
        // line of the whole file.
        let mut total_lines = 0_usize;
        let mut selected: Vec<&str> = Vec::new();
        for line in text.lines() {
            if total_lines >= start && selected.len() < limit {
                selected.push(line);
            }
            total_lines += 1;
        }
        let start = start.min(total_lines);
        let rendered = selected.join("\n");
        let truncated = start > 0 || start.saturating_add(selected.len()) < total_lines;
        Ok(ToolOutput::new(
            rendered,
            json!({
                "path": path.as_str(),
                "total_lines": total_lines,
                "start_line": start + 1,
                "returned_lines": selected.len(),
            }),
        )
        .truncated(truncated))
    }
}

/// Writes a whole UTF-8 text file inside the workspace sandbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsWriteTool;

impl Tool for FsWriteTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_write",
            title: "Write file",
            description: "Writes a complete UTF-8 text file inside the workspace. The parent \
                          directory must already exist.",
            schema: WRITE_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::FilesystemWrite,
                risk: RiskLevel::Medium,
                requires_approval: true,
                gateway_scope: "operator.write",
            },
        }
    }

    fn resource(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        Ok(Resource::Path(
            required_path(arguments, context, "path")?
                .as_str()
                .to_owned(),
        ))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let path = required_path(arguments, context, "path")?;
        let text = arguments.required_text("content")?;
        let mode = match arguments.text("mode") {
            Some("create") | None => WriteMode::CreateNew,
            Some(_) => WriteMode::Overwrite,
        };
        let resolved = context.sandbox.write_file(&path, text.as_bytes(), mode)?;
        Ok(ToolOutput::new(
            format!("wrote {} bytes to {}", text.len(), resolved.relative()),
            json!({
                "path": resolved.relative().as_str(),
                "bytes_written": text.len(),
                "mode": if mode == WriteMode::CreateNew { "create" } else { "overwrite" },
            }),
        ))
    }
}

/// Lists one directory inside the workspace sandbox without following links.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsListTool;

impl Tool for FsListTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_list",
            title: "List directory",
            description: "Lists the immediate entries of a workspace directory. Links, junctions, \
                          and other reparse points are reported but never followed.",
            schema: LIST_SCHEMA,
            permission: PermissionDescriptor {
                capability: Capability::FilesystemRead,
                risk: RiskLevel::Low,
                requires_approval: false,
                gateway_scope: "operator.read",
            },
        }
    }

    fn resource(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError> {
        Ok(Resource::Path(
            optional_path(arguments, context, "path")?
                .as_str()
                .to_owned(),
        ))
    }

    fn invoke(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
        _authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError> {
        let path = optional_path(arguments, context, "path")?;
        let entries = context.sandbox.read_directory(&path)?;
        let requested = arguments.count("max_entries").unwrap_or(MAX_LIST_ENTRIES);
        let limit = usize::try_from(requested.min(MAX_LIST_ENTRIES)).unwrap_or(0);
        let truncated = entries.len() > limit;
        let selected = &entries[..entries.len().min(limit)];
        // Appended in place rather than through one `format!` per entry: a
        // listing is capped at a few thousand rows and each one is two pushes.
        let mut rendered = String::new();
        for entry in selected {
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            rendered.push_str(entry.kind.as_str());
            rendered.push(' ');
            rendered.push_str(entry.path.as_str());
        }
        let structured: Vec<Value> = selected
            .iter()
            .map(|entry| {
                json!({
                    "path": entry.path.as_str(),
                    "kind": entry.kind.as_str(),
                    "size_bytes": entry.size_bytes,
                })
            })
            .collect();
        Ok(ToolOutput::new(
            rendered,
            json!({
                "path": path.as_str(),
                "entries": structured,
                "total_entries": entries.len(),
            }),
        )
        .truncated(truncated))
    }
}
