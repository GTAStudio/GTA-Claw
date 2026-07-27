//! Bounded literal content search across the workspace sandbox.

use serde_json::{Value, json};

use crate::error::ToolError;
use crate::fs::{PATH_MAX_BYTES, optional_path};
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum byte length of a search query.
const MAX_QUERY_BYTES: usize = 512;
/// Inclusive maximum number of matches returned by one search.
const MAX_SEARCH_RESULTS: u64 = 500;
/// Inclusive maximum characters preserved from a matching line.
const MAX_LINE_CHARS: usize = 400;

const SEARCH_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "query",
        description: "Literal text to find; regular expressions are not interpreted",
        required: true,
        ty: FieldType::Text {
            max_bytes: MAX_QUERY_BYTES,
        },
    },
    Field {
        name: "path",
        description: "Workspace-relative subtree to search, defaulting to the workspace root",
        required: false,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "case_sensitive",
        description: "Whether matching is case sensitive; defaults to true",
        required: false,
        ty: FieldType::Flag,
    },
    Field {
        name: "max_results",
        description: "Maximum number of matches to return",
        required: false,
        ty: FieldType::Count {
            max: MAX_SEARCH_RESULTS,
        },
    },
])
.recording(&["path", "case_sensitive", "max_results"]);

/// Searches workspace files for a literal string.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsSearchTool;

impl Tool for FsSearchTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_search",
            title: "Search file contents",
            description: "Searches UTF-8 workspace files for a literal string and returns \
                          matching lines with their paths and line numbers.",
            schema: SEARCH_SCHEMA,
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
        let root = optional_path(arguments, context, "path")?;
        let query = arguments.required_text("query")?;
        if query.is_empty() {
            return Err(ToolError::Schema(crate::schema::SchemaError::Empty(
                "query",
            )));
        }
        let case_sensitive = arguments.flag_or("case_sensitive", true);
        let needle = if case_sensitive {
            query.to_owned()
        } else {
            query.to_lowercase()
        };
        let requested = arguments.count("max_results").unwrap_or(MAX_SEARCH_RESULTS);
        let limit = usize::try_from(requested.min(MAX_SEARCH_RESULTS)).unwrap_or(0);

        let mut matches: Vec<Value> = Vec::new();
        let mut rendered = Vec::new();
        let mut total = 0_usize;
        let mut skipped_files = 0_usize;
        for file in context.sandbox.walk_files(&root)? {
            let Ok(bytes) = context.sandbox.read_file(&file) else {
                skipped_files += 1;
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                skipped_files += 1;
                continue;
            };
            for (index, line) in text.lines().enumerate() {
                // The case-sensitive path is the common one and must not copy
                // every line of every file just to look for a substring.
                let found = if case_sensitive {
                    line.contains(needle.as_str())
                } else {
                    line.to_lowercase().contains(needle.as_str())
                };
                if !found {
                    continue;
                }
                total += 1;
                if matches.len() >= limit {
                    continue;
                }
                let excerpt: String = line.chars().take(MAX_LINE_CHARS).collect();
                rendered.push(format!("{}:{}: {excerpt}", file.as_str(), index + 1));
                matches.push(json!({
                    "path": file.as_str(),
                    "line": index + 1,
                    "text": excerpt,
                }));
            }
        }
        let truncated = total > matches.len();
        Ok(ToolOutput::new(
            rendered.join("\n"),
            json!({
                "root": root.as_str(),
                "matches": matches,
                "total_matches": total,
                "skipped_files": skipped_files,
            }),
        )
        .truncated(truncated))
    }
}
