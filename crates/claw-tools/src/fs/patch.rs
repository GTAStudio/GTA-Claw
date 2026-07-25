//! Strict unified-diff parsing and application.
//!
//! Application is exact: every context and removal line must equal the file
//! line it claims, hunks must be ordered and in range, and declared hunk counts
//! must match the body. A patch that does not apply cleanly changes nothing.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::json;

use crate::error::ToolError;
use crate::fs::{PATH_MAX_BYTES, decode_utf8, required_path};
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::sandbox::WriteMode;
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum byte length of a patch payload.
const MAX_PATCH_BYTES: usize = 256 * 1024;
/// Inclusive maximum number of hunks in one patch.
const MAX_HUNKS: usize = 512;

const PATCH_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "path",
        description: "Workspace-relative file the patch applies to",
        required: true,
        ty: FieldType::Text {
            max_bytes: PATH_MAX_BYTES,
        },
    },
    Field {
        name: "patch",
        description: "Unified diff for exactly one file, with `@@` hunk headers",
        required: true,
        ty: FieldType::Blob {
            max_bytes: MAX_PATCH_BYTES,
        },
    },
])
.recording(&["path"]);

/// Line terminator style preserved across a patch application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LineEnding {
    Lf,
    Crlf,
}

impl LineEnding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
        }
    }
}

/// One parsed hunk.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Hunk {
    old_start: usize,
    old_count: usize,
    new_count: usize,
    body: Vec<HunkLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HunkLine {
    Context(String),
    Removed(String),
    Added(String),
}

/// A parsed unified diff restricted to a single file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnifiedPatch {
    hunks: Vec<Hunk>,
}

impl UnifiedPatch {
    /// Parses a unified diff, verifying any file headers name `path`.
    pub fn parse(patch: &str, path: &str) -> Result<Self, PatchError> {
        if patch.trim().is_empty() {
            return Err(PatchError::Empty);
        }
        if patch.len() > MAX_PATCH_BYTES {
            return Err(PatchError::TooLong);
        }
        let mut hunks: Vec<Hunk> = Vec::new();
        let mut current: Option<Hunk> = None;
        let mut seen_hunk_header = false;
        // A trailing terminator would otherwise yield a phantom empty line
        // that a hunk body would count as context.
        let body_text = patch.strip_suffix('\n').unwrap_or(patch);
        for raw in body_text.split('\n') {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if let Some(header) = line.strip_prefix("--- ") {
                if seen_hunk_header {
                    return Err(PatchError::MultipleFiles);
                }
                verify_header_path(header, path)?;
                continue;
            }
            if let Some(header) = line.strip_prefix("+++ ") {
                if seen_hunk_header {
                    return Err(PatchError::MultipleFiles);
                }
                verify_header_path(header, path)?;
                continue;
            }
            if line.starts_with("diff ") || line.starts_with("index ") {
                if seen_hunk_header {
                    return Err(PatchError::MultipleFiles);
                }
                continue;
            }
            if line.starts_with("@@") {
                seen_hunk_header = true;
                if let Some(hunk) = current.take() {
                    hunks.push(hunk);
                }
                if hunks.len() >= MAX_HUNKS {
                    return Err(PatchError::TooManyHunks);
                }
                current = Some(parse_hunk_header(line)?);
                continue;
            }
            let Some(hunk) = current.as_mut() else {
                if line.is_empty() {
                    continue;
                }
                return Err(PatchError::MissingHunkHeader);
            };
            if line == r"\ No newline at end of file" {
                continue;
            }
            match line.chars().next() {
                Some(' ') => hunk.body.push(HunkLine::Context(line[1..].to_owned())),
                Some('-') => hunk.body.push(HunkLine::Removed(line[1..].to_owned())),
                Some('+') => hunk.body.push(HunkLine::Added(line[1..].to_owned())),
                None => hunk.body.push(HunkLine::Context(String::new())),
                Some(_) => return Err(PatchError::InvalidLinePrefix),
            }
        }
        if let Some(hunk) = current.take() {
            hunks.push(hunk);
        }
        if hunks.is_empty() {
            return Err(PatchError::MissingHunkHeader);
        }
        for hunk in &hunks {
            let removed = hunk
                .body
                .iter()
                .filter(|line| matches!(line, HunkLine::Context(_) | HunkLine::Removed(_)))
                .count();
            let added = hunk
                .body
                .iter()
                .filter(|line| matches!(line, HunkLine::Context(_) | HunkLine::Added(_)))
                .count();
            if removed != hunk.old_count || added != hunk.new_count {
                return Err(PatchError::CountMismatch);
            }
        }
        Ok(Self { hunks })
    }

    /// Applies the patch to `original`, returning the new content.
    pub fn apply(&self, original: &str) -> Result<String, PatchError> {
        let ending = if original.contains("\r\n") {
            LineEnding::Crlf
        } else {
            LineEnding::Lf
        };
        let trailing_newline = original.ends_with('\n');
        let lines: Vec<&str> = if original.is_empty() {
            Vec::new()
        } else {
            original
                .split('\n')
                .map(|line| line.strip_suffix('\r').unwrap_or(line))
                .collect()
        };
        // A trailing terminator produces a final empty element that is not a line.
        let lines = if trailing_newline && !lines.is_empty() {
            &lines[..lines.len() - 1]
        } else {
            &lines[..]
        };

        let mut output: Vec<String> = Vec::new();
        let mut cursor = 0_usize;
        for hunk in &self.hunks {
            let start = hunk
                .old_start
                .checked_sub(1)
                .ok_or(PatchError::OutOfRange)?;
            if start < cursor {
                return Err(PatchError::HunksOutOfOrder);
            }
            if start > lines.len() {
                return Err(PatchError::OutOfRange);
            }
            output.extend(lines[cursor..start].iter().map(|line| (*line).to_owned()));
            cursor = start;
            for entry in &hunk.body {
                match entry {
                    HunkLine::Context(text) | HunkLine::Removed(text) => {
                        let actual = lines.get(cursor).ok_or(PatchError::OutOfRange)?;
                        if actual != text {
                            return Err(PatchError::ContextMismatch);
                        }
                        if matches!(entry, HunkLine::Context(_)) {
                            output.push((*actual).to_owned());
                        }
                        cursor += 1;
                    }
                    HunkLine::Added(text) => output.push(text.clone()),
                }
            }
        }
        output.extend(lines[cursor..].iter().map(|line| (*line).to_owned()));
        let mut joined = output.join(ending.as_str());
        if trailing_newline && !joined.is_empty() {
            joined.push_str(ending.as_str());
        }
        Ok(joined)
    }

    /// Returns the number of hunks.
    #[must_use]
    pub fn hunk_count(&self) -> usize {
        self.hunks.len()
    }
}

fn verify_header_path(header: &str, path: &str) -> Result<(), PatchError> {
    let candidate = header.split('\t').next().unwrap_or(header).trim();
    if candidate == "/dev/null" {
        return Err(PatchError::PathMismatch);
    }
    let normalized = candidate.replace('\\', "/");
    let stripped = normalized
        .strip_prefix("a/")
        .or_else(|| normalized.strip_prefix("b/"))
        .unwrap_or(normalized.as_str());
    if stripped == path {
        Ok(())
    } else {
        Err(PatchError::PathMismatch)
    }
}

fn parse_hunk_header(line: &str) -> Result<Hunk, PatchError> {
    let body = line
        .strip_prefix("@@")
        .and_then(|rest| rest.split_once("@@"))
        .map(|(ranges, _)| ranges.trim())
        .ok_or(PatchError::MalformedHunkHeader)?;
    let (old, new) = body
        .split_once(' ')
        .ok_or(PatchError::MalformedHunkHeader)?;
    let old = old
        .strip_prefix('-')
        .ok_or(PatchError::MalformedHunkHeader)?;
    let new = new
        .trim()
        .strip_prefix('+')
        .ok_or(PatchError::MalformedHunkHeader)?;
    let (old_start, old_count) = parse_range(old)?;
    let (_new_start, new_count) = parse_range(new)?;
    if old_start == 0 && old_count != 0 {
        return Err(PatchError::OutOfRange);
    }
    Ok(Hunk {
        old_start: if old_count == 0 {
            old_start + 1
        } else {
            old_start
        },
        old_count,
        new_count,
        body: Vec::new(),
    })
}

fn parse_range(value: &str) -> Result<(usize, usize), PatchError> {
    let (start, count) = match value.split_once(',') {
        Some((start, count)) => (start, count),
        None => (value, "1"),
    };
    let start = start
        .parse::<usize>()
        .map_err(|_| PatchError::MalformedHunkHeader)?;
    let count = count
        .parse::<usize>()
        .map_err(|_| PatchError::MalformedHunkHeader)?;
    Ok((start, count))
}

/// A patch that could not be parsed or applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchError {
    /// The patch was empty.
    Empty,
    /// The patch exceeded its byte bound.
    TooLong,
    /// The patch contained no hunk header.
    MissingHunkHeader,
    /// A hunk header was malformed.
    MalformedHunkHeader,
    /// A hunk body line had an unrecognized prefix.
    InvalidLinePrefix,
    /// The declared hunk counts do not match the hunk body.
    CountMismatch,
    /// A file header named a different path than the argument.
    PathMismatch,
    /// The patch touched more than one file.
    MultipleFiles,
    /// The patch had more hunks than the bound allows.
    TooManyHunks,
    /// Hunks were not in ascending, non-overlapping order.
    HunksOutOfOrder,
    /// A hunk referenced a line outside the file.
    OutOfRange,
    /// A context or removal line did not match the file.
    ContextMismatch,
}

impl Display for PatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "patch is empty",
            Self::TooLong => "patch is too long",
            Self::MissingHunkHeader => "patch has no hunk header",
            Self::MalformedHunkHeader => "patch has a malformed hunk header",
            Self::InvalidLinePrefix => "patch has an invalid hunk line prefix",
            Self::CountMismatch => "patch hunk counts do not match the hunk body",
            Self::PathMismatch => "patch header names a different file",
            Self::MultipleFiles => "patch touches more than one file",
            Self::TooManyHunks => "patch has too many hunks",
            Self::HunksOutOfOrder => "patch hunks are out of order",
            Self::OutOfRange => "patch hunk is outside the file",
            Self::ContextMismatch => "patch context does not match the file",
        };
        formatter.write_str(message)
    }
}

impl Error for PatchError {}

/// Applies a unified diff to exactly one workspace file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsPatchTool;

impl Tool for FsPatchTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_patch",
            title: "Apply patch",
            description: "Applies a unified diff to one workspace file. Every context line must \
                          match exactly; a patch that does not apply cleanly changes nothing.",
            schema: PATCH_SCHEMA,
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
        let patch = UnifiedPatch::parse(arguments.required_text("patch")?, path.as_str())?;
        let original = decode_utf8(context.sandbox.read_file(&path)?)?;
        let updated = patch.apply(&original)?;
        let resolved =
            context
                .sandbox
                .write_file(&path, updated.as_bytes(), WriteMode::Overwrite)?;
        Ok(ToolOutput::new(
            format!(
                "applied {} hunk(s) to {}",
                patch.hunk_count(),
                resolved.relative()
            ),
            json!({
                "path": resolved.relative().as_str(),
                "hunks": patch.hunk_count(),
                "bytes_written": updated.len(),
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINAL: &str = "alpha\nbravo\ncharlie\ndelta\n";

    #[test]
    fn applies_a_replacement_hunk_exactly() {
        let patch = UnifiedPatch::parse(
            "--- a/notes.txt\n+++ b/notes.txt\n@@ -2,2 +2,3 @@\n bravo\n-charlie\n+CHARLIE\n+extra\n",
            "notes.txt",
        )
        .expect("valid patch");
        assert_eq!(patch.hunk_count(), 1);
        assert_eq!(
            patch.apply(ORIGINAL).expect("clean application"),
            "alpha\nbravo\nCHARLIE\nextra\ndelta\n"
        );
    }

    #[test]
    fn applies_pure_insertions_and_pure_deletions() {
        let insertion = UnifiedPatch::parse("@@ -1,1 +1,2 @@\n alpha\n+inserted\n", "notes.txt")
            .expect("valid patch");
        assert_eq!(
            insertion.apply(ORIGINAL).expect("clean application"),
            "alpha\ninserted\nbravo\ncharlie\ndelta\n"
        );
        let deletion = UnifiedPatch::parse("@@ -3,2 +3,1 @@\n-charlie\n delta\n", "notes.txt")
            .expect("valid patch");
        assert_eq!(
            deletion.apply(ORIGINAL).expect("clean application"),
            "alpha\nbravo\ndelta\n"
        );
    }

    #[test]
    fn applies_multiple_ordered_hunks() {
        let patch = UnifiedPatch::parse(
            "@@ -1,1 +1,1 @@\n-alpha\n+ALPHA\n@@ -4,1 +4,1 @@\n-delta\n+DELTA\n",
            "notes.txt",
        )
        .expect("valid patch");
        assert_eq!(patch.hunk_count(), 2);
        assert_eq!(
            patch.apply(ORIGINAL).expect("clean application"),
            "ALPHA\nbravo\ncharlie\nDELTA\n"
        );
    }

    #[test]
    fn preserves_crlf_line_endings_and_missing_trailing_newline() {
        let crlf = "alpha\r\nbravo\r\n";
        let patch =
            UnifiedPatch::parse("@@ -2,1 +2,1 @@\n-bravo\n+BRAVO\n", "notes.txt").expect("valid");
        assert_eq!(
            patch.apply(crlf).expect("clean application"),
            "alpha\r\nBRAVO\r\n"
        );
        let without_newline = "alpha\nbravo";
        assert_eq!(
            patch.apply(without_newline).expect("clean application"),
            "alpha\nBRAVO"
        );
    }

    #[test]
    fn refuses_context_that_does_not_match() {
        let patch = UnifiedPatch::parse("@@ -2,1 +2,1 @@\n-BRAVO\n+bravo\n", "notes.txt")
            .expect("valid patch");
        assert_eq!(patch.apply(ORIGINAL), Err(PatchError::ContextMismatch));
    }

    #[test]
    fn refuses_out_of_order_and_out_of_range_hunks() {
        let backwards = UnifiedPatch::parse(
            "@@ -3,1 +3,1 @@\n-charlie\n+CHARLIE\n@@ -1,1 +1,1 @@\n-alpha\n+ALPHA\n",
            "notes.txt",
        )
        .expect("valid patch");
        assert_eq!(backwards.apply(ORIGINAL), Err(PatchError::HunksOutOfOrder));

        let beyond = UnifiedPatch::parse("@@ -99,1 +99,1 @@\n-alpha\n+ALPHA\n", "notes.txt")
            .expect("valid patch");
        assert_eq!(beyond.apply(ORIGINAL), Err(PatchError::OutOfRange));
    }

    #[test]
    fn refuses_malformed_patches_and_foreign_paths() {
        let cases: [(&str, PatchError); 7] = [
            ("", PatchError::Empty),
            ("no hunk here\n", PatchError::MissingHunkHeader),
            ("@@ nonsense @@\n", PatchError::MalformedHunkHeader),
            ("@@ -1,1 +1,1 @@\n!alpha\n", PatchError::InvalidLinePrefix),
            ("@@ -1,2 +1,1 @@\n-alpha\n", PatchError::CountMismatch),
            (
                "--- a/other.txt\n+++ b/other.txt\n@@ -1,1 +1,1 @@\n-alpha\n+ALPHA\n",
                PatchError::PathMismatch,
            ),
            (
                "--- a/../../etc/passwd\n@@ -1,1 +1,1 @@\n-alpha\n+ALPHA\n",
                PatchError::PathMismatch,
            ),
        ];
        for (patch, expected) in cases {
            assert_eq!(
                UnifiedPatch::parse(patch, "notes.txt"),
                Err(expected),
                "{patch:?}"
            );
        }
    }

    #[test]
    fn a_failed_hunk_leaves_the_whole_patch_unapplied() {
        let patch = UnifiedPatch::parse(
            "@@ -1,1 +1,1 @@\n-alpha\n+ALPHA\n@@ -3,1 +3,1 @@\n-CHARLIE\n+charlie\n",
            "notes.txt",
        )
        .expect("valid patch");
        assert_eq!(patch.apply(ORIGINAL), Err(PatchError::ContextMismatch));
    }
}
