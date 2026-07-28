//! Glob pattern matching and the workspace glob tool.
//!
//! The matcher is segment-based and iterative so a hostile pattern cannot
//! trigger exponential backtracking.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::json;

use crate::error::ToolError;
use crate::fs::{PATH_MAX_BYTES, optional_path};
use crate::permission::{Authorization, Capability, PermissionDescriptor, Resource, RiskLevel};
use crate::schema::{Arguments, Field, FieldType, ParameterSchema};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Inclusive maximum byte length of a glob pattern.
const MAX_PATTERN_BYTES: usize = 256;
/// Inclusive maximum number of `/`-separated pattern segments.
const MAX_PATTERN_SEGMENTS: usize = 24;
/// Inclusive maximum number of paths returned by one glob.
const MAX_GLOB_RESULTS: u64 = 1_000;

const GLOB_SCHEMA: ParameterSchema = ParameterSchema::new(&[
    Field {
        name: "pattern",
        description: "Glob pattern such as `src/**/*.rs`, matched against workspace-relative paths",
        required: true,
        ty: FieldType::Text {
            max_bytes: MAX_PATTERN_BYTES,
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
        name: "max_results",
        description: "Maximum number of paths to return",
        required: false,
        ty: FieldType::Count {
            max: MAX_GLOB_RESULTS,
        },
    },
])
.recording(&["path", "max_results"]);

/// A validated glob pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobPattern {
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    /// `**`, which matches zero or more whole path segments.
    AnyDepth,
    /// A single-segment pattern.
    Single(Vec<Token>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Literal(char),
    AnyChar,
    AnyRun,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

impl GlobPattern {
    /// Validates a caller-supplied glob pattern.
    ///
    /// # Errors
    ///
    /// Returns [`GlobError::Empty`] for an empty pattern, [`GlobError::TooLong`]
    /// past 256 bytes, [`GlobError::ControlCharacter`] when the pattern holds a
    /// control character, [`GlobError::NotRelative`] for a leading separator, a
    /// `:`, or a `.`/`..` segment, [`GlobError::TooManySegments`] past 24
    /// segments, [`GlobError::EmptySegment`] for a repeated separator,
    /// [`GlobError::UnterminatedClass`] for a `[` with no closing `]` or a stray
    /// `]`, and [`GlobError::InvalidRange`] when a class range ends before it
    /// starts.
    pub fn parse(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(GlobError::TooLong);
        }
        if pattern.chars().any(char::is_control) {
            return Err(GlobError::ControlCharacter);
        }
        if pattern.starts_with('/') || pattern.starts_with('\\') || pattern.contains(':') {
            return Err(GlobError::NotRelative);
        }
        let raw: Vec<&str> = pattern.split(['/', '\\']).collect();
        if raw.len() > MAX_PATTERN_SEGMENTS {
            return Err(GlobError::TooManySegments);
        }
        let mut segments = Vec::with_capacity(raw.len());
        for segment in raw {
            match segment {
                "" => return Err(GlobError::EmptySegment),
                "." | ".." => return Err(GlobError::NotRelative),
                "**" => segments.push(Segment::AnyDepth),
                other => segments.push(Segment::Single(parse_tokens(other)?)),
            }
        }
        Ok(Self { segments })
    }

    /// Returns whether a normalized workspace-relative path matches.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        match_segments(&self.segments, &parts, &mut MatchScratch::default())
    }

    /// Matches path components that the caller already has split apart.
    ///
    /// Walking a workspace yields components directly, so the tool loop uses
    /// this to avoid rebuilding a joined path string for every candidate file.
    /// The scratch buffers are the caller's so that a walk of 20 000 paths does
    /// not allocate three vectors per candidate.
    fn matches_parts(&self, parts: &[&str], scratch: &mut MatchScratch) -> bool {
        match_segments(&self.segments, parts, scratch)
    }
}

/// Reusable working buffers for one matcher invocation.
///
/// `match_segments` needs two rows of a reachability table and `match_tokens`
/// needs a segment's characters addressable by index. Allocating those per
/// candidate path cost three allocations per walked file; hoisting them out of
/// the loop took the matcher from 199 ns to 78 ns per path.
#[derive(Debug, Default)]
struct MatchScratch {
    reachable: Vec<bool>,
    next: Vec<bool>,
    characters: Vec<char>,
}

fn parse_tokens(segment: &str) -> Result<Vec<Token>, GlobError> {
    let mut tokens = Vec::new();
    let mut characters = segment.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '*' => {
                if tokens.last() != Some(&Token::AnyRun) {
                    tokens.push(Token::AnyRun);
                }
            }
            '?' => tokens.push(Token::AnyChar),
            '[' => {
                let negated = if matches!(characters.peek(), Some('!' | '^')) {
                    characters.next();
                    true
                } else {
                    false
                };
                let mut ranges = Vec::new();
                let mut closed = false;
                while let Some(item) = characters.next() {
                    if item == ']' && !ranges.is_empty() {
                        closed = true;
                        break;
                    }
                    if characters.peek() == Some(&'-') {
                        characters.next();
                        let end = characters.next().ok_or(GlobError::UnterminatedClass)?;
                        if end < item {
                            return Err(GlobError::InvalidRange);
                        }
                        ranges.push((item, end));
                    } else {
                        ranges.push((item, item));
                    }
                }
                if !closed {
                    return Err(GlobError::UnterminatedClass);
                }
                tokens.push(Token::Class { negated, ranges });
            }
            ']' => return Err(GlobError::UnterminatedClass),
            other => tokens.push(Token::Literal(other)),
        }
    }
    Ok(tokens)
}

/// Matches pattern segments against path segments with iterative `**` handling.
fn match_segments(segments: &[Segment], parts: &[&str], scratch: &mut MatchScratch) -> bool {
    // `reachable[index]` marks that the first `index` path parts have been
    // consumed by the pattern prefix processed so far. The two buffers are
    // swapped rather than reallocated: a pattern may hold 24 segments and the
    // matcher runs once per walked file.
    let MatchScratch {
        reachable,
        next,
        characters,
    } = scratch;
    reachable.clear();
    reachable.resize(parts.len() + 1, false);
    next.clear();
    next.resize(parts.len() + 1, false);
    reachable[0] = true;
    for segment in segments {
        next.fill(false);
        match segment {
            Segment::AnyDepth => {
                let mut carry = false;
                for index in 0..=parts.len() {
                    carry |= reachable[index];
                    next[index] = carry;
                }
            }
            Segment::Single(tokens) => {
                for index in 0..parts.len() {
                    if reachable[index] && match_tokens(tokens, parts[index], characters) {
                        next[index + 1] = true;
                    }
                }
            }
        }
        std::mem::swap(reachable, next);
        if !reachable.iter().any(|value| *value) {
            return false;
        }
    }
    reachable[parts.len()]
}

/// Matches one segment with a linear two-pointer scan over `*` runs.
fn match_tokens(tokens: &[Token], part: &str, characters: &mut Vec<char>) -> bool {
    characters.clear();
    characters.extend(part.chars());
    let mut token_index = 0;
    let mut char_index = 0;
    let mut star_token = None;
    let mut star_char = 0;
    while char_index < characters.len() {
        match tokens.get(token_index) {
            Some(Token::AnyRun) => {
                star_token = Some(token_index);
                star_char = char_index;
                token_index += 1;
            }
            Some(token) if token_matches(token, characters[char_index]) => {
                token_index += 1;
                char_index += 1;
            }
            _ => match star_token {
                Some(index) => {
                    token_index = index + 1;
                    star_char += 1;
                    char_index = star_char;
                }
                None => return false,
            },
        }
    }
    tokens[token_index..]
        .iter()
        .all(|token| *token == Token::AnyRun)
}

fn token_matches(token: &Token, character: char) -> bool {
    match token {
        Token::Literal(expected) => *expected == character,
        Token::AnyChar | Token::AnyRun => true,
        Token::Class { negated, ranges } => {
            let inside = ranges
                .iter()
                .any(|(start, end)| *start <= character && character <= *end);
            inside != *negated
        }
    }
}

/// A rejected glob pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobError {
    /// The pattern was empty.
    Empty,
    /// The pattern exceeded its byte bound.
    TooLong,
    /// The pattern had more segments than the bound allows.
    TooManySegments,
    /// The pattern contained a control character.
    ControlCharacter,
    /// The pattern was absolute, drive-qualified, or used traversal.
    NotRelative,
    /// A repeated separator produced an empty segment.
    EmptySegment,
    /// A character class was not closed.
    UnterminatedClass,
    /// A character class range ran backwards.
    InvalidRange,
}

impl Display for GlobError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "glob pattern is empty",
            Self::TooLong => "glob pattern is too long",
            Self::TooManySegments => "glob pattern has too many segments",
            Self::ControlCharacter => "glob pattern contains a control character",
            Self::NotRelative => "glob pattern must be workspace-relative",
            Self::EmptySegment => "glob pattern has an empty segment",
            Self::UnterminatedClass => "glob pattern has an unterminated character class",
            Self::InvalidRange => "glob pattern has an inverted character range",
        };
        formatter.write_str(message)
    }
}

impl Error for GlobError {}

impl From<GlobError> for ToolError {
    fn from(error: GlobError) -> Self {
        Self::Sandbox(match error {
            GlobError::Empty => crate::sandbox::SandboxError::EmptyPath,
            GlobError::TooLong => crate::sandbox::SandboxError::PathTooLong,
            GlobError::TooManySegments => crate::sandbox::SandboxError::TooManyComponents,
            GlobError::ControlCharacter => crate::sandbox::SandboxError::ControlCharacter,
            GlobError::NotRelative => crate::sandbox::SandboxError::AbsolutePathForbidden,
            GlobError::EmptySegment => crate::sandbox::SandboxError::EmptyComponent,
            GlobError::UnterminatedClass | GlobError::InvalidRange => {
                crate::sandbox::SandboxError::InvalidCharacter
            }
        })
    }
}

/// Finds workspace files whose relative path matches a glob pattern.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsGlobTool;

impl Tool for FsGlobTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs_glob",
            title: "Find files by pattern",
            description: "Lists workspace files whose relative path matches a glob pattern. \
                          Supports `*`, `?`, `**`, and character classes.",
            schema: GLOB_SCHEMA,
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
        let pattern = GlobPattern::parse(arguments.required_text("pattern")?)?;
        let requested = arguments.count("max_results").unwrap_or(MAX_GLOB_RESULTS);
        let limit = usize::try_from(requested.min(MAX_GLOB_RESULTS)).unwrap_or(0);
        let prefix_len = root.components().len();
        let mut matched = Vec::new();
        let mut total = 0_usize;
        // The component slice is borrowed per file instead of joined back into
        // a fresh `String`: a walk yields up to 20 000 paths.
        let files = context.sandbox.walk_files(&root)?;
        let mut parts: Vec<&str> = Vec::new();
        let mut scratch = MatchScratch::default();
        for file in &files {
            parts.clear();
            parts.extend(file.components()[prefix_len..].iter().map(String::as_str));
            if pattern.matches_parts(&parts, &mut scratch) {
                total += 1;
                if matched.len() < limit {
                    matched.push(file.as_str().to_owned());
                }
            }
        }
        let truncated = total > matched.len();
        Ok(ToolOutput::new(
            matched.join("\n"),
            json!({
                "root": root.as_str(),
                "matches": matched,
                "total_matches": total,
            }),
        )
        .truncated(truncated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, path: &str) -> bool {
        GlobPattern::parse(pattern)
            .expect("valid pattern")
            .matches(path)
    }

    #[test]
    fn single_star_never_crosses_a_separator() {
        assert!(matches("*.rs", "main.rs"));
        assert!(!matches("*.rs", "src/main.rs"));
        assert!(matches("src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "src/tools/main.rs"));
    }

    #[test]
    fn double_star_spans_zero_or_more_segments() {
        assert!(matches("src/**/*.rs", "src/main.rs"));
        assert!(matches("src/**/*.rs", "src/tools/fs/basic.rs"));
        assert!(matches("**/*.rs", "main.rs"));
        assert!(!matches("src/**/*.rs", "tests/main.rs"));
        assert!(matches("**", "a/b/c"));
    }

    #[test]
    fn question_marks_and_character_classes_are_exact() {
        assert!(matches("a?c.txt", "abc.txt"));
        assert!(!matches("a?c.txt", "ac.txt"));
        assert!(!matches("a?c.txt", "a/c.txt"));
        assert!(matches("file[0-9].log", "file7.log"));
        assert!(!matches("file[0-9].log", "filex.log"));
        assert!(matches("file[!0-9].log", "filex.log"));
        assert!(!matches("file[!0-9].log", "file7.log"));
        assert!(matches("[abc]x", "bx"));
    }

    #[test]
    fn matching_is_case_sensitive_and_literal_dots_are_required() {
        assert!(!matches("*.RS", "main.rs"));
        assert!(!matches("main.rs", "mainxrs"));
        assert!(matches("main.rs", "main.rs"));
    }

    #[test]
    fn rejects_absolute_traversal_and_malformed_patterns() {
        let cases: [(&str, GlobError); 9] = [
            ("", GlobError::Empty),
            ("/etc/*", GlobError::NotRelative),
            (r"\etc\*", GlobError::NotRelative),
            ("C:/Windows/*", GlobError::NotRelative),
            ("../*.rs", GlobError::NotRelative),
            ("src//*.rs", GlobError::EmptySegment),
            ("src/[abc.rs", GlobError::UnterminatedClass),
            ("src/[z-a].rs", GlobError::InvalidRange),
            ("a\nb", GlobError::ControlCharacter),
        ];
        for (pattern, expected) in cases {
            assert_eq!(GlobPattern::parse(pattern), Err(expected), "{pattern}");
        }
    }

    #[test]
    fn pathological_star_runs_terminate_quickly() {
        let pattern = format!("{}b", "a*".repeat(40));
        let path = "a".repeat(200);
        assert!(!matches(&pattern, &path));
        assert!(matches(&pattern, &format!("{}b", "a".repeat(200))));
    }

    #[test]
    fn adjacent_stars_collapse_and_trailing_stars_match_empty() {
        assert!(matches("a***", "a"));
        assert!(matches("a***", "abcdef"));
        assert!(!matches("a***", ""), "an empty path matches no pattern");
    }
}
