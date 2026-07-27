//! Inline directive parsing.
//!
//! Ports `src/auto-reply/reply/directives.ts`,
//! `src/auto-reply/reply/exec/directive.ts`,
//! `src/auto-reply/reply/directive-parsing.ts` and the level normalizers in
//! `src/auto-reply/thinking.shared.ts` from the frozen upstream baseline.
//!
//! Upstream compiles one regular expression per directive:
//!
//! ```text
//! (?:^|\s)\/(?:name1|name2)(?=$|\s|:)
//! ```
//!
//! The port reproduces it by hand rather than taking a regex dependency, which
//! keeps this crate dependency-free. The three properties that matter are all
//! preserved: the match starts at the preceding whitespace character (so the
//! cleaned text loses that separator), alternatives are tried left to right and
//! the first one whose lookahead succeeds wins, and the boundary after the name
//! must be end-of-input, whitespace or `:`.

use std::fmt::{self, Display, Formatter};

use super::text::{collapse_js_whitespace, is_js_space, js_trim, leading_space_len};

/// A directive that can appear inline in an ordinary message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Directive {
    /// `/think`, `/thinking`, `/t`.
    Think,
    /// `/verbose`, `/v`.
    Verbose,
    /// `/trace`.
    Trace,
    /// `/fast`.
    Fast,
    /// `/elevated`, `/elev`.
    Elevated,
    /// `/reasoning`, `/reason`.
    Reasoning,
    /// `/status`, which takes no level.
    Status,
    /// `/exec`, which takes `key=value` options.
    Exec,
}

impl Directive {
    /// Every directive, in the order `directives.ts` compiles them.
    pub const ALL: [Self; 8] = [
        Self::Think,
        Self::Verbose,
        Self::Trace,
        Self::Fast,
        Self::Elevated,
        Self::Reasoning,
        Self::Status,
        Self::Exec,
    ];

    /// Returns the pinned directive names, in alternation order.
    #[must_use]
    pub const fn names(self) -> &'static [&'static str] {
        match self {
            Self::Think => &["thinking", "think", "t"],
            Self::Verbose => &["verbose", "v"],
            Self::Trace => &["trace"],
            Self::Fast => &["fast"],
            Self::Elevated => &["elevated", "elev"],
            Self::Reasoning => &["reasoning", "reason"],
            Self::Status => &["status"],
            Self::Exec => &["exec"],
        }
    }

    /// Returns the registry key of the command this directive shares its name with.
    #[must_use]
    pub const fn command_key(self) -> &'static str {
        match self {
            Self::Think => "think",
            Self::Verbose => "verbose",
            Self::Trace => "trace",
            Self::Fast => "fast",
            Self::Elevated => "elevated",
            Self::Reasoning => "reasoning",
            Self::Status => "status",
            Self::Exec => "exec",
        }
    }

    /// Parses a directive name back to its variant, matched case-insensitively.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|directive| directive.command_key().eq_ignore_ascii_case(key))
    }
}

impl Display for Directive {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.command_key())
    }
}

/// Canonical `/think` levels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ThinkLevel {
    /// `off`.
    Off,
    /// `minimal`.
    Minimal,
    /// `low`.
    Low,
    /// `medium`.
    Medium,
    /// `high`.
    High,
    /// `xhigh`.
    XHigh,
    /// `adaptive`.
    Adaptive,
    /// `max`.
    Max,
    /// `ultra`.
    Ultra,
}

/// Canonical `/verbose` levels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerboseLevel {
    /// `off`.
    Off,
    /// `on`.
    On,
    /// `full`.
    Full,
}

/// Canonical `/trace` levels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TraceLevel {
    /// `off`.
    Off,
    /// `on`.
    On,
    /// `raw`.
    Raw,
}

/// Canonical `/elevated` levels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ElevatedLevel {
    /// `off`.
    Off,
    /// `on`.
    On,
    /// `ask`.
    Ask,
    /// `full`.
    Full,
}

/// Canonical `/reasoning` levels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReasoningLevel {
    /// `off`.
    Off,
    /// `on`.
    On,
    /// `stream`.
    Stream,
}

/// Canonical `/fast` modes; upstream models these as `boolean | "auto"`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FastMode {
    /// `false`.
    Off,
    /// `true`.
    On,
    /// `"auto"`.
    Auto,
}

/// A normalized directive level, tagged with the directive it belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DirectiveLevel {
    /// A `/think` level.
    Think(ThinkLevel),
    /// A `/verbose` level.
    Verbose(VerboseLevel),
    /// A `/trace` level.
    Trace(TraceLevel),
    /// A `/fast` mode.
    Fast(FastMode),
    /// An `/elevated` level.
    Elevated(ElevatedLevel),
    /// A `/reasoning` level.
    Reasoning(ReasoningLevel),
}

impl DirectiveLevel {
    /// Returns the canonical spelling upstream stores in session state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Think(ThinkLevel::Off)
            | Self::Verbose(VerboseLevel::Off)
            | Self::Trace(TraceLevel::Off)
            | Self::Elevated(ElevatedLevel::Off)
            | Self::Reasoning(ReasoningLevel::Off)
            | Self::Fast(FastMode::Off) => "off",
            Self::Think(ThinkLevel::Minimal) => "minimal",
            Self::Think(ThinkLevel::Low) => "low",
            Self::Think(ThinkLevel::Medium) => "medium",
            Self::Think(ThinkLevel::High) => "high",
            Self::Think(ThinkLevel::XHigh) => "xhigh",
            Self::Think(ThinkLevel::Adaptive) => "adaptive",
            Self::Think(ThinkLevel::Max) => "max",
            Self::Think(ThinkLevel::Ultra) => "ultra",
            Self::Verbose(VerboseLevel::On)
            | Self::Trace(TraceLevel::On)
            | Self::Elevated(ElevatedLevel::On)
            | Self::Reasoning(ReasoningLevel::On)
            | Self::Fast(FastMode::On) => "on",
            Self::Verbose(VerboseLevel::Full) | Self::Elevated(ElevatedLevel::Full) => "full",
            Self::Trace(TraceLevel::Raw) => "raw",
            Self::Elevated(ElevatedLevel::Ask) => "ask",
            Self::Reasoning(ReasoningLevel::Stream) => "stream",
            Self::Fast(FastMode::Auto) => "auto",
        }
    }
}

impl Display for DirectiveLevel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The outcome of extracting one directive from a message body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectiveParse {
    cleaned: String,
    present: bool,
    raw_level: Option<String>,
    level: Option<DirectiveLevel>,
}

impl DirectiveParse {
    /// Returns the message text with the directive removed.
    #[must_use]
    pub fn cleaned(&self) -> &str {
        &self.cleaned
    }

    /// Returns whether the directive was present at all.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Returns the raw level token as the sender typed it.
    #[must_use]
    pub fn raw_level(&self) -> Option<&str> {
        self.raw_level.as_deref()
    }

    /// Returns the normalized level, absent when the raw token is unrecognized.
    #[must_use]
    pub const fn level(&self) -> Option<DirectiveLevel> {
        self.level
    }

    fn absent(body: &str) -> Self {
        Self {
            cleaned: js_trim(body).to_owned(),
            present: false,
            raw_level: None,
            level: None,
        }
    }
}

/// The outcome of extracting `/exec` and its options.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields are the columns of the pinned `exec.golden` table, one `invalid_*` flag \
              per option key; collapsing them would decouple the type from the fixture it is \
              checked against"
)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecDirectiveParse {
    cleaned: String,
    present: bool,
    host: Option<String>,
    security: Option<String>,
    ask: Option<String>,
    node: Option<String>,
    raw_host: Option<String>,
    raw_security: Option<String>,
    raw_ask: Option<String>,
    raw_node: Option<String>,
    has_options: bool,
    invalid_host: bool,
    invalid_security: bool,
    invalid_ask: bool,
    invalid_node: bool,
}

impl ExecDirectiveParse {
    /// Returns the message text with the consumed options removed.
    #[must_use]
    pub fn cleaned(&self) -> &str {
        &self.cleaned
    }

    /// Returns whether `/exec` was present.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Returns the normalized `host=` value.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Returns the normalized `security=` value.
    #[must_use]
    pub fn security(&self) -> Option<&str> {
        self.security.as_deref()
    }

    /// Returns the normalized `ask=` value.
    #[must_use]
    pub fn ask(&self) -> Option<&str> {
        self.ask.as_deref()
    }

    /// Returns the `node=` value.
    #[must_use]
    pub fn node(&self) -> Option<&str> {
        self.node.as_deref()
    }

    /// Returns the raw `host=` value as typed.
    #[must_use]
    pub fn raw_host(&self) -> Option<&str> {
        self.raw_host.as_deref()
    }

    /// Returns the raw `security=` value as typed.
    #[must_use]
    pub fn raw_security(&self) -> Option<&str> {
        self.raw_security.as_deref()
    }

    /// Returns the raw `ask=` value as typed.
    #[must_use]
    pub fn raw_ask(&self) -> Option<&str> {
        self.raw_ask.as_deref()
    }

    /// Returns the raw `node=` value as typed.
    #[must_use]
    pub fn raw_node(&self) -> Option<&str> {
        self.raw_node.as_deref()
    }

    /// Returns whether any recognized option key was seen.
    #[must_use]
    pub const fn has_options(&self) -> bool {
        self.has_options
    }

    /// Returns whether `host=` carried an unrecognized value.
    #[must_use]
    pub const fn invalid_host(&self) -> bool {
        self.invalid_host
    }

    /// Returns whether `security=` carried an unrecognized value.
    #[must_use]
    pub const fn invalid_security(&self) -> bool {
        self.invalid_security
    }

    /// Returns whether `ask=` carried an unrecognized value.
    #[must_use]
    pub const fn invalid_ask(&self) -> bool {
        self.invalid_ask
    }

    /// Returns whether `node=` carried an empty value.
    #[must_use]
    pub const fn invalid_node(&self) -> bool {
        self.invalid_node
    }
}

/// A located directive match, mirroring the JavaScript match object.
struct DirectiveMatch {
    /// Byte offset of `match.index`, which includes the leading separator.
    start: usize,
    /// Byte offset of the `/` that opens the directive.
    slash: usize,
    /// Byte offset just past `match[0]`.
    end: usize,
}

/// Ports `compileDirectivePattern(...).exec(body)` without a regex engine.
fn find_directive(body: &str, names: &[&str]) -> Option<DirectiveMatch> {
    for (index, character) in body.char_indices() {
        if character != '/' {
            continue;
        }
        let start = if index == 0 {
            0
        } else {
            let previous = body[..index].chars().next_back()?;
            if !is_js_space(previous) {
                continue;
            }
            index - previous.len_utf8()
        };
        let after = index + 1;
        for name in names {
            let Some(candidate) = body.get(after..after + name.len()) else {
                continue;
            };
            if !candidate.eq_ignore_ascii_case(name) {
                continue;
            }
            let boundary = after + name.len();
            let follows = body[boundary..].chars().next();
            match follows {
                None => {}
                Some(character) if is_js_space(character) || character == ':' => {}
                Some(_) => continue,
            }
            return Some(DirectiveMatch {
                start,
                slash: index,
                end: boundary,
            });
        }
    }
    None
}

/// Ports the `(?:\s*:\s*)?` suffix `/status` carries after its lookahead.
fn extend_optional_colon_suffix(body: &str, end: usize) -> usize {
    let remainder = &body[end..];
    let spaces = leading_space_len(remainder);
    let Some(after_colon) = remainder[spaces..].strip_prefix(':') else {
        return end;
    };
    end + spaces + 1 + leading_space_len(after_colon)
}

struct LevelMatch {
    start: usize,
    end: usize,
    raw_level: Option<String>,
}

/// Ports `matchLevelDirective`.
fn match_level_directive(
    body: &str,
    names: &[&str],
    normalize: fn(&str) -> Option<DirectiveLevel>,
) -> Option<LevelMatch> {
    let matched = find_directive(body, names)?;
    let mut index = matched.end;
    index += leading_space_len(&body[index..]);
    if body[index..].starts_with(':') {
        index += 1;
        index += leading_space_len(&body[index..]);
    }
    let arg_start = index;
    while let Some(character) = body[index..].chars().next() {
        if character.is_ascii_alphabetic() || character == '-' {
            index += character.len_utf8();
        } else {
            break;
        }
    }
    let candidate = (index > arg_start).then(|| &body[arg_start..index]);
    if let Some(candidate) = candidate
        && (normalize(candidate).is_some() || js_trim(&body[index..]).is_empty())
    {
        return Some(LevelMatch {
            start: matched.start,
            end: index,
            raw_level: Some(candidate.to_owned()),
        });
    }
    Some(LevelMatch {
        start: matched.start,
        end: arg_start,
        raw_level: None,
    })
}

/// Ports `extractLevelDirective`.
fn extract_level_directive(
    body: &str,
    names: &[&str],
    normalize: fn(&str) -> Option<DirectiveLevel>,
) -> DirectiveParse {
    let Some(matched) = match_level_directive(body, names, normalize) else {
        return DirectiveParse::absent(body);
    };
    let joined = format!("{} {}", &body[..matched.start], &body[matched.end..]);
    let level = matched.raw_level.as_deref().and_then(normalize);
    DirectiveParse {
        cleaned: js_trim(&collapse_js_whitespace(&joined)).to_owned(),
        present: true,
        raw_level: matched.raw_level,
        level,
    }
}

/// Ports `extractSimpleDirective`, including its first-occurrence replacement.
fn extract_simple_directive(body: &str, names: &[&str]) -> DirectiveParse {
    let Some(matched) = find_directive(body, names) else {
        return DirectiveParse::absent(body);
    };
    let end = extend_optional_colon_suffix(body, matched.end);
    let text = &body[matched.start..end];
    // `String.prototype.replace(string, " ")` rewrites the first occurrence found
    // by `indexOf`, which is not necessarily the occurrence the regex matched.
    let position = body.find(text).unwrap_or(matched.start);
    let joined = format!("{} {}", &body[..position], &body[position + text.len()..]);
    DirectiveParse {
        cleaned: js_trim(&collapse_js_whitespace(&joined)).to_owned(),
        present: true,
        raw_level: None,
        level: None,
    }
}

/// Extracts one directive from a message body.
///
/// [`Directive::Exec`] is reported without its options; use
/// [`extract_exec_directive`] when the options are needed.
#[must_use]
pub fn extract_directive(directive: Directive, body: &str) -> DirectiveParse {
    match directive {
        Directive::Think => extract_level_directive(body, directive.names(), normalize_think_level),
        Directive::Verbose => {
            extract_level_directive(body, directive.names(), normalize_verbose_level)
        }
        Directive::Trace => extract_level_directive(body, directive.names(), normalize_trace_level),
        Directive::Fast => extract_level_directive(body, directive.names(), normalize_fast_mode),
        Directive::Elevated => {
            extract_level_directive(body, directive.names(), normalize_elevated_level)
        }
        Directive::Reasoning => {
            extract_level_directive(body, directive.names(), normalize_reasoning_level)
        }
        Directive::Status => extract_simple_directive(body, directive.names()),
        Directive::Exec => {
            let exec = extract_exec_directive(body);
            DirectiveParse {
                cleaned: exec.cleaned,
                present: exec.present,
                raw_level: None,
                level: None,
            }
        }
    }
}

/// Extracts a directive only when the sender may use directives.
///
/// `docs/tools/slash-commands.md`: "Directives only apply for authorized
/// senders. ... Unauthorized senders see directives treated as plain text."
/// The message body is therefore returned untouched apart from trimming.
#[must_use]
pub fn extract_directive_for_sender(
    directive: Directive,
    body: &str,
    sender_is_authorized: bool,
) -> DirectiveParse {
    if sender_is_authorized {
        extract_directive(directive, body)
    } else {
        DirectiveParse::absent(body)
    }
}

/// Ports `skipDirectiveArgPrefix`.
fn skip_directive_arg_prefix(raw: &str) -> usize {
    let mut index = leading_space_len(raw);
    if raw[index..].starts_with(':') {
        index += 1;
        index += leading_space_len(&raw[index..]);
    }
    index
}

/// Ports `takeDirectiveToken`.
fn take_directive_token(raw: &str, start_index: usize) -> (Option<&str>, usize) {
    let mut index = start_index + leading_space_len(&raw[start_index..]);
    if index >= raw.len() {
        return (None, index);
    }
    let start = index;
    while let Some(character) = raw[index..].chars().next() {
        if is_js_space(character) {
            break;
        }
        index += character.len_utf8();
    }
    if start == index {
        return (None, index);
    }
    let token = &raw[start..index];
    index += leading_space_len(&raw[index..]);
    (Some(token), index)
}

/// Splits an `/exec` option token on the first `=` or `:`.
fn split_exec_token(token: &str) -> Option<(String, &str)> {
    let equals = token.find('=');
    let colon = token.find(':');
    let separator = match (equals, colon) {
        (None, None) => return None,
        (Some(index), None) | (None, Some(index)) => index,
        (Some(left), Some(right)) => left.min(right),
    };
    let key = super::text::normalize_optional_lowercase(&token[..separator])?;
    Some((key, js_trim(&token[separator + 1..])))
}

fn normalize_exec_host(value: &str) -> Option<String> {
    match super::text::normalize_optional_lowercase(value)?.as_str() {
        normalized @ ("auto" | "sandbox" | "gateway" | "node") => Some(normalized.to_owned()),
        _ => None,
    }
}

fn normalize_exec_security(value: &str) -> Option<String> {
    match super::text::normalize_optional_lowercase(value)?.as_str() {
        normalized @ ("deny" | "allowlist" | "full") => Some(normalized.to_owned()),
        _ => None,
    }
}

fn normalize_exec_ask(value: &str) -> Option<String> {
    match super::text::normalize_optional_lowercase(value)?.as_str() {
        normalized @ ("off" | "on-miss" | "always") => Some(normalized.to_owned()),
        _ => None,
    }
}

/// Ports `extractExecDirective`.
///
/// Upstream computes the slice offset with a case-sensitive
/// `match[0].indexOf("/exec")`, which returns `-1` for `/EXEC` and mis-slices the
/// body even though the pattern itself is case-insensitive. This port takes the
/// offset from the match, so `/EXEC` behaves like `/exec`; every lowercase input
/// is unaffected.
#[must_use]
pub fn extract_exec_directive(body: &str) -> ExecDirectiveParse {
    let Some(matched) = find_directive(body, Directive::Exec.names()) else {
        return ExecDirectiveParse {
            cleaned: js_trim(body).to_owned(),
            ..ExecDirectiveParse::default()
        };
    };

    let start = matched.slash;
    let args_start = start + "/exec".len();
    let raw = &body[args_start..];

    let mut index = skip_directive_arg_prefix(raw);
    let mut consumed = index;
    let mut parsed = ExecDirectiveParse {
        present: true,
        ..ExecDirectiveParse::default()
    };

    loop {
        if index >= raw.len() {
            break;
        }
        let (token, next_index) = take_directive_token(raw, index);
        index = next_index;
        let Some(token) = token else {
            break;
        };
        let Some((key, value)) = split_exec_token(token) else {
            break;
        };
        match key.as_str() {
            "host" => {
                parsed.raw_host = Some(value.to_owned());
                parsed.host = normalize_exec_host(value);
                parsed.invalid_host = parsed.host.is_none();
            }
            "security" => {
                parsed.raw_security = Some(value.to_owned());
                parsed.security = normalize_exec_security(value);
                parsed.invalid_security = parsed.security.is_none();
            }
            "ask" => {
                parsed.raw_ask = Some(value.to_owned());
                parsed.ask = normalize_exec_ask(value);
                parsed.invalid_ask = parsed.ask.is_none();
            }
            "node" => {
                parsed.raw_node = Some(value.to_owned());
                let trimmed = js_trim(value);
                if trimmed.is_empty() {
                    parsed.invalid_node = true;
                } else {
                    parsed.node = Some(trimmed.to_owned());
                }
            }
            _ => break,
        }
        parsed.has_options = true;
        consumed = index;
    }

    let joined = format!("{} {}", &body[..start], &raw[consumed..]);
    js_trim(&collapse_js_whitespace(&joined)).clone_into(&mut parsed.cleaned);
    parsed
}

/// Ports `normalizeThinkLevel`.
#[must_use]
pub fn normalize_think_level(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_optional_lowercase(raw)?;
    let collapsed: String = key
        .chars()
        .filter(|character| !is_js_space(*character) && *character != '_' && *character != '-')
        .collect();
    let level = match collapsed.as_str() {
        "adaptive" | "auto" => Some(ThinkLevel::Adaptive),
        "max" => Some(ThinkLevel::Max),
        "ultra" => Some(ThinkLevel::Ultra),
        "xhigh" | "extrahigh" => Some(ThinkLevel::XHigh),
        _ => None,
    };
    if let Some(level) = level {
        return Some(DirectiveLevel::Think(level));
    }
    let level = match key.as_str() {
        "off" => ThinkLevel::Off,
        // `think` on its own, and the plain on/enable aliases, resolve to the
        // same levels as their explicit spellings upstream.
        "min" | "minimal" | "think" => ThinkLevel::Minimal,
        "on" | "enable" | "enabled" | "low" | "thinkhard" | "think-hard" | "think_hard" => {
            ThinkLevel::Low
        }
        "mid" | "med" | "medium" | "thinkharder" | "think-harder" | "harder" => ThinkLevel::Medium,
        "high" | "ultrathink" | "thinkhardest" | "highest" => ThinkLevel::High,
        _ => return None,
    };
    Some(DirectiveLevel::Think(level))
}

/// Ports `normalizeVerboseLevel` through `normalizeOnOffFullLevel`.
#[must_use]
pub fn normalize_verbose_level(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_optional_lowercase(raw)?;
    let level = match key.as_str() {
        "off" | "false" | "no" | "0" => VerboseLevel::Off,
        "full" | "all" | "everything" => VerboseLevel::Full,
        "on" | "minimal" | "true" | "yes" | "1" => VerboseLevel::On,
        _ => return None,
    };
    Some(DirectiveLevel::Verbose(level))
}

/// Ports `normalizeTraceLevel`.
#[must_use]
pub fn normalize_trace_level(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_optional_lowercase(raw)?;
    let level = match key.as_str() {
        "off" | "false" | "no" | "0" => TraceLevel::Off,
        "on" | "true" | "yes" | "1" => TraceLevel::On,
        "raw" | "unfiltered" => TraceLevel::Raw,
        _ => return None,
    };
    Some(DirectiveLevel::Trace(level))
}

/// Ports `normalizeFastMode`.
#[must_use]
pub fn normalize_fast_mode(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_lowercase_or_empty(raw);
    if key.is_empty() {
        return None;
    }
    let mode = match key.as_str() {
        "off" | "false" | "no" | "0" | "disable" | "disabled" | "normal" => FastMode::Off,
        "on" | "true" | "yes" | "1" | "enable" | "enabled" | "fast" => FastMode::On,
        "auto" | "automatic" => FastMode::Auto,
        _ => return None,
    };
    Some(DirectiveLevel::Fast(mode))
}

/// Ports `normalizeElevatedLevel`.
#[must_use]
pub fn normalize_elevated_level(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_lowercase_or_empty(raw);
    if key.is_empty() {
        return None;
    }
    let level = match key.as_str() {
        "off" | "false" | "no" | "0" => ElevatedLevel::Off,
        "full" | "auto" | "auto-approve" | "autoapprove" => ElevatedLevel::Full,
        "ask" | "prompt" | "approval" | "approve" => ElevatedLevel::Ask,
        "on" | "true" | "yes" | "1" => ElevatedLevel::On,
        _ => return None,
    };
    Some(DirectiveLevel::Elevated(level))
}

/// Ports `normalizeReasoningLevel`.
#[must_use]
pub fn normalize_reasoning_level(raw: &str) -> Option<DirectiveLevel> {
    let key = super::text::normalize_lowercase_or_empty(raw);
    if key.is_empty() {
        return None;
    }
    let level = match key.as_str() {
        "off" | "false" | "no" | "0" | "hide" | "hidden" | "disable" | "disabled" => {
            ReasoningLevel::Off
        }
        "on" | "true" | "yes" | "1" | "show" | "visible" | "enable" | "enabled" => {
            ReasoningLevel::On
        }
        "stream" | "streaming" | "draft" | "live" => ReasoningLevel::Stream,
        _ => return None,
    };
    Some(DirectiveLevel::Reasoning(level))
}

/// Normalizes a raw level token for a directive, returning `None` for `/status`
/// and `/exec`, which carry no level.
#[must_use]
pub fn normalize_level(directive: Directive, raw: &str) -> Option<DirectiveLevel> {
    match directive {
        Directive::Think => normalize_think_level(raw),
        Directive::Verbose => normalize_verbose_level(raw),
        Directive::Trace => normalize_trace_level(raw),
        Directive::Fast => normalize_fast_mode(raw),
        Directive::Elevated => normalize_elevated_level(raw),
        Directive::Reasoning => normalize_reasoning_level(raw),
        Directive::Status | Directive::Exec => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Directive, DirectiveLevel, ThinkLevel, extract_directive, extract_directive_for_sender,
        extract_exec_directive, find_directive, normalize_think_level,
    };

    #[test]
    fn a_directive_must_start_at_a_whitespace_boundary() {
        assert!(find_directive("x/think", &["think"]).is_none());
        assert!(find_directive("/think", &["think"]).is_some());
        assert!(find_directive("a /think", &["think"]).is_some());
        assert!(find_directive("a\u{00a0}/think", &["think"]).is_some());
    }

    #[test]
    fn the_first_alternative_whose_boundary_holds_wins() {
        let matched = find_directive("/thinking", Directive::Think.names()).expect("matches");
        assert_eq!(matched.end, "/thinking".len());

        let matched = find_directive("/t", Directive::Think.names()).expect("matches");
        assert_eq!(matched.end, "/t".len());

        assert!(find_directive("/thinkings", Directive::Think.names()).is_none());
        assert!(find_directive("/thin", Directive::Think.names()).is_none());
    }

    #[test]
    fn the_leading_separator_is_consumed_with_the_directive() {
        let parsed = extract_directive(Directive::Think, "please /think high answer me");

        assert!(parsed.present());
        assert_eq!(parsed.cleaned(), "please answer me");
        assert_eq!(parsed.raw_level(), Some("high"));
        assert_eq!(
            parsed.level(),
            Some(DirectiveLevel::Think(ThinkLevel::High))
        );
    }

    #[test]
    fn an_unrecognized_level_is_kept_as_message_text_when_more_text_follows() {
        let parsed = extract_directive(Directive::Think, "/think banana about it");

        assert!(parsed.present());
        assert_eq!(parsed.raw_level(), None);
        assert_eq!(parsed.level(), None);
        assert_eq!(parsed.cleaned(), "banana about it");
    }

    #[test]
    fn a_trailing_unrecognized_level_is_still_captured_as_raw() {
        let parsed = extract_directive(Directive::Think, "/think banana");

        assert_eq!(parsed.raw_level(), Some("banana"));
        assert_eq!(parsed.level(), None);
        assert_eq!(parsed.cleaned(), "");
    }

    #[test]
    fn unauthorized_senders_see_directives_as_plain_text() {
        let authorized = extract_directive_for_sender(Directive::Think, " /think high hi ", true);
        let plain = extract_directive_for_sender(Directive::Think, " /think high hi ", false);

        assert!(authorized.present());
        assert_eq!(authorized.cleaned(), "hi");
        assert!(!plain.present());
        assert_eq!(plain.cleaned(), "/think high hi");
    }

    #[test]
    fn exec_consumes_only_recognized_options() {
        let parsed = extract_exec_directive("/exec host=sandbox ask=always run the build");

        assert!(parsed.present());
        assert!(parsed.has_options());
        assert_eq!(parsed.host(), Some("sandbox"));
        assert_eq!(parsed.ask(), Some("always"));
        assert_eq!(parsed.cleaned(), "run the build");
        assert!(!parsed.invalid_host());
    }

    #[test]
    fn think_level_synonyms_normalize_to_the_pinned_enum() {
        assert_eq!(
            normalize_think_level("AUTO"),
            Some(DirectiveLevel::Think(ThinkLevel::Adaptive))
        );
        assert_eq!(
            normalize_think_level("extra high"),
            Some(DirectiveLevel::Think(ThinkLevel::XHigh))
        );
        assert_eq!(
            normalize_think_level("think-hard"),
            Some(DirectiveLevel::Think(ThinkLevel::Low))
        );
        assert_eq!(normalize_think_level("nope"), None);
    }
}
