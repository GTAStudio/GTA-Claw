//! Bounded outbound text segmentation.
//!
//! Providers cap one message at a fixed length. A reply longer than that cap is
//! not truncated here and is never guessed at: segmentation happens only when a
//! destination has declared a limit it can prove, and refuses with
//! [`SegmentationError::NoDeclaredLimit`] otherwise. An invented limit would
//! silently drop the tail of a user's message, which is worse than refusing to
//! send it.
//!
//! The segmenter is transport-neutral. It knows the counting unit, the cluster
//! rules and the preferred break order; it knows nothing about HTTP, providers,
//! or credentials.

use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroU32;

/// Zero-width joiner, which binds the characters on both of its sides.
const ZERO_WIDTH_JOINER: char = '\u{200d}';

/// Unit a destination counts its message length in.
///
/// This is not cosmetic. The same string is 1 character, 2 UTF-16 code units
/// and 4 UTF-8 bytes when it is a single astral-plane emoji, so measuring in
/// the wrong unit either wastes a third of the budget or overruns the provider
/// cap and gets the message rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthUnit {
    /// Unicode scalar values, the unit Rust's [`char`] counts in.
    Chars,
    /// UTF-16 code units, the unit JavaScript's `String.length` counts in.
    Utf16CodeUnits,
    /// UTF-8 bytes.
    Bytes,
}

impl LengthUnit {
    /// Returns the cost of one character in this unit.
    #[must_use]
    pub const fn measure_char(self, character: char) -> u64 {
        match self {
            Self::Chars => 1,
            Self::Utf16CodeUnits => character.len_utf16() as u64,
            Self::Bytes => character.len_utf8() as u64,
        }
    }

    /// Returns the length of `text` in this unit.
    #[must_use]
    pub fn measure(self, text: &str) -> u64 {
        match self {
            Self::Chars => text.chars().count() as u64,
            Self::Utf16CodeUnits => text.chars().map(char::len_utf16).sum::<usize>() as u64,
            Self::Bytes => text.len() as u64,
        }
    }
}

impl Display for LengthUnit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Chars => "characters",
            Self::Utf16CodeUnits => "UTF-16 code units",
            Self::Bytes => "bytes",
        })
    }
}

/// One destination's proven maximum outbound message length.
///
/// A value of this type is an assertion that the number and the unit were both
/// taken from a source in this repository. Constructing one from a guess
/// defeats the entire point of the type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputLimit {
    max: NonZeroU32,
    unit: LengthUnit,
}

impl OutputLimit {
    /// Declares a limit of `max` units of `unit`.
    #[must_use]
    pub const fn new(max: NonZeroU32, unit: LengthUnit) -> Self {
        Self { max, unit }
    }

    /// Returns the maximum length of one message.
    #[must_use]
    pub const fn max(self) -> NonZeroU32 {
        self.max
    }

    /// Returns the unit the maximum is counted in.
    #[must_use]
    pub const fn unit(self) -> LengthUnit {
        self.unit
    }

    /// Returns whether `text` is deliverable as exactly one message.
    ///
    /// Callers use this to keep the common short-message path allocation-free:
    /// a message that fits needs no segment vector and no owned segment.
    #[must_use]
    pub fn fits(self, text: &str) -> bool {
        let max = u64::from(self.max.get());
        // A UTF-8 byte count is an upper bound for both other units, so a
        // string that fits by bytes fits by any unit without a second scan.
        text.len() as u64 <= max || self.unit.measure(text) <= max
    }
}

/// Why outbound text could not be segmented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentationError {
    /// The destination has no proven output limit, so no split is defensible.
    NoDeclaredLimit,
    /// The limit is smaller than the markers needed to continue a code fence.
    LimitTooSmall,
    /// A single indivisible cluster is longer than the whole limit.
    ///
    /// Splitting it would corrupt the text, so it is refused instead.
    IndivisibleCluster,
}

impl Display for SegmentationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoDeclaredLimit => "destination has no declared output limit",
            Self::LimitTooSmall => "destination output limit is too small to segment",
            Self::IndivisibleCluster => "text contains a cluster longer than the output limit",
        })
    }
}

impl Error for SegmentationError {}

/// Splits `text` into segments that each fit `limit`.
///
/// # Break order
///
/// Within the budget the last newline is preferred, then the last space, then a
/// hard cut. A newline is only taken when it falls at or past half the budget
/// and a space only at or past three tenths of it, because an earlier break
/// wastes more of the message than the ragged edge costs. This is the ported
/// behavior of the legacy `src/utils/splitMessage.ts`, recorded as
/// `behavior.message.split` in `compat/legacy/ledger/behaviors.json`. The break
/// character itself is dropped: it becomes leading whitespace of the remainder
/// and is trimmed, exactly as the legacy `slice`/`trimStart` pair did.
///
/// # Cluster safety
///
/// Segments are cut on [`char`] boundaries, so a multi-byte UTF-8 sequence can
/// never be torn. On top of that this std-only implementation refuses to cut
/// inside these classes, which is what makes emoji and accented text survive:
///
/// - combining marks in the generic blocks U+0300–U+036F, U+1AB0–U+1AFF,
///   U+1DC0–U+1DFF, U+20D0–U+20F0 and U+FE20–U+FE2F, plus the Cyrillic, Hebrew,
///   Arabic and Thai mark ranges;
/// - variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) and tag characters
///   (U+E0020–U+E007F), so `❤️` and subdivision flags stay intact;
/// - zero-width joiner and non-joiner runs, in both directions, so an emoji ZWJ
///   sequence such as a family emoji is never broken apart;
/// - emoji modifiers U+1F3FB–U+1F3FF, so a skin tone stays on its base;
/// - regional indicator pairs, using the even/odd run rule, so a flag is never
///   split into two letters and two adjacent flags still break between them;
/// - a CRLF pair, and conjoining Hangul V and T jamo.
///
/// What it does **not** preserve, because std ships no Unicode segmentation
/// data and this crate may not add a dependency for it: Indic clusters
/// (Devanagari, Bengali, Tamil and friends — viramas, conjuncts and vowel
/// signs), Lao, Tibetan, Myanmar and Khmer marks, the `Prepend` class, and any
/// combining character assigned to a block not listed above or added to Unicode
/// after this table was written. Those cut like ordinary characters. This is a
/// documented approximation of UAX #29, not an implementation of it.
///
/// # Fenced code
///
/// A break that would land inside a fenced code block is moved back to just
/// before the fence, so the block travels whole in the next segment. When the
/// block is itself longer than the limit that is impossible, so the segment is
/// closed with the fence marker and the next segment re-opens the fence with
/// the same marker and info string. The fence markers are charged to the
/// budget, so both halves still fit. This means the concatenation of the
/// segments is not byte-identical to `text` when a fence had to be reopened;
/// that is the deliberate cost of the second half still rendering as code.
/// Inside a fence the remainder is not left-trimmed either, because that would
/// eat the indentation of the continued code line.
///
/// # Errors
///
/// - [`SegmentationError::NoDeclaredLimit`] when `limit` is [`None`]. This is
///   the whole reason the argument is an [`Option`]: a destination whose limit
///   this repository cannot prove must refuse rather than pick a number.
/// - [`SegmentationError::IndivisibleCluster`] when no cut point inside the
///   budget preserves the cluster rules above, which happens when a single
///   combining or ZWJ run is longer than the entire limit.
/// - [`SegmentationError::LimitTooSmall`] when the limit cannot even carry the
///   fence markers needed to continue a code block.
pub fn segment_text(
    text: &str,
    limit: Option<OutputLimit>,
) -> Result<Vec<Cow<'_, str>>, SegmentationError> {
    let limit = limit.ok_or(SegmentationError::NoDeclaredLimit)?;
    let mut segments = Vec::new();
    let mut remaining = text;
    let mut carry = None;
    while !remaining.is_empty() {
        let step = next_segment(remaining, limit, carry)?;
        segments.push(step.segment);
        carry = step.carry;
        remaining = step.rest;
    }
    Ok(segments)
}

/// One code fence, borrowed from the text that opened it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fence<'a> {
    marker: &'a str,
    info: &'a str,
}

impl Fence<'_> {
    /// Returns the cost of re-opening this fence at the start of a segment.
    fn reopen_units(&self, unit: LengthUnit) -> u64 {
        unit.measure(self.marker) + unit.measure(self.info) + 1
    }

    /// Returns the cost of closing this fence at the end of a segment.
    fn close_units(&self, unit: LengthUnit) -> u64 {
        unit.measure(self.marker) + 1
    }
}

/// A fence that is open at some offset, and where it was opened.
///
/// `line_start` is [`None`] when the fence was inherited from a previous
/// segment, which is exactly the case where the split cannot be moved before
/// the fence.
#[derive(Clone, Copy, Debug)]
struct OpenFence<'a> {
    fence: Fence<'a>,
    line_start: Option<usize>,
}

/// One emitted segment plus the state needed for the next one.
struct Step<'a> {
    segment: Cow<'a, str>,
    carry: Option<Fence<'a>>,
    rest: &'a str,
}

fn next_segment<'a>(
    text: &'a str,
    limit: OutputLimit,
    carry: Option<Fence<'a>>,
) -> Result<Step<'a>, SegmentationError> {
    let unit = limit.unit();
    let max = u64::from(limit.max().get());
    let reopen = carry.map_or(0, |fence| fence.reopen_units(unit));
    let available = max
        .checked_sub(reopen)
        .filter(|budget| *budget > 0)
        .ok_or(SegmentationError::LimitTooSmall)?;

    let mut reserve = 0;
    loop {
        let budget = available - reserve;
        let window = scan_window(text, unit, budget);
        if reserve == 0 && window.fits {
            return Ok(Step {
                segment: build_segment(text, carry, None),
                carry: None,
                rest: "",
            });
        }
        if window.ceiling == 0 {
            return Err(SegmentationError::IndivisibleCluster);
        }

        let (split, closing) = place_split(text, &window, budget, carry);
        let close_cost = closing.map_or(0, |fence| fence.close_units(unit));
        if close_cost > reserve {
            if close_cost >= available {
                return Err(SegmentationError::LimitTooSmall);
            }
            reserve = close_cost;
            continue;
        }

        let rest = &text[split..];
        return Ok(Step {
            segment: build_segment(&text[..split], carry, closing),
            carry: closing,
            rest: if closing.is_some() {
                strip_one_newline(rest)
            } else {
                rest.trim_start()
            },
        });
    }
}

/// Chooses the cut offset and reports the fence left open at it, if any.
fn place_split<'a>(
    text: &'a str,
    window: &Window,
    budget: u64,
    carry: Option<Fence<'a>>,
) -> (usize, Option<Fence<'a>>) {
    let split = choose_break(window, budget);
    let Some(open) = fence_open_at(text, split, carry) else {
        return (split, None);
    };
    // Moving the cut to just before the opening fence keeps the whole block in
    // the next segment. It is only possible when the fence starts inside this
    // segment and something precedes it, otherwise the block must be cut and
    // reopened.
    match open.line_start {
        Some(line_start) if line_start >= 2 && text.as_bytes()[line_start - 1] == b'\n' => {
            (line_start - 1, None)
        }
        _ => (split, Some(open.fence)),
    }
}

/// Everything one bounded scan of the remaining text can decide.
#[derive(Clone, Copy, Debug, Default)]
struct Window {
    /// The whole text fits in the budget.
    fits: bool,
    /// Largest cluster-safe offset whose prefix fits the budget; 0 means none.
    ceiling: usize,
    /// Last newline inside the window, with the length of the text before it.
    last_newline: Option<(usize, u64)>,
    /// Last space inside the window, with the length of the text before it.
    last_space: Option<(usize, u64)>,
}

fn scan_window(text: &str, unit: LengthUnit, budget: u64) -> Window {
    let mut window = Window::default();
    let mut units = 0;
    let mut previous = None;
    let mut regional_run = 0_usize;
    for (offset, character) in text.char_indices() {
        if units > budget {
            return window;
        }
        if offset > 0 && is_cluster_boundary(previous, character, regional_run) {
            window.ceiling = offset;
            match character {
                '\n' => window.last_newline = Some((offset, units)),
                ' ' => window.last_space = Some((offset, units)),
                _ => {}
            }
        }
        units += unit.measure_char(character);
        previous = Some(character);
        regional_run = if is_regional_indicator(character) {
            regional_run + 1
        } else {
            0
        };
    }
    if units <= budget {
        window.fits = true;
        window.ceiling = text.len();
    }
    window
}

/// Applies the legacy newline-then-space-then-hard-cut preference.
///
/// The fractions are the legacy `maxLength * 0.5` and `maxLength * 0.3` tests,
/// rewritten as exact integer comparisons so no rounding can move a boundary.
const fn choose_break(window: &Window, budget: u64) -> usize {
    if let Some((offset, units)) = window.last_newline
        && units * 2 >= budget
    {
        return offset;
    }
    if let Some((offset, units)) = window.last_space
        && units * 10 >= budget * 3
    {
        return offset;
    }
    window.ceiling
}

fn build_segment<'a>(
    body: &'a str,
    open: Option<Fence<'_>>,
    close: Option<Fence<'_>>,
) -> Cow<'a, str> {
    if open.is_none() && close.is_none() {
        return Cow::Borrowed(body);
    }
    let extra = open.map_or(0, |fence| fence.marker.len() + fence.info.len() + 1)
        + close.map_or(0, |fence| fence.marker.len() + 1);
    let mut segment = String::with_capacity(body.len() + extra);
    if let Some(fence) = open {
        segment.push_str(fence.marker);
        segment.push_str(fence.info);
        segment.push('\n');
    }
    segment.push_str(body);
    if let Some(fence) = close {
        if !segment.ends_with('\n') {
            segment.push('\n');
        }
        segment.push_str(fence.marker);
    }
    Cow::Owned(segment)
}

/// Removes exactly one line ending, preserving code indentation after it.
fn strip_one_newline(text: &str) -> &str {
    text.strip_prefix("\r\n")
        .or_else(|| text.strip_prefix('\n'))
        .unwrap_or(text)
}

/// Returns the fence still open at `offset`, scanning whole lines.
///
/// A fence is treated as open from the first byte of its opening line to the
/// last byte of its closing line, so a cut can never land inside a marker.
fn fence_open_at<'a>(
    text: &'a str,
    offset: usize,
    carry: Option<Fence<'a>>,
) -> Option<OpenFence<'a>> {
    let mut open = carry.map(|fence| OpenFence {
        fence,
        line_start: None,
    });
    let mut line_start = 0;
    while line_start < offset {
        let line_end = text[line_start..]
            .find('\n')
            .map_or(text.len(), |index| line_start + index);
        let line = &text[line_start..line_end];
        match open {
            None => {
                if let Some(fence) = opening_fence(line) {
                    open = Some(OpenFence {
                        fence,
                        line_start: Some(line_start),
                    });
                }
            }
            Some(state) => {
                if line_end <= offset && closes_fence(line, state.fence.marker) {
                    open = None;
                }
            }
        }
        line_start = line_end + 1;
    }
    open
}

/// Parses a line that opens a fenced code block: three or more backticks or
/// tildes, indented by at most three spaces.
fn opening_fence(line: &str) -> Option<Fence<'_>> {
    let line = line.trim_end_matches('\r');
    let content = line.trim_start_matches(' ');
    // Four or more leading spaces is an indented code block, not a fence.
    if line.len() - content.len() > 3 {
        return None;
    }
    let character = content.chars().next()?;
    if character != '`' && character != '~' {
        return None;
    }
    let rest = content.trim_start_matches(character);
    let run = content.len() - rest.len();
    if run < 3 {
        return None;
    }
    let info = rest.trim();
    // A backtick fence may not carry a backtick in its info string.
    if character == '`' && info.contains('`') {
        return None;
    }
    Some(Fence {
        marker: &content[..run],
        info,
    })
}

/// Returns whether a line closes a fence opened with `marker`.
fn closes_fence(line: &str, marker: &str) -> bool {
    let line = line.trim_end_matches('\r');
    let content = line.trim_start_matches(' ');
    if line.len() - content.len() > 3 {
        return false;
    }
    let Some(character) = marker.chars().next() else {
        return false;
    };
    let rest = content.trim_start_matches(character);
    content.len() - rest.len() >= marker.len() && rest.trim().is_empty()
}

/// Returns whether a segment may end immediately before `next`.
fn is_cluster_boundary(previous: Option<char>, next: char, regional_run: usize) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    if previous == ZERO_WIDTH_JOINER || (previous == '\r' && next == '\n') {
        return false;
    }
    if binds_to_previous(next) {
        return false;
    }
    // Two regional indicators are one flag, four are two flags: a break is only
    // legal when an even number of them precedes this one.
    !(is_regional_indicator(next) && regional_run % 2 == 1)
}

const fn is_regional_indicator(character: char) -> bool {
    matches!(character, '\u{1f1e6}'..='\u{1f1ff}')
}

/// Returns whether `character` must stay attached to the character before it.
///
/// The exact coverage and the deliberate gaps are documented on
/// [`segment_text`]. Unassigned code points inside a listed combining block are
/// included on purpose: they are reserved for future marks, and refusing to cut
/// there is the conservative direction.
fn binds_to_previous(character: char) -> bool {
    matches!(
        u32::from(character),
        // Combining Diacritical Marks.
        0x0300..=0x036f
        // Cyrillic combining marks.
        | 0x0483..=0x0489
        // Hebrew points and accents.
        | 0x0591..=0x05bd | 0x05bf | 0x05c1..=0x05c2 | 0x05c4..=0x05c5 | 0x05c7
        // Arabic marks.
        | 0x0610..=0x061a | 0x064b..=0x065f | 0x0670
        | 0x06d6..=0x06dc | 0x06df..=0x06e4 | 0x06e7..=0x06e8 | 0x06ea..=0x06ed
        // Thai vowel signs and tone marks.
        | 0x0e31 | 0x0e34..=0x0e3a | 0x0e47..=0x0e4e
        // Conjoining Hangul V and T jamo, including the extended blocks.
        | 0x1160..=0x11ff | 0xd7b0..=0xd7c6 | 0xd7cb..=0xd7fb
        // Zero-width non-joiner and joiner.
        | 0x200c..=0x200d
        // Combining Diacritical Marks Extended and Supplement.
        | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff
        // Combining Diacritical Marks for Symbols, including the keycap.
        | 0x20d0..=0x20f0
        // Variation selectors and Combining Half Marks.
        | 0xfe00..=0xfe0f | 0xfe20..=0xfe2f
        // Emoji modifiers, the skin tones.
        | 0x1f3fb..=0x1f3ff
        // Tag characters and the variation selector supplement.
        | 0xe0020..=0xe007f | 0xe0100..=0xe01ef
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(max: u32, unit: LengthUnit) -> OutputLimit {
        OutputLimit::new(NonZeroU32::new(max).expect("non-zero test limit"), unit)
    }

    fn chars(max: u32) -> OutputLimit {
        limit(max, LengthUnit::Chars)
    }

    fn segments(text: &str, limit: OutputLimit) -> Vec<String> {
        segment_text(text, Some(limit))
            .expect("segmentable text")
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    /// The legacy `src/utils/splitMessage.ts` algorithm, verbatim, over UTF-16.
    ///
    /// It exists only to prove the port: for fence-free text this Rust
    /// implementation must agree with it exactly.
    fn legacy_split(text: &str, max_length: usize) -> Vec<String> {
        let units = text.encode_utf16().collect::<Vec<_>>();
        let index_of = |haystack: &[u16], needle: u16, from: usize| -> Option<usize> {
            haystack
                .iter()
                .take(from.min(haystack.len().saturating_sub(1)) + 1)
                .rposition(|unit| *unit == needle)
        };
        let decode = |slice: &[u16]| String::from_utf16(slice).expect("valid UTF-16 slice");
        if units.len() <= max_length {
            return vec![decode(&units)];
        }
        let mut chunks = Vec::new();
        let mut remaining = units;
        // `lastIndexOf` returning -1 is modelled as `None`, which is below
        // every fraction of a non-zero limit exactly as -1 was.
        #[expect(
            clippy::cast_precision_loss,
            reason = "the oracle must reproduce the legacy float comparison, including its rounding"
        )]
        let below = |value: Option<usize>, fraction: f64| {
            value.is_none_or(|index| (index as f64) < (max_length as f64) * fraction)
        };
        while !remaining.is_empty() {
            if remaining.len() <= max_length {
                chunks.push(decode(&remaining));
                break;
            }
            let mut split = index_of(&remaining, u16::from(b'\n'), max_length);
            if below(split, 0.5) {
                split = index_of(&remaining, u16::from(b' '), max_length);
            }
            let split = if below(split, 0.3) {
                max_length
            } else {
                split.expect("a break at or past three tenths of the limit")
            };
            chunks.push(decode(&remaining[..split]));
            remaining = remaining.split_off(split);
            while remaining
                .first()
                .and_then(|unit| char::from_u32(u32::from(*unit)))
                .is_some_and(char::is_whitespace)
            {
                remaining.remove(0);
            }
        }
        chunks
    }

    #[test]
    fn an_absent_limit_refuses_instead_of_guessing_one() {
        assert_eq!(
            segment_text("anything at all", None),
            Err(SegmentationError::NoDeclaredLimit)
        );
    }

    #[test]
    fn text_of_exactly_the_limit_is_one_segment() {
        let text = "a".repeat(10);
        assert_eq!(segments(&text, chars(10)), vec![text.clone()]);
        assert_eq!(segments(&format!("{text}b"), chars(10)).len(), 2);
    }

    #[test]
    fn a_borrowed_single_segment_allocates_no_string() {
        let text = "short enough";
        let produced = segment_text(text, Some(chars(64))).expect("segmentable text");
        assert!(matches!(produced.as_slice(), [Cow::Borrowed(borrowed)] if *borrowed == text));
    }

    #[test]
    fn empty_text_produces_no_segment_at_all() {
        assert!(segments("", chars(10)).is_empty());
        // Whitespace-only text still has content to deliver, so it is kept as
        // one segment exactly as the legacy splitter kept it.
        assert_eq!(segments("   ", chars(10)), vec!["   "]);
    }

    #[test]
    fn no_segment_is_ever_empty() {
        for text in [
            "\n\n\n\nabc\n\n\n\n",
            "                    x",
            "a b c d e f g h i j k l m n o p",
            "\n a\n  b\n   c\n",
        ] {
            for max in 1..=8 {
                let produced = segments(text, chars(max));
                assert!(
                    produced.iter().all(|segment| !segment.is_empty()),
                    "{text:?} at {max}: {produced:?}"
                );
            }
        }
    }

    #[test]
    fn a_single_word_longer_than_the_limit_terminates_by_hard_cutting() {
        let produced = segments(&"x".repeat(25), chars(10));
        assert_eq!(
            produced,
            vec!["x".repeat(10), "x".repeat(10), "x".repeat(5)]
        );
    }

    #[test]
    fn a_newline_past_half_the_budget_wins_over_a_later_hard_cut() {
        let text = format!("{}\n{}", "a".repeat(6), "b".repeat(10));
        assert_eq!(segments(&text, chars(10)), vec!["aaaaaa", "bbbbbbbbbb"]);
    }

    #[test]
    fn a_newline_before_half_the_budget_yields_to_a_later_space() {
        let text = "ab\ncdefg hijklmnop";
        assert_eq!(segments(text, chars(10)), vec!["ab\ncdefg", "hijklmnop"]);
    }

    #[test]
    fn a_break_too_early_for_both_rules_falls_back_to_a_hard_cut() {
        let text = "ab cdefghijklmnop";
        assert_eq!(segments(text, chars(10)), vec!["ab cdefghi", "jklmnop"]);
    }

    #[test]
    fn plain_text_segmentation_matches_the_legacy_oracle_exactly() {
        let cases = [
            "the quick brown fox jumps over the lazy dog",
            "line one\nline two\nline three\nline four\nline five",
            "no-spaces-at-all-anywhere-in-this-entire-string-of-text",
            "trailing spaces      and\n\nblank lines\n\n\nfollow here",
            "a b c d e f g h i j k l m n o p q r s t u v w x y z",
            "\nleading newline then a reasonably long body of text\n",
        ];
        for text in cases {
            for max in 3..=20 {
                assert_eq!(
                    segments(text, limit(max, LengthUnit::Utf16CodeUnits)),
                    legacy_split(text, max as usize),
                    "{text:?} at {max}"
                );
            }
        }
    }

    #[test]
    fn a_multi_byte_character_is_never_cut_in_half() {
        let text = "é".repeat(20);
        for unit in [
            LengthUnit::Chars,
            LengthUnit::Utf16CodeUnits,
            LengthUnit::Bytes,
        ] {
            for max in 2..=12 {
                let produced = segments(&text, limit(max, unit));
                assert_eq!(produced.concat(), text, "{unit} at {max}");
                assert!(
                    produced
                        .iter()
                        .all(|segment| segment.chars().all(|character| character == 'é'))
                );
            }
        }
    }

    #[test]
    fn a_combining_sequence_is_never_split_from_its_base() {
        // "e" + U+0301, repeated: each pair must stay together.
        let text = "e\u{301}".repeat(12);
        for max in 2..=10 {
            for segment in segments(&text, chars(max)) {
                assert!(
                    !segment.starts_with('\u{301}'),
                    "combining mark opened a segment at {max}"
                );
                assert!(
                    !segment.ends_with('e'),
                    "a base character lost its mark at {max}"
                );
            }
        }
    }

    #[test]
    fn an_emoji_zero_width_joiner_sequence_survives_segmentation() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        let text = family.repeat(4);
        for max in 6..=20 {
            let produced = segments(&text, chars(max));
            assert_eq!(produced.concat(), text);
            for segment in produced {
                assert!(!segment.starts_with('\u{200d}'));
                assert!(!segment.ends_with('\u{200d}'));
                assert_eq!(
                    segment.chars().count() % family.chars().count(),
                    0,
                    "a family emoji was torn apart at {max}"
                );
            }
        }
    }

    #[test]
    fn a_variation_selector_and_a_skin_tone_stay_with_their_base() {
        let text = "\u{2764}\u{fe0f}\u{1f44d}\u{1f3fd}".repeat(6);
        for max in 3..=12 {
            for segment in segments(&text, chars(max)) {
                let first = segment.chars().next().expect("non-empty segment");
                assert!(!binds_to_previous(first), "{first:?} opened a segment");
            }
        }
    }

    #[test]
    fn a_flag_is_never_split_but_two_flags_may_be_separated() {
        // Two regional indicator pairs: DE then FR.
        let text = "\u{1f1e9}\u{1f1ea}\u{1f1eb}\u{1f1f7}";
        assert_eq!(
            segments(text, chars(2)),
            vec!["\u{1f1e9}\u{1f1ea}", "\u{1f1eb}\u{1f1f7}"]
        );
        assert_eq!(
            segment_text(text, Some(chars(1))),
            Err(SegmentationError::IndivisibleCluster)
        );
    }

    #[test]
    fn a_carriage_return_keeps_its_line_feed() {
        let text = "aa\r\nbb\r\ncc";
        for max in 2..=6 {
            for segment in segments(text, chars(max)) {
                assert!(!segment.ends_with('\r'), "CRLF was split at {max}");
                assert!(!segment.starts_with('\n'), "CRLF was split at {max}");
            }
        }
    }

    #[test]
    fn a_cluster_longer_than_the_whole_limit_is_refused_not_corrupted() {
        let text = format!("start {}", "a\u{301}\u{302}\u{303}\u{304}".repeat(3));
        assert_eq!(
            segment_text(&text, Some(chars(4))),
            Err(SegmentationError::IndivisibleCluster)
        );
    }

    #[test]
    fn each_unit_counts_what_that_unit_actually_measures() {
        // One astral emoji: 1 char, 2 UTF-16 code units, 4 UTF-8 bytes.
        let text = "\u{1f600}".repeat(4);
        assert_eq!(segments(&text, chars(2)).len(), 2);
        assert_eq!(
            segments(&text, limit(2, LengthUnit::Utf16CodeUnits)).len(),
            4
        );
        assert_eq!(segments(&text, limit(8, LengthUnit::Bytes)).len(), 2);
        assert_eq!(segments(&text, limit(4, LengthUnit::Chars)), vec![text]);
    }

    #[test]
    fn every_segment_respects_the_limit_in_its_own_unit() {
        let text = "Grüße 🇩🇪 team\nhere is a much longer paragraph that has to be broken\n\
                    ```rust\nfn main() { println!(\"hello 👨‍👩‍👧\"); }\n```\ntail text";
        for unit in [
            LengthUnit::Chars,
            LengthUnit::Utf16CodeUnits,
            LengthUnit::Bytes,
        ] {
            for max in 20..=120 {
                let declared = limit(max, unit);
                // A limit too small to carry one cluster or one fence marker
                // must refuse; anything it does produce must fit.
                match segment_text(text, Some(declared)) {
                    Ok(produced) => {
                        for segment in produced {
                            assert!(
                                unit.measure(&segment) <= u64::from(max),
                                "{unit} at {max} produced {segment:?}"
                            );
                        }
                    }
                    Err(error) => assert!(
                        matches!(
                            error,
                            SegmentationError::IndivisibleCluster
                                | SegmentationError::LimitTooSmall
                        ),
                        "{unit} at {max}: {error}"
                    ),
                }
            }
            let realistic = limit(1900, unit);
            assert!(segment_text(text, Some(realistic)).is_ok());
        }
    }

    #[test]
    fn a_short_fenced_block_moves_whole_into_the_next_segment() {
        let text = "intro paragraph here\n```rust\nlet x = 1;\n```\ntail";
        let produced = segments(text, chars(30));
        assert_eq!(
            produced,
            vec!["intro paragraph here", "```rust\nlet x = 1;\n```\ntail"]
        );
    }

    #[test]
    fn a_fence_longer_than_the_limit_is_closed_and_reopened() {
        let body = (0..12)
            .map(|index| format!("let value{index} = {index};"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = format!("```rust\n{body}\n```");
        let produced = segments(&text, chars(60));
        assert!(produced.len() > 1, "{produced:?}");
        for (index, segment) in produced.iter().enumerate() {
            assert!(segment.chars().count() <= 60, "{segment:?}");
            if index > 0 {
                assert!(segment.starts_with("```rust\n"), "{segment:?}");
            }
            if index + 1 < produced.len() {
                assert!(segment.ends_with("\n```"), "{segment:?}");
            }
            assert_eq!(
                segment.matches("```").count() % 2,
                0,
                "unbalanced fence in {segment:?}"
            );
        }
        assert!(produced.last().expect("a segment").ends_with("\n```"));
    }

    #[test]
    fn a_reopened_fence_keeps_its_marker_length_and_indentation() {
        let body = (0..10)
            .map(|index| format!("    indented line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let text = format!("~~~~ python\n{body}\n~~~~");
        let produced = segments(&text, chars(70));
        assert!(produced.len() > 1);
        for segment in produced.iter().skip(1) {
            assert!(segment.starts_with("~~~~python\n"), "{segment:?}");
            let continued = segment
                .lines()
                .nth(1)
                .expect("a continued line after the reopened fence");
            assert!(
                continued.starts_with("    ") || continued.starts_with("indented"),
                "indentation was trimmed: {continued:?}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_fence_is_not_treated_as_one() {
        let text = "two `` backticks and ` one, none of which open a block, plus a long tail";
        assert_eq!(
            segments(text, limit(20, LengthUnit::Utf16CodeUnits)),
            legacy_split(text, 20)
        );
    }

    #[test]
    fn an_indented_four_space_block_is_not_a_fence() {
        assert!(opening_fence("    ```rust").is_none());
        assert!(opening_fence("   ```rust").is_some());
        assert!(opening_fence("``").is_none());
        assert!(opening_fence("```in`fo").is_none());
        assert!(opening_fence("~~~ in`fo").is_some());
    }

    #[test]
    fn a_closing_fence_needs_at_least_the_opening_run_and_no_info() {
        assert!(closes_fence("```", "```"));
        assert!(closes_fence("`````", "```"));
        assert!(!closes_fence("``", "```"));
        assert!(!closes_fence("``` rust", "```"));
        assert!(!closes_fence("~~~", "```"));
    }

    #[test]
    fn a_limit_smaller_than_the_fence_it_must_reopen_is_refused() {
        let text = format!("```averylonginfostring\n{}\n```", "x".repeat(80));
        assert_eq!(
            segment_text(&text, Some(chars(12))),
            Err(SegmentationError::LimitTooSmall)
        );
    }

    #[test]
    fn segmentation_errors_display_without_leaking_the_message() {
        for error in [
            SegmentationError::NoDeclaredLimit,
            SegmentationError::LimitTooSmall,
            SegmentationError::IndivisibleCluster,
        ] {
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(LengthUnit::Chars.to_string(), "characters");
        assert_eq!(LengthUnit::Bytes.to_string(), "bytes");
        assert_eq!(LengthUnit::Utf16CodeUnits.to_string(), "UTF-16 code units");
    }

    #[test]
    fn a_declared_limit_reports_its_own_shape() {
        let declared = limit(1900, LengthUnit::Utf16CodeUnits);
        assert_eq!(declared.max().get(), 1900);
        assert_eq!(declared.unit(), LengthUnit::Utf16CodeUnits);
        assert!(declared.fits(&"a".repeat(1900)));
        assert!(!declared.fits(&"a".repeat(1901)));
        assert!(declared.fits(&"\u{1f600}".repeat(950)));
        assert!(!declared.fits(&"\u{1f600}".repeat(951)));
    }
}
