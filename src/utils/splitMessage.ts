const graphemeSegmenter = new Intl.Segmenter(undefined, {
  granularity: "grapheme",
});
const whitespaceGrapheme = /^\s+$/u;

function trimLeadingWhitespaceGraphemes(value: string): string {
  let trimAt = 0;
  for (const { index, segment } of graphemeSegmenter.segment(value)) {
    if (!whitespaceGrapheme.test(segment)) break;
    trimAt = index + segment.length;
  }
  return value.slice(trimAt);
}

export class MessageGraphemeTooLongError extends RangeError {
  constructor(
    readonly grapheme: string,
    readonly maxLength: number,
  ) {
    super(
      `A message grapheme uses ${grapheme.length} UTF-16 code units, exceeding the ${maxLength}-unit limit`,
    );
    this.name = "MessageGraphemeTooLongError";
  }
}

export function splitMessage(text: string, maxLength: number): string[] {
  if (!Number.isInteger(maxLength) || maxLength < 1) {
    throw new RangeError("maxLength must be a positive integer");
  }

  const normalized = text.toWellFormed();
  const graphemes = Array.from(graphemeSegmenter.segment(normalized));
  for (const { segment } of graphemes) {
    if (segment.length > maxLength) {
      throw new MessageGraphemeTooLongError(segment, maxLength);
    }
  }

  if (normalized.length <= maxLength) return [normalized];

  const chunks: string[] = [];
  let remaining = normalized;

  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      chunks.push(remaining);
      break;
    }

    let hardSplitAt = 0;
    let newlineSplitAt = -1;
    let wordSplitAt = -1;
    for (const { index, segment } of graphemeSegmenter.segment(remaining)) {
      if (index > maxLength) break;

      if (segment === "\n" || segment === "\r\n" || segment === "\r") {
        newlineSplitAt = index;
      } else if (segment === " ") {
        wordSplitAt = index;
      }

      const end = index + segment.length;
      if (end <= maxLength) {
        hardSplitAt = end;
      }
    }

    let splitAt = newlineSplitAt;
    if (splitAt < maxLength * 0.5) {
      splitAt = wordSplitAt;
    }
    if (splitAt < maxLength * 0.3) {
      splitAt = hardSplitAt;
    }

    chunks.push(remaining.slice(0, splitAt));
    remaining = trimLeadingWhitespaceGraphemes(remaining.slice(splitAt));
  }

  return chunks;
}
