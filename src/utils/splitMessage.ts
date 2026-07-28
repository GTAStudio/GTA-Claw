export function splitMessage(text: string, maxLength: number): string[] {
  if (!Number.isInteger(maxLength) || maxLength < 1) {
    throw new RangeError("maxLength must be a positive integer");
  }

  let normalized = text.toWellFormed();
  if (maxLength === 1) {
    normalized = Array.from(normalized, (character) =>
      character.length === 1 ? character : "\uFFFD",
    ).join("");
  }

  if (normalized.length <= maxLength) return [normalized];

  const chunks: string[] = [];
  let remaining = normalized;

  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      chunks.push(remaining);
      break;
    }

    let splitAt = remaining.lastIndexOf("\n", maxLength);
    if (splitAt < maxLength * 0.5) {
      splitAt = remaining.lastIndexOf(" ", maxLength);
    }
    if (splitAt < maxLength * 0.3) {
      splitAt = maxLength;
    }
    if (
      splitAt > 0 &&
      splitAt < remaining.length &&
      isHighSurrogate(remaining.charCodeAt(splitAt - 1)) &&
      isLowSurrogate(remaining.charCodeAt(splitAt))
    ) {
      splitAt -= 1;
    }

    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt).trimStart();
  }

  return chunks;
}

function isHighSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xd800 && codeUnit <= 0xdbff;
}

function isLowSurrogate(codeUnit: number): boolean {
  return codeUnit >= 0xdc00 && codeUnit <= 0xdfff;
}
