import assert from "node:assert/strict";
import test from "node:test";
import {
  MessageGraphemeTooLongError,
  splitMessage,
} from "../dist/utils/splitMessage.js";

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

test("splitMessage preserves newline and word split preferences", () => {
  assert.deepEqual(splitMessage("12345\n67890", 6), ["12345", "67890"]);
  assert.deepEqual(splitMessage("12345\r\n67890", 8), ["12345", "67890"]);
  assert.deepEqual(splitMessage("hello world", 7), ["hello", "world"]);
});

test("splitMessage keeps astral characters paired at hard boundaries", () => {
  const chunks = splitMessage("ab😀cd", 3);
  assert.deepEqual(chunks, ["ab", "😀c", "d"]);
  assert.equal(chunks.join(""), "ab😀cd");
  assert.ok(chunks.every((chunk) => chunk.length <= 3));
  assert.ok(chunks.every((chunk) => !hasUnpairedSurrogate(chunk)));
});

test("splitMessage repairs malformed UTF-16 and preserves code-unit limits", () => {
  const chunks = splitMessage("a\uD800b\uDC00c", 2);
  assert.equal(chunks.join(""), "a\uFFFDb\uFFFDc");
  assert.ok(chunks.every((chunk) => chunk.length <= 2));
  assert.ok(chunks.every((chunk) => !hasUnpairedSurrogate(chunk)));
});

test("splitMessage keeps combining and ZWJ graphemes intact", () => {
  const combining = splitMessage("Ae\u0301B", 2);
  assert.deepEqual(combining, ["A", "e\u0301", "B"]);
  assert.equal(combining.join(""), "Ae\u0301B");

  const family = "👨‍👩‍👧‍👦";
  const zwj = splitMessage(`a${family}b`, 1 + family.length);
  assert.deepEqual(zwj, [`a${family}`, "b"]);
  assert.equal(zwj.join(""), `a${family}b`);
});

test("splitMessage trims separators only at whole grapheme boundaries", () => {
  const chunks = splitMessage("abc \u0301d", 3);
  assert.deepEqual(chunks, ["abc", " \u0301d"]);
  assert.equal(chunks.join(""), "abc \u0301d");
});

test("splitMessage rejects an indivisible grapheme over the code-unit limit", () => {
  assert.throws(
    () => splitMessage("😀", 1),
    (err) => {
      assert.ok(err instanceof MessageGraphemeTooLongError);
      assert.equal(err.grapheme, "😀");
      assert.equal(err.maxLength, 1);
      return true;
    },
  );

  const family = "👨‍👩‍👧‍👦";
  assert.throws(
    () => splitMessage(family, family.length - 1),
    MessageGraphemeTooLongError,
  );
});
