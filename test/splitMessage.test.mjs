import assert from "node:assert/strict";
import test from "node:test";
import { splitMessage } from "../dist/utils/splitMessage.js";

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

  assert.deepEqual(splitMessage("😀", 1), ["\uFFFD"]);
});
