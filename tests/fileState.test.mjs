import assert from "node:assert/strict";
import test from "node:test";

import { KeyedSerialQueue } from "../dist/state/fileState.js";

test("keyed queue serializes one scope without blocking another", async () => {
  const queue = new KeyedSerialQueue();
  let releaseFirst;
  let markFirstStarted;
  const firstStarted = new Promise((resolve) => {
    markFirstStarted = resolve;
  });
  const firstGate = new Promise((resolve) => {
    releaseFirst = resolve;
  });

  const first = queue.run("scope-a", async () => {
    markFirstStarted();
    await firstGate;
  });
  await firstStarted;

  let sameScopeRan = false;
  const sameScope = queue.run("scope-a", async () => {
    sameScopeRan = true;
  });
  await queue.run("scope-b", async () => undefined);
  assert.equal(sameScopeRan, false);

  releaseFirst();
  await Promise.all([first, sameScope]);
  assert.equal(sameScopeRan, true);
});
