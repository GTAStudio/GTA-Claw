import assert from "node:assert/strict";
import test from "node:test";
import { TelegramPollingClient } from "../dist/channels/telegramPolling.js";

function update(updateId, text = "hello") {
  return {
    update_id: updateId,
    message: {
      message_id: updateId,
      chat: { id: 123 },
      from: { id: 456, username: "octocat" },
      text,
    },
  };
}

test("Telegram commits offsets only after an update is handled successfully", async () => {
  let failSecond = true;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 60_000,
    onMessage: async ({ text }) => {
      if (text === "second" && failSecond) {
        throw new Error("temporary failure");
      }
      return "";
    },
  });

  await assert.rejects(
    client.processUpdates([update(10, "first"), update(11, "second")]),
    /temporary failure/,
  );
  assert.equal(client.offset, 11);

  failSecond = false;
  await client.processUpdates([update(11, "second")]);
  assert.equal(client.offset, 12);
});

test(
  "Telegram stop aborts an in-flight long poll",
  { timeout: 1_000 },
  async () => {
    let pollSignal;
    const client = new TelegramPollingClient({
      botToken: "token",
      pollIntervalMs: 60_000,
      onMessage: async () => "",
      fetchFn: async (_url, init) => {
        pollSignal = init.signal;
        return new Promise((_resolve, reject) => {
          pollSignal.addEventListener(
            "abort",
            () => reject(pollSignal.reason),
            { once: true },
          );
        });
      },
    });

    await client.start();
    await new Promise(setImmediate);
    assert.equal(pollSignal.aborted, false);
    await client.stop();
    assert.equal(pollSignal.aborted, true);
  },
);

test(
  "Telegram stop cancels retry sleep without starting another poll",
  { timeout: 1_000 },
  async () => {
    let polls = 0;
    const client = new TelegramPollingClient({
      botToken: "token",
      pollIntervalMs: 60_000,
      onMessage: async () => "",
      fetchFn: async () => {
        polls += 1;
        return new Response(null, { status: 503 });
      },
    });

    await client.start();
    await new Promise(setImmediate);
    assert.equal(polls, 1);
    await client.stop();
    assert.equal(polls, 1);
  },
);
