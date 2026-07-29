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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function waitForAbort(signal) {
  if (signal.aborted) {
    return Promise.reject(signal.reason);
  }

  return new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => reject(signal.reason), {
      once: true,
    });
  });
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

test(
  "Telegram start waits for a stopping loop blocked in onMessage",
  { timeout: 1_000 },
  async () => {
    const enteredMessage = deferred();
    const releaseMessage = deferred();
    const restartedPoll = deferred();
    let polls = 0;
    let handled = 0;
    const client = new TelegramPollingClient({
      botToken: "token",
      pollIntervalMs: 60_000,
      onMessage: async () => {
        handled += 1;
        enteredMessage.resolve();
        await releaseMessage.promise;
        return "";
      },
      fetchFn: async (url, init) => {
        if (!String(url).includes("/getUpdates")) {
          throw new Error(`unexpected URL: ${url}`);
        }
        polls += 1;
        if (polls === 2) {
          restartedPoll.resolve();
          return waitForAbort(init.signal);
        }
        return new Response(
          JSON.stringify({
            ok: true,
            result: [update(1)],
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      },
    });

    await client.start();
    await enteredMessage.promise;
    const stopping = client.stop();
    const restarting = client.start();
    await new Promise(setImmediate);
    assert.equal(polls, 1);
    assert.equal(handled, 1);

    releaseMessage.resolve();
    await stopping;
    await restarting;
    await restartedPoll.promise;
    assert.equal(polls, 2);
    assert.equal(handled, 1);
    await client.stop();
  },
);

test(
  "Telegram orders a second stop after a queued restart",
  { timeout: 1_000 },
  async () => {
    const enteredMessage = deferred();
    const releaseMessage = deferred();
    const restartedPoll = deferred();
    let polls = 0;
    let handled = 0;
    const client = new TelegramPollingClient({
      botToken: "token",
      pollIntervalMs: 60_000,
      onMessage: async () => {
        handled += 1;
        enteredMessage.resolve();
        await releaseMessage.promise;
        return "";
      },
      fetchFn: async (_url, init) => {
        polls += 1;
        if (polls === 1) {
          return new Response(
            JSON.stringify({ ok: true, result: [update(2)] }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          );
        }

        restartedPoll.resolve();
        return waitForAbort(init.signal);
      },
    });

    await client.start();
    await enteredMessage.promise;
    const stopping = client.stop();
    const restarting = client.start();
    const stoppingAgain = client.stop();
    releaseMessage.resolve();

    await Promise.all([stopping, restarting, stoppingAgain]);
    await restartedPoll.promise;
    assert.equal(polls, 2);
    assert.equal(handled, 1);
    await new Promise(setImmediate);
    assert.equal(polls, 2);
  },
);

test(
  "Telegram retries only the unsent reply chunk across stop and restart",
  { timeout: 1_000 },
  async () => {
    const failedSecondChunk = deferred();
    const retryPollStarted = deferred();
    const deliveredRetry = deferred();
    const finalPollStarted = deferred();
    let polls = 0;
    let handled = 0;
    let sendAttempts = 0;
    const sentChunks = [];
    const client = new TelegramPollingClient({
      botToken: "token",
      pollIntervalMs: 0,
      onMessage: async () => {
        handled += 1;
        return "x".repeat(5000);
      },
      fetchFn: async (url, init) => {
        if (String(url).includes("/getUpdates")) {
          polls += 1;
          if (polls === 2) {
            retryPollStarted.resolve();
            return waitForAbort(init.signal);
          }
          if (polls === 4) {
            finalPollStarted.resolve();
            return waitForAbort(init.signal);
          }
          return new Response(
            JSON.stringify({ ok: true, result: [update(20)] }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" },
            },
          );
        }

        sendAttempts += 1;
        const chunk = JSON.parse(init.body).text;
        sentChunks.push(chunk);
        if (sendAttempts === 2) {
          failedSecondChunk.resolve();
          return new Response(null, { status: 503 });
        }
        if (sendAttempts === 3) {
          deliveredRetry.resolve();
        }
        return new Response(null, { status: 200 });
      },
    });

    await client.start();
    await failedSecondChunk.promise;
    await retryPollStarted.promise;
    assert.equal(client.offset, 0);
    await client.stop();

    await client.start();
    await deliveredRetry.promise;
    await finalPollStarted.promise;
    assert.equal(client.offset, 21);
    assert.equal(handled, 1);
    assert.equal(polls, 4);
    assert.deepEqual(
      sentChunks.map((chunk) => chunk.length),
      [4000, 1000, 1000],
    );
    assert.equal(sentChunks[0], "x".repeat(4000));
    assert.equal(sentChunks[1], "x".repeat(1000));
    assert.equal(sentChunks[2], "x".repeat(1000));
    await client.stop();
  },
);

test("Telegram dead-letters terminal 403 delivery once and continues", async () => {
  const handled = [];
  let sends = 0;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 60_000,
    onMessage: async ({ text }) => {
      handled.push(text);
      return text === "forbidden" ? "reply" : "";
    },
    fetchFn: async () => {
      sends += 1;
      return new Response(null, { status: 403 });
    },
  });

  await client.processUpdates([
    update(30, "forbidden"),
    update(31, "later"),
  ]);
  assert.equal(client.offset, 32);
  assert.deepEqual(handled, ["forbidden", "later"]);
  assert.equal(sends, 1);
  assert.match(client.deadLetteredUpdates.get(30), /terminal status 403/);

  await client.processUpdates([update(30, "forbidden")]);
  assert.deepEqual(handled, ["forbidden", "later"]);
  assert.equal(sends, 1);
  assert.equal(client.deadLetteredUpdates.size, 1);
});

test("Telegram dead-letters an impossible grapheme without duplicate side effects", async () => {
  const handled = [];
  const oversizedGrapheme = `a${"\u0301".repeat(4000)}`;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 60_000,
    onMessage: async ({ text }) => {
      handled.push(text);
      return text === "impossible" ? oversizedGrapheme : "";
    },
    fetchFn: async () => {
      throw new Error("sendMessage must not run for an oversized grapheme");
    },
  });

  await client.processUpdates([
    update(40, "impossible"),
    update(41, "later"),
  ]);
  assert.equal(client.offset, 42);
  assert.deepEqual(handled, ["impossible", "later"]);
  assert.match(
    client.deadLetteredUpdates.get(40),
    /message grapheme uses 4001 UTF-16 code units/i,
  );

  await client.processUpdates([update(40, "impossible")]);
  assert.deepEqual(handled, ["impossible", "later"]);
  assert.equal(client.deadLetteredUpdates.size, 1);
});

test("Telegram retains checkpoints for 429, 5xx, and network failures", async () => {
  const failures = [
    new Response(null, { status: 429 }),
    new Response(null, { status: 503 }),
    new Error("network failure"),
    new Response(null, { status: 200 }),
  ];
  let handled = 0;
  let sends = 0;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 60_000,
    onMessage: async () => {
      handled += 1;
      return "reply";
    },
    fetchFn: async () => {
      const result = failures[sends];
      sends += 1;
      if (result instanceof Error) throw result;
      return result;
    },
  });

  for (const pattern of [/429/, /503/, /network failure/]) {
    await assert.rejects(client.processUpdates([update(50)]), pattern);
    assert.equal(client.offset, 0);
  }
  await client.processUpdates([update(50)]);
  assert.equal(client.offset, 51);
  assert.equal(handled, 1);
  assert.equal(sends, 4);
  assert.equal(client.deadLetteredUpdates.size, 0);
});

test("Telegram honors retry_after before polling again", async () => {
  const waitStarted = deferred();
  const waits = [];
  let handled = 0;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 100,
    onMessage: async () => {
      handled += 1;
      return "reply";
    },
    fetchFn: async (url) => {
      if (String(url).includes("/getUpdates")) {
        return new Response(
          JSON.stringify({ ok: true, result: [update(60)] }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      return new Response(
        JSON.stringify({
          ok: false,
          error_code: 429,
          parameters: { retry_after: 7 },
        }),
        {
          status: 429,
          headers: { "Content-Type": "application/json" },
        },
      );
    },
    waitFn: async (delayMs) => {
      waits.push(delayMs);
      client.running = false;
      waitStarted.resolve();
    },
  });

  await client.start();
  await waitStarted.promise;
  await client.stop();

  assert.deepEqual(waits, [7_000]);
  assert.equal(handled, 1);
  assert.equal(client.offset, 0);
  assert.equal(client.deliveryCheckpoints.has(60), true);
});

test("Telegram migrates a checkpoint destination without duplicate side effects", async () => {
  const sent = [];
  let handled = 0;
  let sendAttempt = 0;
  const client = new TelegramPollingClient({
    botToken: "token",
    pollIntervalMs: 60_000,
    onMessage: async () => {
      handled += 1;
      return "x".repeat(5_000);
    },
    fetchFn: async (_url, init) => {
      sendAttempt += 1;
      sent.push(JSON.parse(init.body));
      if (sendAttempt === 2) {
        return new Response(
          JSON.stringify({
            ok: false,
            error_code: 400,
            parameters: { migrate_to_chat_id: -1009876543210 },
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          },
        );
      }
      return new Response(null, { status: 200 });
    },
  });

  await assert.rejects(
    client.processUpdates([update(70)]),
    /retryable status 400/,
  );
  assert.equal(client.offset, 0);
  assert.equal(client.deliveryCheckpoints.get(70).nextChunk, 1);
  assert.equal(
    client.deliveryCheckpoints.get(70).chatId,
    -1009876543210,
  );

  await client.processUpdates([update(70)]);
  assert.equal(client.offset, 71);
  assert.equal(handled, 1);
  assert.deepEqual(
    sent.map(({ chat_id, text }) => [chat_id, text.length]),
    [
      [123, 4_000],
      [123, 1_000],
      [-1009876543210, 1_000],
    ],
  );
});
