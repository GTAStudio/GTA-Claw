import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { WhatsAppWebhookHandler } from "../dist/channels/whatsappWebhook.js";

const APP_SECRET = "test-app-secret";

function webhookBody(messageId = "wamid.1") {
  return {
    entry: [
      {
        changes: [
          {
            value: {
              messages: [
                {
                  from: "15551234567",
                  id: messageId,
                  timestamp: "1",
                  type: "text",
                  text: { body: " hello " },
                },
              ],
            },
          },
        ],
      },
    ],
  };
}

function signedRequest(body, rawBody = JSON.stringify(body), signature) {
  const digest =
    signature ??
    `sha256=${createHmac("sha256", APP_SECRET).update(rawBody).digest("hex")}`;
  return {
    body,
    whatsappRawBody: Buffer.from(rawBody),
    headers: { "x-hub-signature-256": digest },
  };
}

function responseRecorder() {
  const calls = [];
  return {
    calls,
    send(status, body) {
      calls.push({ status, body });
    },
  };
}

function createHandler(overrides = {}) {
  return new WhatsAppWebhookHandler({
    verifyToken: "verify",
    accessToken: "access",
    phoneNumberId: "phone",
    appSecret: APP_SECRET,
    onMessage: async () => "",
    fetchFn: async () => new Response(null, { status: 200 }),
    ...overrides,
  });
}

test("WhatsApp authenticates the exact raw body and rejects unsafe signatures", async () => {
  let handled = 0;
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      return "";
    },
  });
  const body = webhookBody();
  const rawBody = ` { "entry": ${JSON.stringify(body.entry)} } `;

  const accepted = responseRecorder();
  await handler.incoming(
    signedRequest(body, rawBody),
    accepted,
    () => undefined,
  );
  assert.equal(accepted.calls[0].status, 200);
  assert.equal(handled, 1);

  const rejectedRequests = [
    { body, whatsappRawBody: Buffer.from(rawBody), headers: {} },
    signedRequest(body, rawBody, "sha1=abc"),
    signedRequest(body, rawBody, "sha256=xyz"),
    signedRequest(body, rawBody, `sha256=${"0".repeat(64)}`),
    { body, headers: signedRequest(body).headers },
  ];

  for (const request of rejectedRequests) {
    const rejected = responseRecorder();
    await handler.incoming(request, rejected, () => undefined);
    assert.equal(rejected.calls[0].status, 401);
  }
  assert.equal(handled, 1);
});

test("WhatsApp retries only outbound delivery after a send failure", async () => {
  let handled = 0;
  let sends = 0;
  let resolveRetry;
  const retryResult = new Promise((resolve) => {
    resolveRetry = resolve;
  });
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      return "reply";
    },
    fetchFn: async () => {
      sends += 1;
      if (sends === 1) {
        return new Response("temporary failure", {
          status: 503,
          statusText: "Unavailable",
        });
      }
      await retryResult;
      return new Response(null, { status: 200 });
    },
  });
  const request = signedRequest(webhookBody("wamid.retry"));

  const failed = responseRecorder();
  await handler.incoming(request, failed, () => undefined);
  assert.equal(failed.calls[0].status, 500);

  const retried = responseRecorder();
  const concurrentRetry = responseRecorder();
  const firstRetry = handler.incoming(request, retried, () => undefined);
  const secondRetry = handler.incoming(
    request,
    concurrentRetry,
    () => undefined,
  );
  await new Promise(setImmediate);
  assert.equal(handled, 1);
  assert.equal(sends, 2);
  resolveRetry();
  await Promise.all([firstRetry, secondRetry]);
  assert.equal(retried.calls[0].status, 200);
  assert.equal(concurrentRetry.calls[0].status, 200);

  const duplicate = responseRecorder();
  await handler.incoming(request, duplicate, () => undefined);
  assert.equal(duplicate.calls[0].status, 200);
  assert.equal(handled, 1);
  assert.equal(sends, 2);
});

test("WhatsApp retries inbound handling only when the handler fails", async () => {
  let handled = 0;
  let sends = 0;
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      if (handled === 1) {
        throw new Error("inbound processing failed");
      }
      return "reply";
    },
    fetchFn: async () => {
      sends += 1;
      return new Response(null, { status: 200 });
    },
  });
  const request = signedRequest(webhookBody("wamid.inbound-retry"));

  const failed = responseRecorder();
  await handler.incoming(request, failed, () => undefined);
  assert.equal(failed.calls[0].status, 500);

  const retried = responseRecorder();
  await handler.incoming(request, retried, () => undefined);
  assert.equal(retried.calls[0].status, 200);
  assert.equal(handled, 2);
  assert.equal(sends, 1);
});

test("WhatsApp outbound retry resumes at the failed reply chunk", async () => {
  let handled = 0;
  const sentChunks = [];
  let attempt = 0;
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      return `${"a".repeat(3500)}b`;
    },
    fetchFn: async (_url, init) => {
      attempt += 1;
      sentChunks.push(JSON.parse(init.body).text.body);
      if (attempt === 2) {
        return new Response("temporary failure", {
          status: 503,
          statusText: "Unavailable",
        });
      }
      return new Response(null, { status: 200 });
    },
  });
  const request = signedRequest(webhookBody("wamid.chunk-retry"));

  const failed = responseRecorder();
  await handler.incoming(request, failed, () => undefined);
  assert.equal(failed.calls[0].status, 500);

  const retried = responseRecorder();
  await handler.incoming(request, retried, () => undefined);
  assert.equal(retried.calls[0].status, 200);
  assert.equal(handled, 1);
  assert.deepEqual(
    sentChunks.map((chunk) => chunk.length),
    [3500, 1, 1],
  );
  assert.equal(sentChunks[1], "b");
  assert.equal(sentChunks[2], "b");
});

test("WhatsApp checkpoints a generated reply before grapheme validation", async () => {
  let handled = 0;
  let sends = 0;
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      return `a${"\u0301".repeat(3500)}`;
    },
    fetchFn: async () => {
      sends += 1;
      return new Response(null, { status: 200 });
    },
  });
  const request = signedRequest(webhookBody("wamid.oversized-grapheme"));

  const first = responseRecorder();
  await handler.incoming(request, first, () => undefined);
  assert.equal(first.calls[0].status, 500);

  const retried = responseRecorder();
  await handler.incoming(request, retried, () => undefined);
  assert.equal(retried.calls[0].status, 500);
  assert.equal(handled, 1);
  assert.equal(sends, 0);
});

test("WhatsApp coalesces concurrent deliveries of the same message id", async () => {
  let handled = 0;
  let sends = 0;
  let resolveMessage;
  const messageResult = new Promise((resolve) => {
    resolveMessage = resolve;
  });
  const handler = createHandler({
    onMessage: async () => {
      handled += 1;
      return messageResult;
    },
    fetchFn: async () => {
      sends += 1;
      return new Response(null, { status: 200 });
    },
  });
  const request = signedRequest(webhookBody("wamid.concurrent"));
  const firstResponse = responseRecorder();
  const secondResponse = responseRecorder();

  const first = handler.incoming(request, firstResponse, () => undefined);
  const second = handler.incoming(request, secondResponse, () => undefined);
  await new Promise(setImmediate);
  assert.equal(handled, 1);

  resolveMessage("reply");
  await Promise.all([first, second]);
  assert.equal(firstResponse.calls[0].status, 200);
  assert.equal(secondResponse.calls[0].status, 200);
  assert.equal(handled, 1);
  assert.equal(sends, 1);
});
