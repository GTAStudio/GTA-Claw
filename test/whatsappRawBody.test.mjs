import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import { gzipSync } from "node:zlib";
import {
  captureWhatsAppRawBody,
  WhatsAppWebhookHandler,
} from "../dist/channels/whatsappWebhook.js";

const APP_SECRET = "raw-body-app-secret";
const WEBHOOK_PATH = "/whatsapp/webhook";

function responseRecorder() {
  const calls = [];
  return {
    calls,
    send(status, body) {
      calls.push({ status, body });
    },
  };
}

function requestStream(method, url, headers = {}) {
  const request = new PassThrough();
  request.method = method;
  request.url = url;
  request.headers = headers;
  return request;
}

test("raw-body capture is scoped to the WhatsApp POST route", async () => {
  const capture = captureWhatsAppRawBody(WEBHOOK_PATH);

  for (const [method, url] of [
    ["GET", WEBHOOK_PATH],
    ["POST", "/other"],
  ]) {
    const request = requestStream(method, url);
    let nextCalls = 0;
    capture(request, {}, () => {
      nextCalls += 1;
    });
    assert.equal(nextCalls, 1);
    assert.equal(request.listenerCount("data"), 0);
    const ended = once(request, "end");
    request.resume();
    request.end("ignored");
    await ended;
    assert.equal(request.whatsappRawBody, undefined);
  }

  const request = requestStream("POST", `${WEBHOOK_PATH}?source=meta`);
  let nextCalls = 0;
  capture(request, {}, () => {
    nextCalls += 1;
  });
  assert.equal(nextCalls, 1);
  assert.equal(request.listenerCount("data"), 1);
  const ended = once(request, "end");
  request.end("captured");
  await ended;
  assert.deepEqual(request.whatsappRawBody, Buffer.from("captured"));
});

test("WhatsApp authenticates the exact compressed entity buffer", async () => {
  const json = Buffer.from(
    `{\n  "entry": [{"changes":[{"value":{"messages":[{"from":"15551234567","id":"wamid.raw","timestamp":"1","type":"text","text":{"body":"hello"}}]}}]}]\n}`,
  );
  const body = JSON.parse(json.toString("utf8"));
  const compressed = gzipSync(json);
  const capture = captureWhatsAppRawBody(WEBHOOK_PATH);

  const capturedRequest = requestStream("POST", WEBHOOK_PATH, {
    "content-type": "application/json",
    "content-encoding": "gzip",
  });
  capture(capturedRequest, {}, () => undefined);
  const ended = once(capturedRequest, "end");
  capturedRequest.end(compressed);
  await ended;
  assert.deepEqual(capturedRequest.whatsappRawBody, compressed);

  let handled = 0;
  const handler = new WhatsAppWebhookHandler({
    verifyToken: "verify",
    accessToken: "access",
    phoneNumberId: "phone",
    appSecret: APP_SECRET,
    onMessage: async () => {
      handled += 1;
      return "";
    },
  });
  const exactSignature = `sha256=${createHmac("sha256", APP_SECRET)
    .update(compressed)
    .digest("hex")}`;
  const reconstructedSignature = `sha256=${createHmac("sha256", APP_SECRET)
    .update(json)
    .digest("hex")}`;

  const accepted = responseRecorder();
  await handler.incoming(
    {
      body,
      headers: { "x-hub-signature-256": exactSignature },
      whatsappRawBody: capturedRequest.whatsappRawBody,
    },
    accepted,
    () => undefined,
  );
  assert.equal(accepted.calls[0].status, 200);
  assert.equal(handled, 1);

  const rejected = responseRecorder();
  await handler.incoming(
    {
      body,
      headers: { "x-hub-signature-256": reconstructedSignature },
      whatsappRawBody: capturedRequest.whatsappRawBody,
    },
    rejected,
    () => undefined,
  );
  assert.equal(rejected.calls[0].status, 401);
  assert.equal(handled, 1);
});
