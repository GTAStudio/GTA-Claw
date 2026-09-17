import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";
import { gzipSync } from "node:zlib";
import {
  captureWhatsAppRawBody,
  MAX_WHATSAPP_WEBHOOK_BODY_BYTES,
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
  assert.equal(nextCalls, 0);
  assert.equal(request.listenerCount("data"), 1);
  const ended = once(request, "end");
  request.end("captured");
  await ended;
  assert.equal(nextCalls, 1);
  assert.deepEqual(request.whatsappRawBody, Buffer.from("captured"));
});

test("captured gzip body is authenticated and parsed without req.body", async () => {
  const json = Buffer.from(
    `{\n  "entry": [{"changes":[{"value":{"metadata":{"phone_number_id":"phone"},"messages":[{"from":"15551234567","id":"wamid.raw","timestamp":"1","type":"text","text":{"body":"hello"}}]}}]}]\n}`,
  );
  const compressed = gzipSync(json);
  const capture = captureWhatsAppRawBody(WEBHOOK_PATH);

  const capturedRequest = requestStream("POST", WEBHOOK_PATH, {
    "content-type": "application/json",
    "content-encoding": "gzip",
  });
  let nextCalls = 0;
  capture(capturedRequest, {}, () => {
    nextCalls += 1;
  });
  assert.equal(nextCalls, 0);
  const ended = once(capturedRequest, "end");
  capturedRequest.end(compressed);
  await ended;
  assert.equal(nextCalls, 1);
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

  capturedRequest.headers["x-hub-signature-256"] = exactSignature;
  const accepted = responseRecorder();
  await handler.incoming(
    capturedRequest,
    accepted,
    () => undefined,
  );
  assert.equal(accepted.calls[0].status, 200);
  assert.equal(handled, 1);

  capturedRequest.headers["x-hub-signature-256"] = reconstructedSignature;
  const rejected = responseRecorder();
  await handler.incoming(
    capturedRequest,
    rejected,
    () => undefined,
  );
  assert.equal(rejected.calls[0].status, 401);
  assert.equal(handled, 1);
});

test("chunked raw-body capture rejects payloads over the byte cap", async () => {
  const capture = captureWhatsAppRawBody(WEBHOOK_PATH);
  const request = requestStream("POST", WEBHOOK_PATH);
  const response = responseRecorder();
  const nextArgs = [];
  capture(request, response, (arg) => {
    nextArgs.push(arg);
  });

  const ended = once(request, "end");
  request.write(Buffer.alloc(MAX_WHATSAPP_WEBHOOK_BODY_BYTES, 0x61));
  request.write(Buffer.from("b"));
  assert.deepEqual(response.calls, []);
  assert.deepEqual(nextArgs, []);
  request.end();
  await ended;

  assert.deepEqual(response.calls, [
    { status: 413, body: { error: "WhatsApp webhook body too large" } },
  ]);
  assert.deepEqual(nextArgs, [false]);
  assert.equal(request.whatsappRawBody, undefined);
});

test("authenticated malformed or unsupported bodies return client errors", async () => {
  const handler = new WhatsAppWebhookHandler({
    verifyToken: "verify",
    accessToken: "access",
    phoneNumberId: "phone",
    appSecret: APP_SECRET,
    onMessage: async () => "",
  });

  for (const { rawBody, encoding, status } of [
    {
      rawBody: Buffer.from("{}"),
      encoding: "br",
      status: 415,
    },
    {
      rawBody: Buffer.from("not gzip"),
      encoding: "gzip",
      status: 400,
    },
    {
      rawBody: Buffer.from("{"),
      encoding: "identity",
      status: 400,
    },
  ]) {
    const signature = `sha256=${createHmac("sha256", APP_SECRET)
      .update(rawBody)
      .digest("hex")}`;
    const response = responseRecorder();
    await handler.incoming(
      {
        headers: {
          "content-encoding": encoding,
          "x-hub-signature-256": signature,
        },
        whatsappRawBody: rawBody,
      },
      response,
      () => undefined,
    );
    assert.equal(response.calls[0].status, status);
  }
});
