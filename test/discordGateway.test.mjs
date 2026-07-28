import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { DiscordGatewayClient } from "../dist/channels/discordGateway.js";

class FakeWebSocket extends EventEmitter {
  readyState = 1;
  sent = [];
  closeCalls = 0;
  terminateCalls = 0;
  sendError = null;

  send(payload, callback) {
    this.sent.push(JSON.parse(payload));
    callback?.(this.sendError);
  }

  close(code = 1000) {
    this.closeCalls += 1;
    this.readyState = 3;
    this.emit("close", code);
  }

  terminate() {
    this.terminateCalls += 1;
    this.readyState = 3;
    this.emit("close", 1006);
  }
}

function packet(socket, value) {
  socket.emit("message", Buffer.from(JSON.stringify(value)));
}

function messagePacket(id, content) {
  return {
    op: 0,
    t: "MESSAGE_CREATE",
    s: Number(id),
    d: {
      id,
      channel_id: "channel",
      content,
      author: { id: "user", username: "octocat" },
    },
  };
}

function createClient(onMessage = async () => "") {
  const sockets = [];
  const urls = [];
  const client = new DiscordGatewayClient({
    botToken: "token",
    gatewayUrl: "wss://gateway.example/?v=10&encoding=json",
    intents: 1,
    onMessage,
    webSocketFactory: (url) => {
      urls.push(url);
      const socket = new FakeWebSocket();
      sockets.push(socket);
      return socket;
    },
  });
  return { client, sockets, urls };
}

test("Discord handles requested heartbeats and reconnects when ACKs go stale", async () => {
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];

  packet(socket, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.equal(socket.sent[0].op, 2);

  packet(socket, { op: 1, t: null, s: 7, d: null });
  assert.deepEqual(socket.sent.at(-1), { op: 1, d: 7 });
  packet(socket, { op: 11, t: null, s: null, d: null });

  client.sendHeartbeat(socket, true);
  assert.deepEqual(socket.sent.at(-1), { op: 1, d: 7 });
  client.sendHeartbeat(socket, true);
  assert.equal(socket.terminateCalls, 1);

  await client.stop();
});

test("Discord resumes with the saved session, sequence, and resume gateway URL", async () => {
  const { client, sockets, urls } = createClient();
  client.start();
  const first = sockets[0];
  packet(first, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(first, {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.example",
    },
  });

  first.close();
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const resumed = sockets[1];
  assert.equal(urls[1], "wss://resume.example/?v=10&encoding=json");
  packet(resumed, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.deepEqual(resumed.sent[0], {
    op: 6,
    d: { token: "token", session_id: "session-1", seq: 42 },
  });

  packet(resumed, { op: 9, t: null, s: null, d: false });
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const identified = sockets[2];
  packet(identified, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.equal(identified.sent[0].op, 2);

  await client.stop();
});

test("Discord identifies after a non-resumable session close", async () => {
  const { client, sockets } = createClient();
  client.start();
  const first = sockets[0];
  packet(first, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(first, {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.example",
    },
  });

  first.close(4009);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const next = sockets[1];
  packet(next, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.equal(next.sent[0].op, 2);

  await client.stop();
});

test("Discord stops reconnecting after an unrecoverable gateway close", async () => {
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];
  packet(socket, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 60_000 },
  });

  socket.close(4004);
  assert.equal(client.running, false);
  assert.equal(client.heartbeatTimer, null);
  assert.equal(client.reconnectTimer, null);

  await client.stop();
});

test("Discord serializes message handling and contains listener rejections", async () => {
  const calls = [];
  let releaseFirst;
  const firstResult = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  const { client, sockets } = createClient(async ({ text }) => {
    calls.push(text);
    if (text === "first") {
      return firstResult;
    }
    if (text === "fails") {
      throw new Error("handler failed");
    }
    return "";
  });
  client.start();
  const socket = sockets[0];

  assert.doesNotThrow(() => socket.emit("message", Buffer.from("{")));
  packet(socket, messagePacket("1", "first"));
  packet(socket, messagePacket("2", "fails"));
  packet(socket, messagePacket("3", "third"));
  await new Promise(setImmediate);
  assert.deepEqual(calls, ["first"]);

  releaseFirst("");
  await client.conversationQueue;
  assert.deepEqual(calls, ["first", "fails", "third"]);

  await client.stop();
});

test("Discord contains asynchronous WebSocket send callback failures", async () => {
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];
  socket.sendError = new Error("send failed");

  assert.doesNotThrow(() => {
    packet(socket, {
      op: 10,
      t: null,
      s: null,
      d: { heartbeat_interval: 60_000 },
    });
  });
  assert.equal(socket.terminateCalls, 1);

  await client.stop();
});
