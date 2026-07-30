import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { DiscordGatewayClient } from "../dist/channels/discordGateway.js";

class FakeWebSocket extends EventEmitter {
  readyState = 1;
  sent = [];
  closeCalls = 0;
  closeCodes = [];
  terminateCalls = 0;
  sendError = null;
  closeError = null;

  send(payload, callback) {
    this.sent.push(JSON.parse(payload));
    callback?.(this.sendError);
  }

  close(code) {
    this.closeCalls += 1;
    this.closeCodes.push(code);
    this.readyState = 3;
    this.emit("close", code ?? 1005);
    if (this.closeError) {
      setImmediate(() => this.emit("error", this.closeError));
    }
  }

  remoteClose(code) {
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

test("Discord resets heartbeat scheduling for an adjacent opcode 1", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];

  packet(socket, {
    op: 10,
    t: null,
    s: null,
    d: { heartbeat_interval: 1_000 },
  });
  assert.equal(socket.sent[0].op, 2);

  t.mock.timers.tick(999);
  packet(socket, { op: 1, t: null, s: 7, d: null });
  assert.deepEqual(socket.sent.at(-1), { op: 1, d: 7 });
  const sendsAfterRequest = socket.sent.length;

  t.mock.timers.tick(1);
  assert.equal(socket.terminateCalls, 0);
  assert.equal(socket.sent.length, sendsAfterRequest);

  t.mock.timers.tick(998);
  assert.equal(socket.terminateCalls, 0);
  packet(socket, { op: 11, t: null, s: null, d: null });

  t.mock.timers.tick(1);
  assert.deepEqual(socket.sent.at(-1), { op: 1, d: 7 });
  assert.equal(socket.sent.length, sendsAfterRequest + 1);

  t.mock.timers.tick(1_000);
  assert.equal(socket.terminateCalls, 1);

  await client.stop();
});

test("Discord answers opcode 1 immediately and refreshes the ACK watchdog", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];
  packet(socket, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 1_000 },
  });

  t.mock.timers.tick(1_000);
  assert.equal(socket.sent.filter(({ op }) => op === 1).length, 1);
  t.mock.timers.tick(999);
  packet(socket, { op: 1, t: null, d: null });
  packet(socket, { op: 1, t: null, d: null });
  assert.equal(socket.sent.filter(({ op }) => op === 1).length, 3);

  t.mock.timers.tick(1);
  assert.equal(socket.terminateCalls, 0);
  t.mock.timers.tick(998);
  assert.equal(socket.terminateCalls, 0);
  t.mock.timers.tick(1);
  assert.equal(socket.terminateCalls, 1);

  await client.stop();
});

test("Discord rejects heartbeat intervals outside safe bounds", async () => {
  for (const interval of [
    -1,
    0,
    1,
    999,
    300_001,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    1_000.5,
    "1000",
  ]) {
    const { client, sockets } = createClient();
    client.start();
    const socket = sockets[0];

    packet(socket, {
      op: 10,
      t: null,
      d: { heartbeat_interval: interval },
    });

    assert.equal(socket.terminateCalls, 1, String(interval));
    assert.equal(socket.sent.length, 0, String(interval));
    assert.equal(client.heartbeatTimer, null, String(interval));
    assert.equal(client.heartbeatAckTimer, null, String(interval));
    await client.stop();
  }
});

test("Discord accepts heartbeat intervals at both safety boundaries", async () => {
  for (const interval of [1_000, 300_000]) {
    const { client, sockets } = createClient();
    client.start();
    const socket = sockets[0];

    packet(socket, {
      op: 10,
      t: null,
      d: { heartbeat_interval: interval },
    });

    assert.equal(socket.terminateCalls, 0, String(interval));
    assert.equal(socket.sent[0].op, 2, String(interval));
    assert.notEqual(client.heartbeatTimer, null, String(interval));
    await client.stop();
  }
});

test("Discord retains sequence when Hello and ACK omit s", async () => {
  const { client, sockets } = createClient();
  client.start();
  const first = sockets[0];
  packet(first, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(first, {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });
  packet(first, { op: 11, t: null, d: null });
  packet(first, { op: 1, t: null, d: null });
  assert.deepEqual(first.sent.at(-1), { op: 1, d: 42 });

  first.remoteClose(1006);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const resumed = sockets[1];
  packet(resumed, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.deepEqual(resumed.sent[0], {
    op: 6,
    d: { token: "token", session_id: "session-1", seq: 42 },
  });

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
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  first.remoteClose(1006);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const resumed = sockets[1];
  assert.equal(urls[1], "wss://resume.discord.gg?v=10&encoding=json");
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
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  first.remoteClose(4009);
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

  socket.remoteClose(4004);
  assert.equal(client.running, false);
  assert.equal(client.heartbeatTimer, null);
  assert.equal(client.reconnectTimer, null);

  await client.stop();
});

test("Discord contains close-time errors when stopped while connecting", async () => {
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];
  socket.readyState = 0;
  socket.closeError = new Error(
    "WebSocket was closed before the connection was established",
  );

  await client.stop();
  await new Promise(setImmediate);
  assert.equal(sockets.length, 1);
  assert.equal(client.reconnectTimer, null);
  assert.equal(socket.listenerCount("error"), 1);
  assert.deepEqual(socket.closeCodes, [1000]);
});

test("Discord final stop sends 1000 and clears resumable state", async () => {
  const { client, sockets } = createClient();
  client.start();
  const socket = sockets[0];
  packet(socket, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(socket, {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  await client.stop();

  assert.deepEqual(socket.closeCodes, [1000]);
  assert.equal(client.sessionId, null);
  assert.equal(client.seq, null);
  assert.equal(client.resumeGatewayUrl, null);
  assert.equal(client.reconnectTimer, null);
});

test("Discord clean remote closes discard the resumable session", async () => {
  for (const closeCode of [1000, 1001]) {
    const { client, sockets } = createClient();
    client.start();
    const first = sockets[0];
    packet(first, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    packet(first, {
      op: 0,
      t: "READY",
      s: 42,
      d: {
        session_id: "session-1",
        resume_gateway_url: "wss://resume.discord.gg",
      },
    });

    first.remoteClose(closeCode);
    clearTimeout(client.reconnectTimer);
    client.reconnectTimer = null;
    client.connect();
    const next = sockets[1];
    packet(next, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });

    assert.equal(next.sent[0].op, 2, String(closeCode));
    await client.stop();
  }
});

test("Discord gateway-requested no-code close remains resumable", async () => {
  const { client, sockets } = createClient();
  client.start();
  const first = sockets[0];
  packet(first, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(first, {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  packet(first, { op: 7, t: null, d: null });
  assert.deepEqual(first.closeCodes, [undefined]);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  const resumed = sockets[1];
  packet(resumed, {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.equal(resumed.sent[0].op, 6);

  await client.stop();
});

test("Discord accepts the PR230 resume gateway URL forms", async () => {
  const safeUrls = [
    [
      "wss://gateway-us-east1-b.discord.gg",
      "wss://gateway-us-east1-b.discord.gg?v=10&encoding=json",
    ],
    ["wss://discord.gg", "wss://discord.gg?v=10&encoding=json"],
    [
      "wss://GATEWAY.DISCORD.GG:443/gateway?encoding=json&v=10",
      "wss://GATEWAY.DISCORD.GG:443/gateway?encoding=json&v=10",
    ],
    [
      "wss://gateway.discord.gg/?compression=zlib-stream",
      "wss://gateway.discord.gg/?compression=zlib-stream",
    ],
    [
      "wss://gateway.example/resume?encoding=json",
      "wss://gateway.example/resume?encoding=json",
    ],
  ];

  for (const [resumeGatewayUrl, expectedUrl] of safeUrls) {
    const { client, sockets, urls } = createClient();
    client.start();
    const first = sockets[0];
    packet(first, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    packet(first, {
      op: 0,
      t: "READY",
      s: 42,
      d: {
        session_id: "session-1",
        resume_gateway_url: resumeGatewayUrl,
      },
    });
    assert.equal(client.sessionId, "session-1", resumeGatewayUrl);
    assert.equal(client.resumeGatewayUrl, expectedUrl, resumeGatewayUrl);

    first.remoteClose(1006);
    clearTimeout(client.reconnectTimer);
    client.reconnectTimer = null;
    client.connect();
    assert.equal(urls[1], expectedUrl, resumeGatewayUrl);

    const resumed = sockets[1];
    packet(resumed, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    assert.equal(resumed.sent[0].op, 6, resumeGatewayUrl);
    await client.stop();
  }
});

test("Discord atomically rejects READY with an unsafe resume gateway URL", async () => {
  const unsafeUrls = [
    "https://resume.discord.gg",
    "wss://user:password@resume.discord.gg",
    "wss://@resume.discord.gg",
    "WSS://resume.discord.gg",
    "wss://resume.discord.gg#fragment",
    "wss://resume.discord.gg:8443",
    "wss://discord.gg.attacker.example",
    "wss://attacker.example",
    "wss://evil.example\\.discord.gg",
    " wss://resume.discord.gg",
    "not a URL",
    42,
  ];

  for (const resumeGatewayUrl of unsafeUrls) {
    const { client, sockets, urls } = createClient();
    client.start();
    const first = sockets[0];
    packet(first, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    packet(first, {
      op: 0,
      t: "READY",
      s: 41,
      d: {
        session_id: "prior-session",
        resume_gateway_url: "wss://resume.discord.gg",
      },
    });
    assert.equal(client.sessionId, "prior-session");
    packet(first, {
      op: 0,
      t: "READY",
      s: 42,
      d: {
        session_id: "session-1",
        resume_gateway_url: resumeGatewayUrl,
      },
    });
    assert.equal(client.sessionId, null, String(resumeGatewayUrl));
    assert.equal(client.seq, null, String(resumeGatewayUrl));
    assert.equal(client.resumeGatewayUrl, null, String(resumeGatewayUrl));

    first.remoteClose(1006);
    clearTimeout(client.reconnectTimer);
    client.reconnectTimer = null;
    client.connect();
    assert.equal(
      urls[1],
      "wss://gateway.example/?v=10&encoding=json",
      resumeGatewayUrl,
    );
    assert.equal(urls.includes(resumeGatewayUrl), false, String(resumeGatewayUrl));

    const bootstrap = sockets[1];
    packet(bootstrap, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    assert.equal(bootstrap.sent[0].op, 2, String(resumeGatewayUrl));
    await client.stop();
  }
});

test("Discord atomically rejects READY with a malformed session ID", async () => {
  const invalidSessionIds = [
    "",
    " session-1",
    "session-1 ",
    "session\u0000-1",
    "session\n1",
    "x".repeat(257),
    42,
  ];

  for (const sessionId of invalidSessionIds) {
    const { client, sockets, urls } = createClient();
    client.start();
    const first = sockets[0];
    packet(first, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    packet(first, {
      op: 0,
      t: "READY",
      s: 41,
      d: {
        session_id: "prior-session",
        resume_gateway_url: "wss://resume.discord.gg",
      },
    });
    assert.equal(client.sessionId, "prior-session");
    packet(first, {
      op: 0,
      t: "READY",
      s: 42,
      d: {
        session_id: sessionId,
        resume_gateway_url: "wss://resume.discord.gg",
      },
    });
    assert.equal(client.sessionId, null, String(sessionId));
    assert.equal(client.seq, null, String(sessionId));
    assert.equal(client.resumeGatewayUrl, null, String(sessionId));

    first.remoteClose(1006);
    clearTimeout(client.reconnectTimer);
    client.reconnectTimer = null;
    client.connect();
    assert.equal(
      urls[1],
      "wss://gateway.example/?v=10&encoding=json",
      String(sessionId),
    );

    const bootstrap = sockets[1];
    packet(bootstrap, {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    assert.equal(bootstrap.sent[0].op, 2, String(sessionId));
    await client.stop();
  }
});

test("Discord READY may omit or null the resume gateway URL", async () => {
  for (const ready of [
    { session_id: "session-1" },
    { session_id: "session-1", resume_gateway_url: null },
  ]) {
    const { client, sockets } = createClient();
    client.start();
    packet(sockets[0], {
      op: 10,
      t: null,
      d: { heartbeat_interval: 60_000 },
    });
    packet(sockets[0], { op: 0, t: "READY", s: 42, d: ready });

    assert.equal(client.sessionId, "session-1");
    assert.equal(client.resumeGatewayUrl, null);
    await client.stop();
  }
});

test("Discord falls back after the resume gateway factory fails", async () => {
  const sockets = [];
  const urls = [];
  const client = new DiscordGatewayClient({
    botToken: "token",
    gatewayUrl: "wss://gateway.example/?v=10&encoding=json",
    intents: 1,
    onMessage: async () => "",
    webSocketFactory: (url) => {
      urls.push(url);
      if (urls.length === 2) {
        throw new Error("resume endpoint unavailable");
      }
      const socket = new FakeWebSocket();
      sockets.push(socket);
      return socket;
    },
  });
  client.start();
  packet(sockets[0], {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(sockets[0], {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  sockets[0].remoteClose(1006);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();

  assert.deepEqual(urls, [
    "wss://gateway.example/?v=10&encoding=json",
    "wss://resume.discord.gg?v=10&encoding=json",
    "wss://gateway.example/?v=10&encoding=json",
  ]);
  packet(sockets[1], {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.deepEqual(sockets[1].sent[0], {
    op: 6,
    d: { token: "token", session_id: "session-1", seq: 42 },
  });

  await client.stop();
});

test("Discord falls back after a pre-Hello resume gateway close", async () => {
  const { client, sockets, urls } = createClient();
  client.start();
  packet(sockets[0], {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  packet(sockets[0], {
    op: 0,
    t: "READY",
    s: 42,
    d: {
      session_id: "session-1",
      resume_gateway_url: "wss://resume.discord.gg",
    },
  });

  sockets[0].remoteClose(1006);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();
  sockets[1].remoteClose(1006);
  clearTimeout(client.reconnectTimer);
  client.reconnectTimer = null;
  client.connect();

  assert.deepEqual(urls, [
    "wss://gateway.example/?v=10&encoding=json",
    "wss://resume.discord.gg?v=10&encoding=json",
    "wss://gateway.example/?v=10&encoding=json",
  ]);
  packet(sockets[2], {
    op: 10,
    t: null,
    d: { heartbeat_interval: 60_000 },
  });
  assert.deepEqual(sockets[2].sent[0], {
    op: 6,
    d: { token: "token", session_id: "session-1", seq: 42 },
  });

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
