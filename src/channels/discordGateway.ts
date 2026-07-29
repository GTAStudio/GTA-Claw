import WebSocket from "ws";
import { logger } from "../utils/logger.js";
import { fetch as defaultFetch } from "../utils/proxy.js";
import { splitMessage } from "../utils/splitMessage.js";

interface DiscordGatewayPacket {
  op: number;
  t: string | null;
  s?: number | null;
  d: unknown;
}

interface DiscordMessageCreate {
  id: string;
  channel_id: string;
  content: string;
  author: {
    id: string;
    username: string;
    bot?: boolean;
  };
}

const NON_RESUMABLE_CLOSE_CODES = new Set([4007, 4009]);
const FATAL_CLOSE_CODES = new Set([4004, 4010, 4011, 4012, 4013, 4014]);

export interface DiscordGatewayOptions {
  botToken: string;
  gatewayUrl: string;
  intents: number;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
  webSocketFactory?: (url: string) => WebSocket;
  fetchFn?: typeof defaultFetch;
}

export class DiscordGatewayClient {
  private readonly botToken: string;
  private readonly gatewayUrl: string;
  private readonly intents: number;
  private readonly onMessage: DiscordGatewayOptions["onMessage"];
  private readonly webSocketFactory: (url: string) => WebSocket;
  private readonly fetchFn: typeof defaultFetch;

  private ws: WebSocket | null = null;
  private running = false;
  private seq: number | null = null;
  private sessionId: string | null = null;
  private resumeGatewayUrl: string | null = null;
  private heartbeatAcked = true;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private conversationQueue: Promise<void> = Promise.resolve();

  constructor(options: DiscordGatewayOptions) {
    this.botToken = options.botToken;
    this.gatewayUrl = options.gatewayUrl;
    this.intents = options.intents;
    this.onMessage = options.onMessage;
    this.webSocketFactory =
      options.webSocketFactory ?? ((url) => new WebSocket(url));
    this.fetchFn = options.fetchFn ?? defaultFetch;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.connect();
    logger.info("Discord gateway client started");
  }

  async stop(): Promise<void> {
    this.running = false;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.ws) {
      const ws = this.ws;
      this.ws = null;
      ws.removeAllListeners();
      ws.on("error", (err) => {
        logger.debug({ err }, "Discord gateway error during shutdown");
      });
      try {
        ws.close();
      } catch (err) {
        logger.error({ err }, "Failed to close Discord gateway");
      }
    }

    logger.info("Discord gateway client stopped");
  }

  private connect(): void {
    if (!this.running) return;

    const connection = this.getConnectionTarget();
    let ws: WebSocket;
    try {
      ws = this.webSocketFactory(connection.url);
    } catch (err) {
      logger.error({ err }, "Failed to create Discord gateway connection");
      if (connection.isResume) {
        this.resumeGatewayUrl = null;
      }
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    let receivedHello = false;

    ws.on("open", () => {
      if (this.ws !== ws) return;
      logger.info("Discord gateway connected");
    });

    ws.on("message", (raw) => {
      if (this.ws !== ws) return;
      try {
        receivedHello = this.handlePacket(raw.toString(), ws) || receivedHello;
      } catch (err) {
        logger.error({ err }, "Discord gateway packet handling failed");
      }
    });

    ws.on("close", (code) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.clearHeartbeat();
      if (connection.isResume && !receivedHello) {
        this.resumeGatewayUrl = null;
      }
      if (NON_RESUMABLE_CLOSE_CODES.has(code)) {
        this.clearSession();
      }
      if (FATAL_CLOSE_CODES.has(code)) {
        this.running = false;
        logger.error(
          { code },
          "Discord gateway closed with an unrecoverable error",
        );
        return;
      }
      logger.warn("Discord gateway disconnected");
      this.scheduleReconnect();
    });

    ws.on("error", (err) => {
      if (this.ws !== ws) return;
      logger.error({ err }, "Discord gateway error");
    });
  }

  private scheduleReconnect(): void {
    if (!this.running) return;
    this.clearHeartbeat();

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 3000);
  }

  private handlePacket(raw: string, ws: WebSocket): boolean {
    const packet = JSON.parse(raw) as DiscordGatewayPacket;
    if (
      typeof packet.s === "number" &&
      Number.isSafeInteger(packet.s) &&
      packet.s >= 0
    ) {
      this.seq = packet.s;
    }

    switch (packet.op) {
      case 10: {
        const data = packet.d as { heartbeat_interval: number };
        this.startHeartbeat(ws, data.heartbeat_interval);
        if (this.sessionId && this.seq !== null) {
          this.resume();
        } else {
          this.identify();
        }
        break;
      }
      case 0: {
        this.handleDispatch(packet.t, packet.d);
        break;
      }
      case 1: {
        this.sendHeartbeat(ws, false);
        break;
      }
      case 7: {
        logger.warn({ op: packet.op }, "Discord requested reconnect");
        this.closeSocket(ws);
        break;
      }
      case 9: {
        if (packet.d !== true) {
          this.clearSession();
        }
        logger.warn(
          { resumable: packet.d === true },
          "Discord session invalidated",
        );
        this.closeSocket(ws);
        break;
      }
      case 11: {
        this.heartbeatAcked = true;
        break;
      }
      default:
        break;
    }

    return packet.op === 10;
  }

  private startHeartbeat(ws: WebSocket, intervalMs: number): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatAcked = true;
    this.heartbeatTimer = setInterval(() => {
      if (this.ws === ws) {
        this.sendHeartbeat(ws, true);
      }
    }, intervalMs);
  }

  private sendHeartbeat(ws: WebSocket, enforceLiveness: boolean): void {
    if (enforceLiveness && !this.heartbeatAcked) {
      logger.warn("Discord heartbeat ACK was not received; reconnecting");
      this.terminateSocket(ws);
      return;
    }

    if (this.sendOnSocket(ws, { op: 1, d: this.seq })) {
      this.heartbeatAcked = false;
    }
  }

  private identify(): void {
    this.send({
      op: 2,
      d: {
        token: this.botToken,
        intents: this.intents,
        properties: {
          os: process.platform,
          browser: "gta-claw",
          device: "gta-claw",
        },
      },
    });
  }

  private resume(): void {
    this.send({
      op: 6,
      d: {
        token: this.botToken,
        session_id: this.sessionId,
        seq: this.seq,
      },
    });
  }

  private send(payload: unknown): void {
    if (this.ws) {
      this.sendOnSocket(this.ws, payload);
    }
  }

  private sendOnSocket(ws: WebSocket, payload: unknown): boolean {
    if (this.ws !== ws || ws.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      ws.send(JSON.stringify(payload), (err) => {
        if (!err || this.ws !== ws) return;
        logger.error({ err }, "Discord gateway send failed");
        this.terminateSocket(ws);
      });
      return true;
    } catch (err) {
      logger.error({ err }, "Discord gateway send failed");
      this.terminateSocket(ws);
      return false;
    }
  }

  private handleDispatch(eventType: string | null, data: unknown): void {
    if (eventType === "READY") {
      const ready = data as {
        session_id: string;
        resume_gateway_url?: string;
      };
      this.sessionId = ready.session_id;
      this.resumeGatewayUrl = ready.resume_gateway_url ?? null;
      logger.info({ sessionId: this.sessionId }, "Discord READY received");
      return;
    }

    if (eventType !== "MESSAGE_CREATE") {
      return;
    }

    const msg = data as DiscordMessageCreate;
    if (!msg.content?.trim()) return;
    if (msg.author.bot) return;

    this.conversationQueue = this.conversationQueue
      .then(() => this.handleMessage(msg))
      .catch((err: unknown) => {
        logger.error(
          { err, channelId: msg.channel_id, messageId: msg.id },
          "Discord message handling failed",
        );
      });
  }

  private async handleMessage(msg: DiscordMessageCreate): Promise<void> {
    const conversationId = `discord:${msg.channel_id}:${msg.author.id}`;
    const reply = await this.onMessage({
      conversationId,
      userName: msg.author.username,
      text: msg.content,
    });

    if (!reply.trim()) return;

    await this.sendChannelMessage(msg.channel_id, reply);
  }

  private async sendChannelMessage(channelId: string, text: string): Promise<void> {
    const chunks = splitMessage(text, 1900);
    for (const chunk of chunks) {
      const resp = await this.fetchFn(
        `https://discord.com/api/v10/channels/${channelId}/messages`,
        {
          method: "POST",
          headers: {
            Authorization: `Bot ${this.botToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ content: chunk }),
          signal: AbortSignal.timeout(10_000),
        },
      );

      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(
          `Discord send message failed: ${resp.status} ${resp.statusText} ${body}`,
        );
      }
    }
  }

  private getConnectionTarget(): { url: string; isResume: boolean } {
    if (!this.resumeGatewayUrl) {
      return { url: this.gatewayUrl, isResume: false };
    }

    try {
      const url = new URL(this.resumeGatewayUrl);
      if (!url.searchParams.has("v")) {
        url.searchParams.set("v", "10");
      }
      if (!url.searchParams.has("encoding")) {
        url.searchParams.set("encoding", "json");
      }
      return { url: url.toString(), isResume: true };
    } catch (err) {
      logger.error(
        { err, resumeGatewayUrl: this.resumeGatewayUrl },
        "Invalid Discord resume gateway URL",
      );
      this.resumeGatewayUrl = null;
      return { url: this.gatewayUrl, isResume: false };
    }
  }

  private closeSocket(ws: WebSocket): void {
    if (this.ws !== ws) return;
    try {
      ws.close();
    } catch (err) {
      logger.error({ err }, "Failed to close Discord gateway");
      this.terminateSocket(ws);
    }
  }

  private terminateSocket(ws: WebSocket): void {
    if (this.ws !== ws) return;
    try {
      ws.terminate();
    } catch (err) {
      logger.error({ err }, "Failed to terminate Discord gateway");
    }
  }

  private clearSession(): void {
    this.seq = null;
    this.sessionId = null;
    this.resumeGatewayUrl = null;
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}

function splitForDiscord(text: string, maxLength: number): string[] {
  if (text.length <= maxLength) return [text];

  const out: string[] = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      out.push(remaining);
      break;
    }

    let splitAt = remaining.lastIndexOf("\n", maxLength);
    if (splitAt < maxLength * 0.5) splitAt = remaining.lastIndexOf(" ", maxLength);
    if (splitAt < maxLength * 0.3) splitAt = maxLength;

    out.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt).trimStart();
  }

  return out;
}
