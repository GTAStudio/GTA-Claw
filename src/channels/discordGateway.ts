import WebSocket from "ws";
import { logger } from "../utils/logger.js";
import { splitMessage } from "../utils/splitMessage.js";

interface DiscordGatewayPacket {
  op: number;
  t: string | null;
  s: number | null;
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

export interface DiscordGatewayOptions {
  botToken: string;
  gatewayUrl: string;
  intents: number;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
}

export class DiscordGatewayClient {
  private readonly botToken: string;
  private readonly gatewayUrl: string;
  private readonly intents: number;
  private readonly onMessage: DiscordGatewayOptions["onMessage"];

  private ws: WebSocket | null = null;
  private running = false;
  private seq: number | null = null;
  private sessionId: string | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: DiscordGatewayOptions) {
    this.botToken = options.botToken;
    this.gatewayUrl = options.gatewayUrl;
    this.intents = options.intents;
    this.onMessage = options.onMessage;
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
      this.ws.removeAllListeners();
      this.ws.close();
      this.ws = null;
    }

    logger.info("Discord gateway client stopped");
  }

  private connect(): void {
    if (!this.running) return;

    const ws = new WebSocket(this.gatewayUrl);
    this.ws = ws;

    ws.on("open", () => {
      logger.info("Discord gateway connected");
    });

    ws.on("message", async (raw) => {
      await this.handlePacket(raw.toString());
    });

    ws.on("close", () => {
      logger.warn("Discord gateway disconnected");
      this.scheduleReconnect();
    });

    ws.on("error", (err) => {
      logger.error({ err }, "Discord gateway error");
    });
  }

  private scheduleReconnect(): void {
    if (!this.running) return;
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, 3000);
  }

  private async handlePacket(raw: string): Promise<void> {
    const packet = JSON.parse(raw) as DiscordGatewayPacket;
    if (packet.s !== null) {
      this.seq = packet.s;
    }

    switch (packet.op) {
      case 10: {
        const data = packet.d as { heartbeat_interval: number };
        this.startHeartbeat(data.heartbeat_interval);
        this.identify();
        break;
      }
      case 0: {
        await this.handleDispatch(packet.t, packet.d);
        break;
      }
      case 7:
      case 9: {
        logger.warn({ op: packet.op }, "Discord requested reconnect");
        this.ws?.close();
        break;
      }
      case 11:
      default:
        break;
    }
  }

  private startHeartbeat(intervalMs: number): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      this.send({ op: 1, d: this.seq });
    }, intervalMs);
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

  private send(payload: unknown): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify(payload));
  }

  private async handleDispatch(eventType: string | null, data: unknown): Promise<void> {
    if (eventType === "READY") {
      const ready = data as { session_id: string };
      this.sessionId = ready.session_id;
      logger.info({ sessionId: this.sessionId }, "Discord READY received");
      return;
    }

    if (eventType !== "MESSAGE_CREATE") {
      return;
    }

    const msg = data as DiscordMessageCreate;
    if (!msg.content?.trim()) return;
    if (msg.author.bot) return;

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
      const resp = await fetch(
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
