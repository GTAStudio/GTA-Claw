import type { Next, Request, Response } from "restify";
import { createHmac, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { logger } from "../utils/logger.js";
import { fetch as defaultFetch } from "../utils/proxy.js";
import {
  MessageGraphemeTooLongError,
  splitMessage,
} from "../utils/splitMessage.js";

const MAX_COMPLETED_MESSAGE_IDS = 10_000;
const MAX_DEAD_LETTERED_MESSAGE_IDS = 10_000;
const MAX_PENDING_REPLIES = 10_000;
export const MAX_WHATSAPP_WEBHOOK_BODY_BYTES = 1024 * 1024;
const gunzipAsync = promisify(gunzip);

class WhatsAppWebhookBodyError extends Error {
  constructor(
    readonly statusCode: number,
    readonly clientMessage: string,
    options?: ErrorOptions,
  ) {
    super(clientMessage, options);
    this.name = "WhatsAppWebhookBodyError";
  }
}

interface WhatsAppTextMessage {
  from: string;
  id: string;
  timestamp: string;
  text?: { body?: string };
  type?: string;
}

interface WhatsAppValue {
  messaging_product?: string;
  metadata?: {
    phone_number_id?: string;
  };
  messages?: WhatsAppTextMessage[];
}

interface WhatsAppChange {
  value?: WhatsAppValue;
}

interface WhatsAppEntry {
  changes?: WhatsAppChange[];
}

interface WhatsAppWebhookBody {
  entry?: WhatsAppEntry[];
}

interface WhatsAppRawRequest extends Request {
  whatsappRawBody?: Buffer;
}

export function isWhatsAppWebhookPost(
  req: Pick<Request, "method" | "url">,
  whatsappPath: string,
): boolean {
  return (
    req.method === "POST" &&
    req.url?.split("?", 1)[0] === whatsappPath
  );
}

export function captureWhatsAppRawBody(whatsappPath: string) {
  return (req: Request, res: Response, next: Next): void => {
    if (!isWhatsAppWebhookPost(req, whatsappPath)) {
      next();
      return;
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let oversized = false;
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      if (err) {
        next(err);
        return;
      }
      if (oversized) {
        res.send(413, { error: "WhatsApp webhook body too large" });
        next(false);
        return;
      }
      (req as WhatsAppRawRequest).whatsappRawBody = Buffer.concat(
        chunks,
        totalBytes,
      );
      next();
    };

    req.on("data", (chunk: Buffer | string) => {
      if (oversized) return;
      const buffer = Buffer.from(chunk);
      totalBytes += buffer.length;
      if (totalBytes > MAX_WHATSAPP_WEBHOOK_BODY_BYTES) {
        oversized = true;
        chunks.length = 0;
        return;
      }
      chunks.push(buffer);
    });
    req.once("end", () => finish());
    req.once("error", (err) =>
      finish(err instanceof Error ? err : new Error(String(err))),
    );
    req.once("aborted", () =>
      finish(new Error("WhatsApp webhook request was aborted")),
    );
  };
}

interface PendingWhatsAppReply {
  to: string;
  reply: string;
  chunks?: string[];
  nextChunk: number;
}

export interface WhatsAppWebhookOptions {
  verifyToken: string;
  accessToken: string;
  phoneNumberId: string;
  appSecret?: string;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
  fetchFn?: typeof defaultFetch;
}

export class WhatsAppWebhookHandler {
  private readonly verifyToken: string;
  private readonly accessToken: string;
  private readonly phoneNumberId: string;
  private readonly appSecret: string;
  private readonly onMessage: WhatsAppWebhookOptions["onMessage"];
  private readonly fetchFn: typeof defaultFetch;
  private readonly completedMessageIds = new Set<string>();
  private readonly deadLetteredMessageIds = new Map<string, string>();
  private readonly pendingReplies = new Map<string, PendingWhatsAppReply>();
  private readonly inFlightMessages = new Map<string, Promise<void>>();

  constructor(options: WhatsAppWebhookOptions) {
    const appSecret =
      options.appSecret ?? process.env["WHATSAPP_APP_SECRET"]?.trim();
    if (!appSecret) {
      throw new Error(
        "WhatsApp app secret is required via appSecret or WHATSAPP_APP_SECRET",
      );
    }

    this.verifyToken = options.verifyToken;
    this.accessToken = options.accessToken;
    this.phoneNumberId = options.phoneNumberId;
    this.appSecret = appSecret;
    this.onMessage = options.onMessage;
    this.fetchFn = options.fetchFn ?? defaultFetch;
  }

  verify = (req: Request, res: Response, next: Next): void => {
    const query = (req.query ?? {}) as Record<string, string | undefined>;
    const mode = query["hub.mode"];
    const token = query["hub.verify_token"];
    const challenge = query["hub.challenge"];

    if (mode === "subscribe" && token === this.verifyToken && challenge) {
      res.sendRaw(200, challenge, { "Content-Type": "text/plain" });
      next();
      return;
    }

    res.send(403, { error: "Forbidden" });
    next();
  };

  incoming = async (req: Request, res: Response, next: Next): Promise<void> => {
    if (!this.hasValidSignature(req)) {
      res.send(401, { error: "Invalid webhook signature" });
      next();
      return;
    }

    try {
      const body = await this.parseAuthenticatedBody(req);
      const entries = body.entry ?? [];

      for (const entry of entries) {
        for (const change of entry.changes ?? []) {
          const value = change.value;
          if (value?.metadata?.phone_number_id !== this.phoneNumberId) {
            continue;
          }
          for (const msg of value.messages ?? []) {
            if (msg.type !== "text") continue;
            const text = msg.text?.body?.trim();
            if (!text) continue;
            await this.processMessage(msg, text);
          }
        }
      }

      res.send(200, { ok: true });
    } catch (err) {
      if (err instanceof WhatsAppWebhookBodyError) {
        logger.warn({ err }, "Invalid WhatsApp webhook body");
        res.send(err.statusCode, { error: err.clientMessage });
      } else {
        logger.error({ err }, "WhatsApp webhook handling failed");
        res.send(500, { error: "Webhook handling failed" });
      }
    }

    next();
  };

  private hasValidSignature(req: Request): boolean {
    const rawSignature = req.headers["x-hub-signature-256"];
    if (typeof rawSignature !== "string") {
      return false;
    }

    const match = /^sha256=([a-fA-F0-9]{64})$/.exec(rawSignature);
    if (!match) {
      return false;
    }

    const rawBody = (req as WhatsAppRawRequest).whatsappRawBody;
    if (!Buffer.isBuffer(rawBody)) {
      return false;
    }

    const expected = createHmac("sha256", this.appSecret)
      .update(rawBody)
      .digest();
    const received = Buffer.from(match[1], "hex");
    return (
      received.length === expected.length &&
      timingSafeEqual(received, expected)
    );
  }

  private async parseAuthenticatedBody(
    req: Request,
  ): Promise<WhatsAppWebhookBody> {
    const rawBody = (req as WhatsAppRawRequest).whatsappRawBody;
    if (!Buffer.isBuffer(rawBody)) {
      throw new WhatsAppWebhookBodyError(
        400,
        "Missing WhatsApp webhook body",
      );
    }

    const encodingHeader = req.headers["content-encoding"];
    const encoding = (
      Array.isArray(encodingHeader)
        ? encodingHeader.join(",")
        : encodingHeader ?? "identity"
    )
      .trim()
      .toLowerCase();

    let decodedBody: Buffer;
    if (!encoding || encoding === "identity") {
      decodedBody = rawBody;
    } else if (encoding === "gzip") {
      try {
        decodedBody = await gunzipAsync(rawBody);
      } catch (err) {
        throw new WhatsAppWebhookBodyError(
          400,
          "Invalid gzip WhatsApp webhook body",
          { cause: err },
        );
      }
    } else {
      throw new WhatsAppWebhookBodyError(
        415,
        `Unsupported Content-Encoding: ${encoding}`,
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(decodedBody.toString("utf8"));
    } catch (err) {
      throw new WhatsAppWebhookBodyError(
        400,
        "Invalid JSON WhatsApp webhook body",
        { cause: err },
      );
    }

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new WhatsAppWebhookBodyError(
        400,
        "Invalid JSON WhatsApp webhook body",
      );
    }
    return parsed as WhatsAppWebhookBody;
  }

  private async processMessage(
    msg: WhatsAppTextMessage,
    text: string,
  ): Promise<void> {
    const messageId = msg.id?.trim();
    if (!messageId) {
      await this.processTextMessage(msg.from, text);
      return;
    }

    if (
      this.completedMessageIds.has(messageId) ||
      this.deadLetteredMessageIds.has(messageId)
    ) {
      return;
    }

    const existing = this.inFlightMessages.get(messageId);
    if (existing) {
      await existing;
      return;
    }

    const processing = this.processIdentifiedMessage(messageId, msg.from, text);
    this.inFlightMessages.set(messageId, processing);

    try {
      await processing;
    } finally {
      if (this.inFlightMessages.get(messageId) === processing) {
        this.inFlightMessages.delete(messageId);
      }
    }
  }

  private async processIdentifiedMessage(
    messageId: string,
    from: string,
    text: string,
  ): Promise<void> {
    let pendingReply = this.pendingReplies.get(messageId);
    if (!pendingReply) {
      if (
        this.pendingReplies.size + this.inFlightMessages.size >=
        MAX_PENDING_REPLIES
      ) {
        throw new Error("WhatsApp pending reply capacity exceeded");
      }
      const reply = await this.onMessage({
        conversationId: `whatsapp:${from}`,
        userName: from,
        text,
      });
      pendingReply = {
        to: from,
        reply,
        nextChunk: 0,
      };
      this.pendingReplies.set(messageId, pendingReply);
    }

    let chunks = pendingReply.chunks;
    if (!chunks) {
      try {
        chunks = pendingReply.reply.trim()
          ? splitMessage(pendingReply.reply, 3500)
          : [];
        pendingReply.chunks = chunks;
      } catch (err) {
        if (!(err instanceof MessageGraphemeTooLongError)) {
          throw err;
        }
        this.pendingReplies.delete(messageId);
        this.recordDeadLetter(messageId, err.message);
        return;
      }
    }

    while (pendingReply.nextChunk < chunks.length) {
      await this.sendText(
        pendingReply.to,
        chunks[pendingReply.nextChunk],
      );
      pendingReply.nextChunk += 1;
    }

    this.pendingReplies.delete(messageId);
    this.rememberCompletedMessage(messageId);
  }

  private async processTextMessage(from: string, text: string): Promise<void> {
    const reply = await this.onMessage({
      conversationId: `whatsapp:${from}`,
      userName: from,
      text,
    });

    if (reply.trim()) {
      await this.sendText(from, reply);
    }
  }

  private rememberCompletedMessage(messageId: string): void {
    this.completedMessageIds.add(messageId);
    if (this.completedMessageIds.size <= MAX_COMPLETED_MESSAGE_IDS) {
      return;
    }

    const oldest = this.completedMessageIds.values().next().value;
    if (oldest !== undefined) {
      this.completedMessageIds.delete(oldest);
    }
  }

  private recordDeadLetter(messageId: string, reason: string): void {
    if (this.deadLetteredMessageIds.has(messageId)) {
      return;
    }

    this.deadLetteredMessageIds.set(messageId, reason);
    logger.error(
      { messageId, reason },
      "WhatsApp message permanently failed and was dead-lettered",
    );

    if (this.deadLetteredMessageIds.size > MAX_DEAD_LETTERED_MESSAGE_IDS) {
      const oldest = this.deadLetteredMessageIds.keys().next().value;
      if (oldest !== undefined) {
        this.deadLetteredMessageIds.delete(oldest);
      }
    }
  }

  private async sendText(to: string, text: string): Promise<void> {
    for (const chunk of splitMessage(text, 3500)) {
      const resp = await this.fetchFn(
        `https://graph.facebook.com/v20.0/${this.phoneNumberId}/messages`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            messaging_product: "whatsapp",
            to,
            type: "text",
            text: { body: chunk },
          }),
          signal: AbortSignal.timeout(10_000),
        },
      );

      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(
          `WhatsApp send failed: ${resp.status} ${resp.statusText} ${body}`,
        );
      }
    }
  }
}
