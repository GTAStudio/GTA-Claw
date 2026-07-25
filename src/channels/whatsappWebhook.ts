import type { Next, Request, Response } from "restify";
import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";
import { splitMessage } from "../utils/splitMessage.js";

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

export interface WhatsAppWebhookOptions {
  verifyToken: string;
  accessToken: string;
  phoneNumberId: string;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
}

export class WhatsAppWebhookHandler {
  private readonly verifyToken: string;
  private readonly accessToken: string;
  private readonly phoneNumberId: string;
  private readonly onMessage: WhatsAppWebhookOptions["onMessage"];

  constructor(options: WhatsAppWebhookOptions) {
    this.verifyToken = options.verifyToken;
    this.accessToken = options.accessToken;
    this.phoneNumberId = options.phoneNumberId;
    this.onMessage = options.onMessage;
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
    try {
      const body = (req.body ?? {}) as WhatsAppWebhookBody;
      const entries = body.entry ?? [];

      for (const entry of entries) {
        for (const change of entry.changes ?? []) {
          for (const msg of change.value?.messages ?? []) {
            if (msg.type !== "text") continue;
            const text = msg.text?.body?.trim();
            if (!text) continue;

            const from = msg.from;
            const conversationId = `whatsapp:${from}`;
            const reply = await this.onMessage({
              conversationId,
              userName: from,
              text,
            });

            if (!reply.trim()) continue;
            await this.sendText(from, reply);
          }
        }
      }

      res.send(200, { ok: true });
    } catch (err) {
      logger.error({ err }, "WhatsApp webhook handling failed");
      res.send(500, { error: "Webhook handling failed" });
    }

    next();
  };

  private async sendText(to: string, text: string): Promise<void> {
    for (const chunk of splitMessage(text, 3500)) {
      const resp = await fetch(
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
