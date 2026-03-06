import { logger } from "../utils/logger.js";

interface TelegramUser {
  id: number;
  username?: string;
  first_name?: string;
  last_name?: string;
}

interface TelegramChat {
  id: number;
}

interface TelegramMessage {
  message_id: number;
  chat: TelegramChat;
  from?: TelegramUser;
  text?: string;
}

interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
}

interface TelegramGetUpdatesResponse {
  ok: boolean;
  result: TelegramUpdate[];
}

export interface TelegramPollingOptions {
  botToken: string;
  pollIntervalMs: number;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
}

export class TelegramPollingClient {
  private readonly baseUrl: string;
  private readonly pollIntervalMs: number;
  private readonly onMessage: TelegramPollingOptions["onMessage"];
  private running = false;
  private loopPromise: Promise<void> | null = null;
  private offset = 0;

  constructor(options: TelegramPollingOptions) {
    this.baseUrl = `https://api.telegram.org/bot${options.botToken}`;
    this.pollIntervalMs = options.pollIntervalMs;
    this.onMessage = options.onMessage;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.loopPromise = this.loop();
    logger.info("Telegram polling client started");
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.loopPromise) {
      await this.loopPromise;
      this.loopPromise = null;
    }
    logger.info("Telegram polling client stopped");
  }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        const updates = await this.getUpdates();
        for (const update of updates) {
          this.offset = Math.max(this.offset, update.update_id + 1);
          await this.handleUpdate(update);
        }
      } catch (err) {
        logger.error({ err }, "Telegram polling loop error");
      }

      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
    }
  }

  private async getUpdates(): Promise<TelegramUpdate[]> {
    const url = new URL(`${this.baseUrl}/getUpdates`);
    url.searchParams.set("timeout", "25");
    url.searchParams.set("allowed_updates", '["message"]');
    if (this.offset > 0) {
      url.searchParams.set("offset", String(this.offset));
    }

    const resp = await fetch(url, {
      signal: AbortSignal.timeout(35_000),
    });

    if (!resp.ok) {
      throw new Error(`Telegram getUpdates failed: ${resp.status}`);
    }

    const data = (await resp.json()) as TelegramGetUpdatesResponse;
    if (!data.ok) {
      throw new Error("Telegram getUpdates returned ok=false");
    }

    return data.result ?? [];
  }

  private async handleUpdate(update: TelegramUpdate): Promise<void> {
    const msg = update.message;
    if (!msg?.text?.trim()) {
      return;
    }

    const userName =
      msg.from?.username ||
      [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(" ") ||
      "telegram-user";

    const conversationId = `telegram:${msg.chat.id}`;
    const answer = await this.onMessage({
      conversationId,
      userName,
      text: msg.text,
    });

    if (!answer.trim()) return;

    await this.sendMessage(msg.chat.id, answer);
  }

  private async sendMessage(chatId: number, text: string): Promise<void> {
    const chunks = splitForTelegram(text, 4000);
    for (const chunk of chunks) {
      const resp = await fetch(`${this.baseUrl}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text: chunk,
          disable_web_page_preview: true,
        }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) {
        throw new Error(`Telegram sendMessage failed: ${resp.status}`);
      }
    }
  }
}

function splitForTelegram(text: string, maxLength: number): string[] {
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
