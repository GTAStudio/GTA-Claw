import { logger } from "../utils/logger.js";
import { fetch as defaultFetch } from "../utils/proxy.js";
import {
  MessageGraphemeTooLongError,
  splitMessage,
} from "../utils/splitMessage.js";

const MAX_DEAD_LETTERED_UPDATES = 1000;

class TelegramTerminalDeliveryError extends Error {
  constructor(readonly status: number) {
    super(`Telegram sendMessage failed with terminal status ${status}`);
    this.name = "TelegramTerminalDeliveryError";
  }
}

class TelegramRetryableDeliveryError extends Error {
  constructor(
    readonly status: number,
    readonly retryAfterMs: number | null,
  ) {
    super(`Telegram sendMessage failed with retryable status ${status}`);
    this.name = "TelegramRetryableDeliveryError";
  }
}

interface TelegramResponseParameters {
  retry_after?: number;
  migrate_to_chat_id?: number;
}

interface TelegramErrorResponse {
  parameters?: TelegramResponseParameters;
}

type TelegramFetchResponse = Awaited<ReturnType<typeof defaultFetch>>;

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

interface TelegramDeliveryCheckpoint {
  chatId: number;
  answer: string;
  chunks?: string[];
  nextChunk: number;
}

export interface TelegramPollingOptions {
  botToken: string;
  pollIntervalMs: number;
  onMessage: (input: {
    conversationId: string;
    userName: string;
    text: string;
  }) => Promise<string>;
  fetchFn?: typeof defaultFetch;
  waitFn?: (delayMs: number, signal: AbortSignal) => Promise<void>;
}

export class TelegramPollingClient {
  private readonly baseUrl: string;
  private readonly pollIntervalMs: number;
  private readonly onMessage: TelegramPollingOptions["onMessage"];
  private readonly fetchFn: typeof defaultFetch;
  private readonly waitFn: NonNullable<TelegramPollingOptions["waitFn"]>;
  private running = false;
  private loopPromise: Promise<void> | null = null;
  private lifecyclePromise: Promise<void> = Promise.resolve();
  private lifecycleController: AbortController | null = null;
  private offset = 0;
  // Checkpoints survive stop/start on this client; a process restart relies on Telegram redelivery.
  private readonly deliveryCheckpoints = new Map<
    number,
    TelegramDeliveryCheckpoint
  >();
  private readonly deadLetteredUpdates = new Map<number, string>();

  constructor(options: TelegramPollingOptions) {
    this.baseUrl = `https://api.telegram.org/bot${options.botToken}`;
    this.pollIntervalMs = options.pollIntervalMs;
    this.onMessage = options.onMessage;
    this.fetchFn = options.fetchFn ?? defaultFetch;
    this.waitFn = options.waitFn ?? waitForDelay;
  }

  start(): Promise<void> {
    const startPromise = this.lifecyclePromise.then(() => {
      if (this.running) return;

      this.running = true;
      this.lifecycleController = new AbortController();
      this.loopPromise = this.loop(this.lifecycleController.signal);
      logger.info("Telegram polling client started");
    });
    this.lifecyclePromise = startPromise.catch(() => undefined);
    return startPromise;
  }

  stop(): Promise<void> {
    const stopPromise = this.lifecyclePromise.then(async () => {
      this.running = false;
      this.lifecycleController?.abort();
      this.lifecycleController = null;

      const loopPromise = this.loopPromise;
      if (loopPromise) {
        await loopPromise;
        if (this.loopPromise === loopPromise) {
          this.loopPromise = null;
        }
      }
      logger.info("Telegram polling client stopped");
    });
    this.lifecyclePromise = stopPromise.catch(() => undefined);
    return stopPromise;
  }

  private async loop(signal: AbortSignal): Promise<void> {
    while (this.running && !signal.aborted) {
      let nextPollDelayMs = this.pollIntervalMs;
      try {
        const updates = await this.getUpdates(signal);
        await this.processUpdates(updates);
      } catch (err) {
        if (!this.running || signal.aborted) {
          break;
        }
        logger.error({ err }, "Telegram polling loop error");
        if (
          err instanceof TelegramRetryableDeliveryError &&
          err.retryAfterMs !== null
        ) {
          nextPollDelayMs = Math.max(nextPollDelayMs, err.retryAfterMs);
        }
      }

      if (this.running && !signal.aborted) {
        await this.waitFn(nextPollDelayMs, signal);
      }
    }
  }

  private async processUpdates(updates: TelegramUpdate[]): Promise<void> {
    for (const update of updates) {
      if (!this.deadLetteredUpdates.has(update.update_id)) {
        try {
          await this.handleUpdate(update);
        } catch (err) {
          const reason = this.terminalFailureReason(err);
          if (!reason) {
            throw err;
          }
          this.deliveryCheckpoints.delete(update.update_id);
          this.recordDeadLetter(update.update_id, reason);
        }
      }
      this.offset = Math.max(this.offset, update.update_id + 1);
    }
  }

  private async getUpdates(signal: AbortSignal): Promise<TelegramUpdate[]> {
    const url = new URL(`${this.baseUrl}/getUpdates`);
    url.searchParams.set("timeout", "25");
    url.searchParams.set("allowed_updates", '["message"]');
    if (this.offset > 0) {
      url.searchParams.set("offset", String(this.offset));
    }

    const resp = await this.fetchFn(url, {
      signal: AbortSignal.any([signal, AbortSignal.timeout(35_000)]),
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
    const existingCheckpoint = this.deliveryCheckpoints.get(update.update_id);
    if (existingCheckpoint) {
      await this.deliverCheckpoint(existingCheckpoint);
      this.deliveryCheckpoints.delete(update.update_id);
      return;
    }

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

    const checkpoint: TelegramDeliveryCheckpoint = {
      chatId: msg.chat.id,
      answer,
      nextChunk: 0,
    };
    this.deliveryCheckpoints.set(update.update_id, checkpoint);
    await this.deliverCheckpoint(checkpoint);
    this.deliveryCheckpoints.delete(update.update_id);
  }

  private async deliverCheckpoint(
    checkpoint: TelegramDeliveryCheckpoint,
  ): Promise<void> {
    checkpoint.chunks ??= splitMessage(checkpoint.answer, 4000);

    while (checkpoint.nextChunk < checkpoint.chunks.length) {
      const chunk = checkpoint.chunks[checkpoint.nextChunk];
      const resp = await this.fetchFn(`${this.baseUrl}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: checkpoint.chatId,
          text: chunk,
          disable_web_page_preview: true,
        }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) {
        const parameters = await this.readResponseParameters(resp);
        const retryAfterMs =
          parameters?.retry_after !== undefined
            ? parameters.retry_after * 1000
            : null;
        if (parameters?.migrate_to_chat_id !== undefined) {
          checkpoint.chatId = parameters.migrate_to_chat_id;
          throw new TelegramRetryableDeliveryError(resp.status, retryAfterMs);
        }
        if (retryAfterMs !== null) {
          throw new TelegramRetryableDeliveryError(resp.status, retryAfterMs);
        }
        if (resp.status >= 400 && resp.status < 500 && resp.status !== 429) {
          throw new TelegramTerminalDeliveryError(resp.status);
        }
        throw new TelegramRetryableDeliveryError(resp.status, null);
      }
      checkpoint.nextChunk += 1;
    }
  }

  private async readResponseParameters(
    resp: TelegramFetchResponse,
  ): Promise<TelegramResponseParameters | null> {
    let data: unknown;
    try {
      data = (await resp.json()) as TelegramErrorResponse;
    } catch (err) {
      logger.warn(
        { err, status: resp.status },
        "Telegram error response was not valid JSON",
      );
      return null;
    }

    if (typeof data !== "object" || data === null) {
      return null;
    }
    const parameters = (data as TelegramErrorResponse).parameters;
    if (typeof parameters !== "object" || parameters === null) {
      return null;
    }

    const parsed: TelegramResponseParameters = {};
    if (
      typeof parameters.retry_after === "number" &&
      Number.isSafeInteger(parameters.retry_after) &&
      parameters.retry_after >= 0
    ) {
      parsed.retry_after = parameters.retry_after;
    }
    if (
      typeof parameters.migrate_to_chat_id === "number" &&
      Number.isSafeInteger(parameters.migrate_to_chat_id)
    ) {
      parsed.migrate_to_chat_id = parameters.migrate_to_chat_id;
    }
    return parsed;
  }

  private terminalFailureReason(err: unknown): string | null {
    if (
      err instanceof TelegramTerminalDeliveryError ||
      err instanceof MessageGraphemeTooLongError
    ) {
      return err.message;
    }
    return null;
  }

  private recordDeadLetter(updateId: number, reason: string): void {
    if (this.deadLetteredUpdates.has(updateId)) {
      return;
    }

    this.deadLetteredUpdates.set(updateId, reason);
    logger.error(
      { updateId, reason },
      "Telegram update permanently failed and was dead-lettered",
    );

    if (this.deadLetteredUpdates.size > MAX_DEAD_LETTERED_UPDATES) {
      const oldest = this.deadLetteredUpdates.keys().next().value;
      if (oldest !== undefined) {
        this.deadLetteredUpdates.delete(oldest);
      }
    }
  }
}

function waitForDelay(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    const finish = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    };
    const timer = setTimeout(finish, delayMs);
    signal.addEventListener("abort", finish, { once: true });
  });
}
