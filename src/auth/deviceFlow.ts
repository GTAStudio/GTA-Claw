import { logger } from "../utils/logger.js";
import { fetch as defaultFetch } from "../utils/proxy.js";

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

interface TokenPollResponse {
  access_token?: string;
  error?: string;
}

class DeviceFlowInvalidatedError extends Error {
  constructor() {
    super("Device Flow was invalidated");
    this.name = "DeviceFlowInvalidatedError";
  }
}

export interface DeviceFlowOptions {
  clientId: string;
  onTokenAcquired: (token: string, login: string) => Promise<void>;
  fetchFn?: typeof defaultFetch;
  scheduleFn?: (
    callback: () => void | Promise<void>,
    delayMs: number,
  ) => ReturnType<typeof setTimeout>;
  clearScheduleFn?: (timer: ReturnType<typeof setTimeout>) => void;
}

/**
 * GitHub Device Flow authorization.
 *
 * Flow:
 * 1. Bot requests a device code from GitHub.
 * 2. User opens https://github.com/login/device and enters the code.
 * 3. Bot polls GitHub until the user authorizes (or the code expires).
 * 4. On success, onTokenAcquired is called with the access token.
 *
 * No domain, callback URL, or client secret needed.
 */
export class GitHubDeviceFlow {
  private readonly clientId: string;
  private readonly onTokenAcquired: (token: string, login: string) => Promise<void>;
  private readonly fetchFn: typeof defaultFetch;
  private readonly scheduleFn: NonNullable<DeviceFlowOptions["scheduleFn"]>;
  private readonly clearScheduleFn: NonNullable<
    DeviceFlowOptions["clearScheduleFn"]
  >;

  private pendingUserCode: string | null = null;
  private pendingVerificationUri: string | null = null;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private flowExpiresAt = 0;
  private flowStartPromise: Promise<string> | null = null;
  private flowGeneration = 0;
  private flowController: AbortController | null = null;
  private acquiredToken: { token: string; login: string } | null = null;
  private activationPromise: Promise<void> | null = null;

  constructor(options: DeviceFlowOptions) {
    this.clientId = options.clientId;
    this.onTokenAcquired = options.onTokenAcquired;
    this.fetchFn = options.fetchFn ?? defaultFetch;
    this.scheduleFn = options.scheduleFn ?? setTimeout;
    this.clearScheduleFn = options.clearScheduleFn ?? clearTimeout;
  }

  /** Returns a user-facing message with authorization instructions. Starts a new flow if none is pending. */
  async getAuthMessage(): Promise<string> {
    if (this.acquiredToken) {
      try {
        await this.activateAcquiredToken();
        return "GitHub authorization completed.";
      } catch (err) {
        logger.error({ err }, "Failed to activate acquired GitHub token");
        return "GitHub authorization succeeded, but GTA-Claw activation failed. Please try again.";
      }
    }

    if (this.pendingUserCode && Date.now() < this.flowExpiresAt) {
      return this.formatAuthMessage(
        this.pendingVerificationUri,
        this.pendingUserCode,
      );
    }

    if (this.flowStartPromise) {
      return this.flowStartPromise;
    }

    const { generation, signal } = this.beginFlow();
    const startPromise = this.startFlow(generation, signal).catch(
      (err: unknown) => {
        if (this.isCurrentFlow(generation)) {
          logger.error({ err }, "Failed to start Device Flow");
        }
        return "Failed to start GitHub Device Flow. Please check the logs.";
      },
    );
    this.flowStartPromise = startPromise;
    try {
      return await startPromise;
    } finally {
      if (this.flowStartPromise === startPromise) {
        this.flowStartPromise = null;
      }
    }
  }

  private async startFlow(
    generation: number,
    signal: AbortSignal,
  ): Promise<string> {
    const resp = await this.fetchFn("https://github.com/login/device/code", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: this.clientId, scope: "copilot" }),
      signal: AbortSignal.any([signal, AbortSignal.timeout(15_000)]),
    });
    this.assertCurrentFlow(generation);

    if (!resp.ok) {
      throw new Error(`Device code request failed: ${resp.status}`);
    }

    const data = (await resp.json()) as DeviceCodeResponse;
    this.assertCurrentFlow(generation);
    this.pendingUserCode = data.user_code;
    this.pendingVerificationUri = data.verification_uri;
    this.flowExpiresAt = Date.now() + data.expires_in * 1000;

    this.startPolling(data.device_code, data.interval, generation, signal);

    logger.info(
      { userCode: data.user_code },
      "Device Flow started — waiting for user authorization",
    );

    return this.formatAuthMessage(data.verification_uri, data.user_code);
  }

  private startPolling(
    deviceCode: string,
    intervalSec: number,
    generation: number,
    signal: AbortSignal,
  ): void {
    this.stopPolling();

    const poll = async (): Promise<void> => {
      if (!this.isCurrentFlow(generation)) {
        return;
      }
      if (Date.now() >= this.flowExpiresAt) {
        logger.warn("Device Flow expired");
        this.clearPendingFlow(generation);
        return;
      }

      try {
        const resp = await this.fetchFn(
          "https://github.com/login/oauth/access_token",
          {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              client_id: this.clientId,
              device_code: deviceCode,
              grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            }),
            signal: AbortSignal.any([signal, AbortSignal.timeout(15_000)]),
          },
        );
        if (!this.isCurrentFlow(generation)) {
          return;
        }

        if (!resp.ok) {
          this.schedulePoll(poll, intervalSec * 1000, generation);
          return;
        }

        const data = (await resp.json()) as TokenPollResponse;
        if (!this.isCurrentFlow(generation)) {
          return;
        }

        if (data.access_token) {
          const login = await this.fetchUserLogin(data.access_token, signal);
          if (!this.isCurrentFlow(generation)) {
            return;
          }
          this.clearPendingFlow(generation);
          this.acquiredToken = { token: data.access_token, login };
          logger.info({ login }, "Device Flow authorization completed");
          try {
            await this.activateAcquiredToken();
          } catch (err) {
            logger.error(
              { err, login },
              "GitHub token acquired but GTA-Claw activation failed",
            );
          }
          return;
        }

        switch (data.error) {
          case "authorization_pending":
            this.schedulePoll(poll, intervalSec * 1000, generation);
            break;
          case "slow_down":
            this.schedulePoll(poll, (intervalSec + 5) * 1000, generation);
            break;
          case "expired_token":
            logger.warn("Device Flow code expired");
            this.clearPendingFlow(generation);
            break;
          case "access_denied":
            logger.warn("Device Flow authorization denied by user");
            this.clearPendingFlow(generation);
            break;
          default:
            logger.warn({ error: data.error }, "Device Flow poll unexpected error");
            this.schedulePoll(poll, intervalSec * 1000, generation);
        }
      } catch (err) {
        if (!this.isCurrentFlow(generation)) {
          return;
        }
        logger.error({ err }, "Device Flow poll error");
        this.schedulePoll(poll, intervalSec * 1000, generation);
      }
    };

    this.schedulePoll(poll, intervalSec * 1000, generation);
  }

  private async fetchUserLogin(
    token: string,
    signal: AbortSignal,
  ): Promise<string> {
    try {
      const resp = await this.fetchFn("https://api.github.com/user", {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "User-Agent": "gta-claw",
        },
        signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
      });
      if (!resp.ok) return "unknown";
      const user = (await resp.json()) as { login?: string };
      return user.login ?? "unknown";
    } catch (err) {
      logger.warn({ err }, "Failed to fetch GitHub login for acquired token");
      return "unknown";
    }
  }

  private formatAuthMessage(
    verificationUri: string | null,
    userCode: string,
  ): string {
    return [
      "Please authorize GTA-Claw with your GitHub account:",
      `1. Open: ${verificationUri}`,
      `2. Enter code: **${userCode}**`,
    ].join("\n");
  }

  private schedulePoll(
    poll: () => Promise<void>,
    delayMs: number,
    generation: number,
  ): void {
    if (!this.isCurrentFlow(generation)) {
      return;
    }

    let timer: ReturnType<typeof setTimeout>;
    timer = this.scheduleFn(async () => {
      if (
        !this.isCurrentFlow(generation) ||
        this.pollTimer !== timer
      ) {
        return;
      }
      this.pollTimer = null;
      await poll();
    }, delayMs);
    this.pollTimer = timer;
  }

  private async activateAcquiredToken(): Promise<void> {
    if (!this.acquiredToken) {
      return;
    }
    if (this.activationPromise) {
      return this.activationPromise;
    }

    const acquiredToken = this.acquiredToken;
    const activationPromise = this.onTokenAcquired(
      acquiredToken.token,
      acquiredToken.login,
    ).then(() => {
      if (this.acquiredToken === acquiredToken) {
        this.acquiredToken = null;
      }
    });
    this.activationPromise = activationPromise;

    try {
      await activationPromise;
    } finally {
      if (this.activationPromise === activationPromise) {
        this.activationPromise = null;
      }
    }
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      this.clearScheduleFn(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private beginFlow(): { generation: number; signal: AbortSignal } {
    this.invalidatePendingFlow();
    const controller = new AbortController();
    this.flowController = controller;
    return {
      generation: this.flowGeneration,
      signal: controller.signal,
    };
  }

  private isCurrentFlow(generation: number): boolean {
    return generation === this.flowGeneration;
  }

  private assertCurrentFlow(generation: number): void {
    if (!this.isCurrentFlow(generation)) {
      throw new DeviceFlowInvalidatedError();
    }
  }

  private clearPendingFlow(generation: number): void {
    if (!this.isCurrentFlow(generation)) {
      return;
    }
    this.flowController?.abort();
    this.flowController = null;
    this.stopPolling();
    this.pendingUserCode = null;
    this.pendingVerificationUri = null;
    this.flowExpiresAt = 0;
  }

  private invalidatePendingFlow(): void {
    this.flowGeneration += 1;
    this.flowController?.abort();
    this.flowController = null;
    this.stopPolling();
    this.flowStartPromise = null;
    this.pendingUserCode = null;
    this.pendingVerificationUri = null;
    this.flowExpiresAt = 0;
  }

  stop(): void {
    this.invalidatePendingFlow();
    this.acquiredToken = null;
  }
}
