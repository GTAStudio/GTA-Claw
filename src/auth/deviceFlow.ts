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

export interface DeviceFlowOptions {
  clientId: string;
  onTokenAcquired: (token: string, login: string) => Promise<void>;
  fetchFn?: typeof defaultFetch;
  scheduleFn?: (
    callback: () => void,
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

    const startPromise = this.startFlow().catch((err: unknown) => {
      logger.error({ err }, "Failed to start Device Flow");
      return "Failed to start GitHub Device Flow. Please check the logs.";
    });
    this.flowStartPromise = startPromise;
    try {
      return await startPromise;
    } finally {
      if (this.flowStartPromise === startPromise) {
        this.flowStartPromise = null;
      }
    }
  }

  private async startFlow(): Promise<string> {
    const resp = await this.fetchFn("https://github.com/login/device/code", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: this.clientId, scope: "copilot" }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!resp.ok) {
      throw new Error(`Device code request failed: ${resp.status}`);
    }

    const data = (await resp.json()) as DeviceCodeResponse;
    this.pendingUserCode = data.user_code;
    this.pendingVerificationUri = data.verification_uri;
    this.flowExpiresAt = Date.now() + data.expires_in * 1000;

    this.startPolling(data.device_code, data.interval);

    logger.info(
      { userCode: data.user_code },
      "Device Flow started — waiting for user authorization",
    );

    return this.formatAuthMessage(data.verification_uri, data.user_code);
  }

  private startPolling(deviceCode: string, intervalSec: number): void {
    this.stopPolling();

    const poll = async (): Promise<void> => {
      this.pollTimer = null;
      if (Date.now() >= this.flowExpiresAt) {
        logger.warn("Device Flow expired");
        this.clearPendingFlow();
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
            signal: AbortSignal.timeout(15_000),
          },
        );

        if (!resp.ok) {
          this.schedulePoll(poll, intervalSec * 1000);
          return;
        }

        const data = (await resp.json()) as TokenPollResponse;

        if (data.access_token) {
          const login = await this.fetchUserLogin(data.access_token);
          this.clearPendingFlow();
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
            this.schedulePoll(poll, intervalSec * 1000);
            break;
          case "slow_down":
            this.schedulePoll(poll, (intervalSec + 5) * 1000);
            break;
          case "expired_token":
            logger.warn("Device Flow code expired");
            this.clearPendingFlow();
            break;
          case "access_denied":
            logger.warn("Device Flow authorization denied by user");
            this.clearPendingFlow();
            break;
          default:
            logger.warn({ error: data.error }, "Device Flow poll unexpected error");
            this.schedulePoll(poll, intervalSec * 1000);
        }
      } catch (err) {
        logger.error({ err }, "Device Flow poll error");
        this.schedulePoll(poll, intervalSec * 1000);
      }
    };

    this.schedulePoll(poll, intervalSec * 1000);
  }

  private async fetchUserLogin(token: string): Promise<string> {
    try {
      const resp = await this.fetchFn("https://api.github.com/user", {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "User-Agent": "gta-claw",
        },
        signal: AbortSignal.timeout(10_000),
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

  private schedulePoll(poll: () => Promise<void>, delayMs: number): void {
    this.pollTimer = this.scheduleFn(poll, delayMs);
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

  private clearPendingFlow(): void {
    this.stopPolling();
    this.pendingUserCode = null;
    this.pendingVerificationUri = null;
    this.flowExpiresAt = 0;
  }

  stop(): void {
    this.clearPendingFlow();
    this.acquiredToken = null;
  }
}
