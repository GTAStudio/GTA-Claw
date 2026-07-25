import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

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

  private pendingUserCode: string | null = null;
  private pendingVerificationUri: string | null = null;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private flowExpiresAt = 0;

  constructor(options: DeviceFlowOptions) {
    this.clientId = options.clientId;
    this.onTokenAcquired = options.onTokenAcquired;
  }

  /** Returns a user-facing message with authorization instructions. Starts a new flow if none is pending. */
  async getAuthMessage(): Promise<string> {
    if (this.pendingUserCode && Date.now() < this.flowExpiresAt) {
      return [
        "Please authorize GTA-Claw with your GitHub account:",
        `1. Open: ${this.pendingVerificationUri}`,
        `2. Enter code: **${this.pendingUserCode}**`,
      ].join("\n");
    }

    try {
      const resp = await fetch("https://github.com/login/device/code", {
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

      logger.info({ userCode: data.user_code }, "Device Flow started — waiting for user authorization");

      return [
        "Please authorize GTA-Claw with your GitHub account:",
        `1. Open: ${data.verification_uri}`,
        `2. Enter code: **${data.user_code}**`,
      ].join("\n");
    } catch (err) {
      logger.error({ err }, "Failed to start Device Flow");
      return "Failed to start GitHub Device Flow. Please check the logs.";
    }
  }

  private startPolling(deviceCode: string, intervalSec: number): void {
    this.stopPolling();

    const poll = async (): Promise<void> => {
      if (Date.now() >= this.flowExpiresAt) {
        logger.warn("Device Flow expired");
        this.clearPending();
        return;
      }

      try {
        const resp = await fetch("https://github.com/login/oauth/access_token", {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/json" },
          body: JSON.stringify({
            client_id: this.clientId,
            device_code: deviceCode,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          }),
          signal: AbortSignal.timeout(15_000),
        });

        if (!resp.ok) {
          this.pollTimer = setTimeout(poll, intervalSec * 1000);
          return;
        }

        const data = (await resp.json()) as TokenPollResponse;

        if (data.access_token) {
          const login = await this.fetchUserLogin(data.access_token);
          logger.info({ login }, "Device Flow authorization completed");
          this.clearPending();
          await this.onTokenAcquired(data.access_token, login);
          return;
        }

        switch (data.error) {
          case "authorization_pending":
            this.pollTimer = setTimeout(poll, intervalSec * 1000);
            break;
          case "slow_down":
            this.pollTimer = setTimeout(poll, (intervalSec + 5) * 1000);
            break;
          case "expired_token":
            logger.warn("Device Flow code expired");
            this.clearPending();
            break;
          case "access_denied":
            logger.warn("Device Flow authorization denied by user");
            this.clearPending();
            break;
          default:
            logger.warn({ error: data.error }, "Device Flow poll unexpected error");
            this.pollTimer = setTimeout(poll, intervalSec * 1000);
        }
      } catch (err) {
        logger.error({ err }, "Device Flow poll error");
        this.pollTimer = setTimeout(poll, intervalSec * 1000);
      }
    };

    this.pollTimer = setTimeout(poll, intervalSec * 1000);
  }

  private async fetchUserLogin(token: string): Promise<string> {
    try {
      const resp = await fetch("https://api.github.com/user", {
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
    } catch {
      return "unknown";
    }
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  private clearPending(): void {
    this.stopPolling();
    this.pendingUserCode = null;
    this.pendingVerificationUri = null;
    this.flowExpiresAt = 0;
  }

  stop(): void {
    this.clearPending();
  }
}
