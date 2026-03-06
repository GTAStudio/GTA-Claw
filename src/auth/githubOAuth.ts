import { randomBytes } from "node:crypto";
import type { Next, Request, Response } from "restify";
import { logger } from "../utils/logger.js";

interface OAuthStateEntry {
  createdAt: number;
}

interface OAuthSessionEntry {
  id: string;
  token: string;
  login: string;
  createdAt: number;
  lastAccess: number;
}

export interface OAuthStatus {
  enabled: boolean;
  authenticated: boolean;
  user?: string;
  callbackPath: string;
}

export interface GitHubOAuthManagerOptions {
  clientId: string;
  clientSecret: string;
  baseUrl: string;
  callbackPath: string;
  scope: string;
  sessionTtlMs: number;
  onTokenAuthorized: (token: string, login: string) => Promise<void>;
}

const STATE_TTL_MS = 10 * 60_000;
const COOKIE_NAME = "gta_oauth_session";

function parseCookieHeader(raw: string | undefined): Record<string, string> {
  if (!raw) return {};

  const parsed: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (!key || rest.length === 0) continue;
    parsed[key] = decodeURIComponent(rest.join("="));
  }
  return parsed;
}

function serializeCookie(
  name: string,
  value: string,
  options: {
    maxAgeSec?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "Lax" | "Strict" | "None";
    path?: string;
  } = {},
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path ?? "/"}`);

  if (options.maxAgeSec !== undefined) {
    parts.push(`Max-Age=${options.maxAgeSec}`);
  }
  if (options.httpOnly ?? true) {
    parts.push("HttpOnly");
  }
  if (options.secure ?? true) {
    parts.push("Secure");
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }

  return parts.join("; ");
}

export class GitHubOAuthManager {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly baseUrl: string;
  private readonly callbackPath: string;
  private readonly scope: string;
  private readonly sessionTtlMs: number;
  private readonly onTokenAuthorized: (
    token: string,
    login: string,
  ) => Promise<void>;

  private readonly stateStore = new Map<string, OAuthStateEntry>();
  private readonly sessionStore = new Map<string, OAuthSessionEntry>();

  constructor(options: GitHubOAuthManagerOptions) {
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.callbackPath = options.callbackPath;
    this.scope = options.scope;
    this.sessionTtlMs = options.sessionTtlMs;
    this.onTokenAuthorized = options.onTokenAuthorized;
  }

  private now(): number {
    return Date.now();
  }

  private cleanupExpired(): void {
    const now = this.now();

    for (const [state, entry] of this.stateStore) {
      if (now - entry.createdAt > STATE_TTL_MS) {
        this.stateStore.delete(state);
      }
    }

    for (const [sessionId, entry] of this.sessionStore) {
      if (now - entry.lastAccess > this.sessionTtlMs) {
        this.sessionStore.delete(sessionId);
      }
    }
  }

  private createState(): string {
    const state = randomBytes(24).toString("hex");
    this.stateStore.set(state, { createdAt: this.now() });
    return state;
  }

  private consumeState(state: string): boolean {
    const entry = this.stateStore.get(state);
    if (!entry) return false;

    this.stateStore.delete(state);
    return this.now() - entry.createdAt <= STATE_TTL_MS;
  }

  private getSessionIdFromRequest(req: Request): string | undefined {
    const cookieHeader = req.headers["cookie"];
    const raw = Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader;
    const cookies = parseCookieHeader(raw);
    return cookies[COOKIE_NAME];
  }

  private createSession(token: string, login: string): OAuthSessionEntry {
    const id = randomBytes(32).toString("hex");
    const now = this.now();
    const entry: OAuthSessionEntry = {
      id,
      token,
      login,
      createdAt: now,
      lastAccess: now,
    };
    this.sessionStore.set(id, entry);
    return entry;
  }

  private getSession(req: Request): OAuthSessionEntry | undefined {
    this.cleanupExpired();

    const sessionId = this.getSessionIdFromRequest(req);
    if (!sessionId) return undefined;

    const session = this.sessionStore.get(sessionId);
    if (!session) return undefined;

    session.lastAccess = this.now();
    return session;
  }

  getStatus(req: Request): OAuthStatus {
    const session = this.getSession(req);
    return {
      enabled: true,
      authenticated: Boolean(session),
      user: session?.login,
      callbackPath: this.callbackPath,
    };
  }

  login = async (req: Request, res: Response, next: Next): Promise<void> => {
    void req;
    const state = this.createState();
    const redirectUri = `${this.baseUrl}${this.callbackPath}`;

    const authUrl = new URL("https://github.com/login/oauth/authorize");
    authUrl.searchParams.set("client_id", this.clientId);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("scope", this.scope);
    authUrl.searchParams.set("state", state);

    logger.info("Redirecting user to GitHub OAuth authorization page");
    res.header("Location", authUrl.toString());
    res.send(302);
    next();
  };

  callback = async (
    req: Request,
    res: Response,
    next: Next,
  ): Promise<void> => {
    this.cleanupExpired();

    const query = (req.query ?? {}) as Record<string, string | undefined>;
    const code = query["code"];
    const state = query["state"];
    const error = query["error"];

    if (error) {
      logger.warn({ error }, "GitHub OAuth callback returned error");
      res.send(400, { error: `OAuth authorization failed: ${error}` });
      next();
      return;
    }

    if (!code || !state || !this.consumeState(state)) {
      res.send(400, { error: "Invalid or expired OAuth callback state" });
      next();
      return;
    }

    try {
      const redirectUri = `${this.baseUrl}${this.callbackPath}`;

      const tokenResp = await fetch(
        "https://github.com/login/oauth/access_token",
        {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "User-Agent": "gta-claw-oauth",
          },
          body: JSON.stringify({
            client_id: this.clientId,
            client_secret: this.clientSecret,
            code,
            redirect_uri: redirectUri,
            state,
          }),
          signal: AbortSignal.timeout(15_000),
        },
      );

      if (!tokenResp.ok) {
        throw new Error(`Token exchange failed: ${tokenResp.status}`);
      }

      const tokenJson = (await tokenResp.json()) as {
        access_token?: string;
        error?: string;
        error_description?: string;
      };

      if (!tokenJson.access_token) {
        throw new Error(
          tokenJson.error_description ?? tokenJson.error ?? "No access token",
        );
      }

      const userResp = await fetch("https://api.github.com/user", {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${tokenJson.access_token}`,
          "User-Agent": "gta-claw-oauth",
        },
        signal: AbortSignal.timeout(10_000),
      });

      if (!userResp.ok) {
        throw new Error(`Failed to fetch GitHub user: ${userResp.status}`);
      }

      const user = (await userResp.json()) as { login?: string };
      const login = user.login ?? "unknown";

      await this.onTokenAuthorized(tokenJson.access_token, login);

      const session = this.createSession(tokenJson.access_token, login);
      const isHttps = this.baseUrl.startsWith("https://");
      res.header(
        "Set-Cookie",
        serializeCookie(COOKIE_NAME, session.id, {
          maxAgeSec: Math.floor(this.sessionTtlMs / 1000),
          httpOnly: true,
          secure: isHttps,
          sameSite: "Lax",
          path: "/",
        }),
      );

      logger.info({ user: login }, "GitHub OAuth authorization completed");
      res.send(200, {
        message: "OAuth authorization successful",
        user: login,
      });
    } catch (err) {
      logger.error({ err }, "OAuth callback handling failed");
      res.send(500, { error: "OAuth callback failed" });
    }

    next();
  };

  logout = (req: Request, res: Response, next: Next): void => {
    const sessionId = this.getSessionIdFromRequest(req);
    if (sessionId) {
      this.sessionStore.delete(sessionId);
    }

    const isHttps = this.baseUrl.startsWith("https://");
    res.header(
      "Set-Cookie",
      serializeCookie(COOKIE_NAME, "", {
        maxAgeSec: 0,
        httpOnly: true,
        secure: isHttps,
        sameSite: "Lax",
        path: "/",
      }),
    );
    res.send(200, { message: "Logged out" });
    next();
  };
}
