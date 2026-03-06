import {
  BotFrameworkAdapter,
  type TurnContext,
} from "botbuilder";
import restify, { type Next, type Request, type Response } from "restify";
import { logger } from "./utils/logger.js";
import type { AgentBot } from "./bot/teamsBot.js";
import type { AppConfig } from "./config.js";
import type { CopilotEngine } from "./engine/copilotEngine.js";
import type { GitHubOAuthManager } from "./auth/githubOAuth.js";

interface RuntimeStatus {
  skillCount: number;
  activeModel: string;
}

interface ReloadResult {
  roleModel?: string;
  skillCount: number;
}

function parseBearerToken(authHeader: string | string[] | undefined): string | undefined {
  const value = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!value) return undefined;

  const trimmed = value.trim();
  const [scheme, ...rest] = trimmed.split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== "bearer" || rest.length === 0) {
    return undefined;
  }
  return rest.join(" ");
}

// Simple in-memory rate limiter (token bucket per IP)
class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; lastRefill: number }>();
  private readonly maxTokens: number;
  private readonly refillRate: number; // tokens per ms

  constructor(maxPerMinute: number) {
    this.maxTokens = maxPerMinute;
    this.refillRate = maxPerMinute / 60_000;
  }

  isAllowed(ip: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(ip);

    if (!bucket) {
      bucket = { tokens: this.maxTokens - 1, lastRefill: now };
      this.buckets.set(ip, bucket);
      return true;
    }

    // Refill tokens based on elapsed time
    const elapsed = now - bucket.lastRefill;
    bucket.tokens = Math.min(this.maxTokens, bucket.tokens + elapsed * this.refillRate);
    bucket.lastRefill = now;

    if (bucket.tokens < 1) {
      return false;
    }

    bucket.tokens -= 1;
    return true;
  }
}

interface ServerDeps {
  bot: AgentBot;
  config: AppConfig;
  getEngine: () => CopilotEngine | null;
  getRuntimeStatus: () => RuntimeStatus;
  oauthManager?: GitHubOAuthManager;
  reloadFn?: () => Promise<ReloadResult>;
}

const startTime = Date.now();

export function createServer(deps: ServerDeps): restify.Server {
  const { bot, config, getEngine, getRuntimeStatus } = deps;

  const server = restify.createServer({ name: "GTA-Claw" });
  server.use(restify.plugins.queryParser());
  const adapter = new BotFrameworkAdapter({
    appId: config.MICROSOFT_APP_ID,
    appPassword: config.MICROSOFT_APP_PASSWORD,
  });
  const rateLimiter = new RateLimiter(config.RATE_LIMIT_PER_MIN);

  // Adapter error handler
  adapter.onTurnError = async (context: TurnContext, error: Error) => {
    logger.error({ err: error }, "Bot adapter turn error");
    await context.sendActivity("An error occurred. Please try again later.");
  };

  // Rate limiting middleware
  server.use((req: Request, res: Response, next: Next) => {
    // Limit only interactive bot traffic; avoid throttling health checks.
    const requestPath = req.url ?? "";
    if (!requestPath.startsWith("/api/messages")) {
      next();
      return;
    }

    const forwardedFor = req.headers["x-forwarded-for"];
    const forwarded =
      typeof forwardedFor === "string"
        ? forwardedFor.split(",")[0]?.trim()
        : undefined;
    const remote = req.socket.remoteAddress ?? "unknown";
    const ip = config.TRUST_PROXY && forwarded ? forwarded : remote;

    if (!rateLimiter.isAllowed(ip)) {
      res.send(429, { error: "Too many requests" });
      return;
    }
    next();
  });

  // Bot Framework messages endpoint
  server.post("/api/messages", async (req: Request, res: Response) => {
    await adapter.processActivity(req, res, async (context) => {
      await bot.run(context);
    });
  });

  // Health check endpoint
  server.get("/health", (req: Request, res: Response, next: Next) => {
    const status = getRuntimeStatus();
    const engine = getEngine();
    res.send(200, {
      status: "ok",
      uptime: Math.floor((Date.now() - startTime) / 1000),
      skills: status.skillCount,
      sessions: engine?.sessionCount ?? 0,
      model: status.activeModel,
      authenticated: Boolean(engine),
      oauthEnabled: config.OAUTH_ENABLED,
    });
    next();
  });

  if (deps.oauthManager) {
    const oauth = deps.oauthManager;

    server.get("/auth/login", oauth.login);
    server.get(config.OAUTH_CALLBACK_PATH, oauth.callback);
    server.get("/auth/status", (req: Request, res: Response, next: Next) => {
      const status = oauth.getStatus(req);
      res.send(200, status);
      next();
    });
    server.post("/auth/logout", oauth.logout);
  }

  // Admin: reload skills (protected by ADMIN_TOKEN)
  if (config.ADMIN_TOKEN && deps.reloadFn) {
    const reloadFn = deps.reloadFn;
    server.post("/admin/reload", async (req: Request, res: Response, next: Next) => {
      const token = parseBearerToken(req.headers["authorization"]);
      if (token !== config.ADMIN_TOKEN) {
        res.send(403, { error: "Forbidden" });
        next();
        return;
      }

      try {
        const result = await reloadFn();
        res.send(200, {
          message: "Reloaded",
          skills: result.skillCount,
          model: result.roleModel ?? config.COPILOT_MODEL,
        });
      } catch (err) {
        logger.error({ err }, "Admin reload failed");
        if (
          err instanceof Error &&
          err.message.toLowerCase().includes("already in progress")
        ) {
          res.send(409, { error: "Reload already in progress" });
        } else {
          res.send(500, { error: "Reload failed" });
        }
      }
      next();
    });
  }

  return server;
}
