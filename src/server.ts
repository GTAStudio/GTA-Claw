import {
  BotFrameworkAdapter,
  type TurnContext,
} from "botbuilder";
import restify, { type Next, type Request, type Response } from "restify";
import { execFile } from "node:child_process";
import os from "node:os";
import { logger } from "./utils/logger.js";
import type { AgentBot } from "./bot/teamsBot.js";
import type { AppConfig } from "./config.js";
import type { CopilotEngine } from "./engine/copilotEngine.js";
import type { WhatsAppWebhookHandler } from "./channels/whatsappWebhook.js";

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
  whatsappHandler?: WhatsAppWebhookHandler;
  reloadFn?: () => Promise<ReloadResult>;
}

const startTime = Date.now();

export function createServer(deps: ServerDeps): restify.Server {
  const { bot, config, getEngine, getRuntimeStatus } = deps;

  const server = restify.createServer({ name: "GTA-Claw" });
  server.use(restify.plugins.queryParser());
  server.use(restify.plugins.bodyParser());
  const adapter = config.ENABLE_TEAMS
    ? new BotFrameworkAdapter({
        appId: config.MICROSOFT_APP_ID,
        appPassword: config.MICROSOFT_APP_PASSWORD,
      })
    : null;
  const rateLimiter = new RateLimiter(config.RATE_LIMIT_PER_MIN);

  if (adapter) {
    // Adapter error handler
    adapter.onTurnError = async (context: TurnContext, error: Error) => {
      logger.error({ err: error }, "Bot adapter turn error");
      await context.sendActivity("An error occurred. Please try again later.");
    };
  }

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

  // Bot Framework messages endpoint (Teams)
  if (config.ENABLE_TEAMS) {
    if (!adapter) {
      throw new Error("Teams is enabled but Bot Framework adapter is unavailable");
    }
    server.post("/api/messages", async (req: Request, res: Response) => {
      await adapter.processActivity(req, res, async (context) => {
        await bot.run(context);
      });
    });
  }

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
      deviceFlowEnabled: config.DEVICE_FLOW_ENABLED,
    });
    next();
  });

  if (deps.whatsappHandler) {
    const whatsapp = deps.whatsappHandler;
    const path = config.WHATSAPP_WEBHOOK_PATH;
    server.get(path, whatsapp.verify);
    server.post(path, whatsapp.incoming);
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

  // Admin: system command execution (whitelisted, protected by ADMIN_TOKEN)
  if (config.ADMIN_TOKEN) {
    // Whitelist of safe read-only commands
    const ALLOWED_COMMANDS: Record<string, { cmd: string; args: string[] }> = {
      uptime: { cmd: "uptime", args: [] },
      disk: { cmd: "df", args: ["-h"] },
      memory: { cmd: "free", args: ["-h"] },
      top: { cmd: "top", args: ["-b", "-n", "1", "-o", "%MEM"] },
      docker_ps: { cmd: "docker", args: ["ps", "--format", "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}\\t{{.Image}}"] },
      docker_stats: { cmd: "docker", args: ["stats", "--no-stream", "--format", "table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}"] },
      docker_images: { cmd: "docker", args: ["images", "--format", "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}\\t{{.CreatedSince}}"] },
      docker_logs: { cmd: "docker", args: ["logs", "--tail", "50"] }, // container name appended
      netstat: { cmd: "ss", args: ["-tlnp"] },
      who: { cmd: "who", args: [] },
      hostname: { cmd: "hostname", args: [] },
      date: { cmd: "date", args: [] },
    };

    // Admin auth: require ADMIN_TOKEN via Bearer, or trust loopback (for in-process skills)
    const isAdminAuthorized = (req: Request): boolean => {
      const token = parseBearerToken(req.headers["authorization"]);
      if (token === config.ADMIN_TOKEN) return true;
      const remote = req.socket.remoteAddress ?? "";
      return remote === "127.0.0.1" || remote === "::1" || remote === "::ffff:127.0.0.1";
    };

    // GET /admin/system — Node.js process + OS info (no shell needed)
    server.get("/admin/system", (req: Request, res: Response, next: Next) => {
      if (!isAdminAuthorized(req)) {
        res.send(403, { error: "Forbidden" });
        next();
        return;
      }

      const mem = process.memoryUsage();
      res.send(200, {
        node: {
          version: process.version,
          pid: process.pid,
          uptime_s: Math.floor(process.uptime()),
          memory_mb: {
            rss: Math.round(mem.rss / 1048576),
            heapUsed: Math.round(mem.heapUsed / 1048576),
            heapTotal: Math.round(mem.heapTotal / 1048576),
          },
        },
        os: {
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          cpus: os.cpus().length,
          totalMemory_mb: Math.round(os.totalmem() / 1048576),
          freeMemory_mb: Math.round(os.freemem() / 1048576),
          uptime_s: Math.floor(os.uptime()),
          loadavg: os.loadavg(),
        },
      });
      next();
    });

    // POST /admin/exec — run whitelisted command
    server.post("/admin/exec", (req: Request, res: Response, next: Next) => {
      if (!isAdminAuthorized(req)) {
        res.send(403, { error: "Forbidden" });
        next();
        return;
      }

      const body = req.body as Record<string, unknown> | undefined;
      const action = typeof body?.action === "string" ? body.action : "";
      const target = typeof body?.target === "string" ? body.target : "";

      const spec = ALLOWED_COMMANDS[action];
      if (!spec) {
        res.send(400, {
          error: `Unknown action: ${action}`,
          allowed: Object.keys(ALLOWED_COMMANDS),
        });
        next();
        return;
      }

      // For docker_logs, append the container name (sanitized)
      const args = [...spec.args];
      if (action === "docker_logs" && target) {
        const safeName = target.replace(/[^a-zA-Z0-9_\-\.]/g, "");
        if (safeName) args.push(safeName);
      }

      logger.info({ action, target }, "Admin exec");

      execFile(spec.cmd, args, { timeout: 15_000, maxBuffer: 1048576 }, (err, stdout, stderr) => {
        if (err) {
          res.send(200, {
            action,
            success: false,
            error: (err as Error).message?.slice(0, 500),
            stderr: stderr?.slice(0, 2000),
          });
        } else {
          res.send(200, {
            action,
            success: true,
            output: stdout.slice(0, 10000),
            stderr: stderr ? stderr.slice(0, 1000) : undefined,
          });
        }
        next();
      });
    });
  }

  return server;
}
