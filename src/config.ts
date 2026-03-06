import { logger } from "./utils/logger.js";

export interface AppConfig {
  // Required core
  MICROSOFT_APP_ID: string;
  MICROSOFT_APP_PASSWORD: string;
  AGENT_ROLE_URL: string;
  ENABLED_SKILLS: string[];

  // Auth
  GITHUB_TOKEN?: string;
  OAUTH_ENABLED: boolean;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  AUTH_BASE_URL?: string;
  OAUTH_CALLBACK_PATH: string;
  OAUTH_SCOPE: string;

  // Optional with defaults
  PORT: number;
  LOG_LEVEL: string;
  SESSION_TTL_MS: number;
  MAX_SESSIONS: number;
  COPILOT_MODEL: string;
  SKILL_EXEC_TIMEOUT_MS: number;
  SDK_REQUEST_TIMEOUT_MS: number;
  RATE_LIMIT_PER_MIN: number;
  ALLOWED_SKILL_DOMAINS: string[];
  DOMAIN: string;
  AUTO_UPDATE: boolean;
  ADMIN_TOKEN: string | undefined;
  TRUST_PROXY: boolean;
}

const VALID_LOG_LEVELS = new Set([
  "trace",
  "debug",
  "info",
  "warn",
  "error",
  "fatal",
]);

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function validateUrl(raw: string, label: string): string {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error(`Invalid protocol`);
    }
    return raw;
  } catch {
    throw new Error(`Invalid URL for ${label}: ${raw}`);
  }
}

function parseCommaSeparatedUrls(raw: string, label: string): string[] {
  if (!raw.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((url) => validateUrl(url, label));
}

function parseIntegerEnv(
  name: string,
  defaultValue: number,
  options?: { min?: number; max?: number },
): number {
  const raw = process.env[name];
  const value = raw === undefined ? defaultValue : Number.parseInt(raw, 10);

  if (!Number.isFinite(value)) {
    throw new Error(`Invalid integer for ${name}: ${raw}`);
  }

  if (options?.min !== undefined && value < options.min) {
    throw new Error(`${name} must be >= ${options.min}, got ${value}`);
  }
  if (options?.max !== undefined && value > options.max) {
    throw new Error(`${name} must be <= ${options.max}, got ${value}`);
  }

  return value;
}

function parseBooleanEnv(name: string, defaultValue: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return defaultValue;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`Invalid boolean for ${name}: ${raw}. Use true or false.`);
}

function parseDomainList(name: string): string[] {
  const raw = process.env[name];
  if (!raw) return [];

  const unique = new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  return [...unique];
}

export function loadConfig(): AppConfig {
  logger.info("Loading configuration...");

  const GITHUB_TOKEN = process.env["GITHUB_TOKEN"]?.trim();
  const GITHUB_CLIENT_ID = process.env["GITHUB_CLIENT_ID"]?.trim();
  const GITHUB_CLIENT_SECRET = process.env["GITHUB_CLIENT_SECRET"]?.trim();
  const AUTH_BASE_URL_RAW = process.env["AUTH_BASE_URL"]?.trim();
  const AUTH_BASE_URL = AUTH_BASE_URL_RAW
    ? validateUrl(AUTH_BASE_URL_RAW, "AUTH_BASE_URL")
    : undefined;
  const OAUTH_CALLBACK_PATH =
    process.env["OAUTH_CALLBACK_PATH"]?.trim() || "/auth/callback";
  const OAUTH_SCOPE = process.env["OAUTH_SCOPE"]?.trim() || "copilot";

  const hasOAuthConfig = Boolean(
    GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && AUTH_BASE_URL,
  );
  const OAUTH_ENABLED = parseBooleanEnv("OAUTH_ENABLED", hasOAuthConfig);

  if (OAUTH_ENABLED && !hasOAuthConfig) {
    throw new Error(
      "OAUTH_ENABLED=true requires GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and AUTH_BASE_URL",
    );
  }

  if (!GITHUB_TOKEN && !OAUTH_ENABLED) {
    throw new Error(
      "Either GITHUB_TOKEN must be set or OAuth must be enabled with OAUTH_ENABLED=true",
    );
  }

  if (!OAUTH_CALLBACK_PATH.startsWith("/")) {
    throw new Error(
      `OAUTH_CALLBACK_PATH must start with '/': ${OAUTH_CALLBACK_PATH}`,
    );
  }

  const MICROSOFT_APP_ID = requireEnv("MicrosoftAppId");
  const MICROSOFT_APP_PASSWORD = requireEnv("MicrosoftAppPassword");

  const AGENT_ROLE_URL = validateUrl(
    requireEnv("AGENT_ROLE_URL"),
    "AGENT_ROLE_URL",
  );

  const ENABLED_SKILLS = parseCommaSeparatedUrls(
    requireEnv("ENABLED_SKILLS"),
    "ENABLED_SKILLS",
  );

  const logLevel = process.env["LOG_LEVEL"] ?? "info";
  if (!VALID_LOG_LEVELS.has(logLevel)) {
    throw new Error(
      `Invalid LOG_LEVEL: ${logLevel}. Valid values: ${[...VALID_LOG_LEVELS].join(", ")}`,
    );
  }

  const config: AppConfig = {
    MICROSOFT_APP_ID,
    MICROSOFT_APP_PASSWORD,
    AGENT_ROLE_URL,
    ENABLED_SKILLS,
    GITHUB_TOKEN,
    OAUTH_ENABLED,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    AUTH_BASE_URL,
    OAUTH_CALLBACK_PATH,
    OAUTH_SCOPE,

    PORT: parseIntegerEnv("PORT", 3978, { min: 1, max: 65535 }),
    LOG_LEVEL: logLevel,
    SESSION_TTL_MS: parseIntegerEnv("SESSION_TTL_MS", 3_600_000, { min: 1_000 }),
    MAX_SESSIONS: parseIntegerEnv("MAX_SESSIONS", 100, { min: 1 }),
    COPILOT_MODEL: process.env["COPILOT_MODEL"] ?? "gpt-4o",
    SKILL_EXEC_TIMEOUT_MS: parseIntegerEnv("SKILL_EXEC_TIMEOUT_MS", 30_000, {
      min: 100,
    }),
    SDK_REQUEST_TIMEOUT_MS: parseIntegerEnv("SDK_REQUEST_TIMEOUT_MS", 120_000, {
      min: 1_000,
    }),
    RATE_LIMIT_PER_MIN: parseIntegerEnv("RATE_LIMIT_PER_MIN", 30, { min: 1 }),
    ALLOWED_SKILL_DOMAINS: parseDomainList("ALLOWED_SKILL_DOMAINS"),
    DOMAIN: process.env["DOMAIN"] ?? "localhost",
    AUTO_UPDATE: parseBooleanEnv("AUTO_UPDATE", false),
    ADMIN_TOKEN: process.env["ADMIN_TOKEN"],
    TRUST_PROXY: parseBooleanEnv("TRUST_PROXY", false),
  };

  logger.info(
    {
      port: config.PORT,
      model: config.COPILOT_MODEL,
      skillUrls: config.ENABLED_SKILLS.length,
      rateLimitPerMin: config.RATE_LIMIT_PER_MIN,
      domain: config.DOMAIN,
      authMode: config.OAUTH_ENABLED
        ? config.GITHUB_TOKEN
          ? "oauth+token"
          : "oauth"
        : "token",
      trustProxy: config.TRUST_PROXY,
      autoUpdate: config.AUTO_UPDATE,
    },
    "Configuration loaded",
  );

  return config;
}
