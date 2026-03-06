import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

const MAX_ROLE_SIZE = 1_048_576; // 1 MB
const FETCH_TIMEOUT_MS = 10_000;

const KNOWN_MODELS = new Set([
  "gpt-4.1",
  "gpt-4o",
  "gpt-5-mini",
  "gpt-5.1",
  "gpt-5.1-codex",
  "gpt-5.1-codex-mini",
  "gpt-5.1-codex-max",
  "gpt-5.2",
  "gpt-5.2-codex",
  "gpt-5.3-codex",
  "claude-haiku-4.5",
  "claude-opus-4.5",
  "claude-opus-4.6",
  "claude-sonnet-4",
  "claude-sonnet-4.5",
  "claude-sonnet-4.6",
  "gemini-2.5-pro",
  "gemini-3-flash",
  "gemini-3-pro",
  "gemini-3.1-pro",
  "grok-code-fast-1",
]);

export interface RoleConfig {
  content: string;
  model?: string;
}

export async function loadRole(url: string): Promise<RoleConfig> {
  logger.info({ url }, "Fetching role configuration...");

  const response = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { Accept: "application/json, text/plain" },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch role from ${url}: ${response.status} ${response.statusText}`,
    );
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_ROLE_SIZE) {
    throw new Error(
      `Role content too large: ${contentLength} bytes (max ${MAX_ROLE_SIZE})`,
    );
  }

  const raw = await response.text();
  if (raw.length > MAX_ROLE_SIZE) {
    throw new Error(
      `Role content too large: ${raw.length} chars (max ${MAX_ROLE_SIZE})`,
    );
  }

  const contentType = response.headers.get("content-type") ?? "";

  // Try parsing as JSON
  if (contentType.includes("json") || raw.trimStart().startsWith("{")) {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const content =
        typeof parsed["content"] === "string"
          ? parsed["content"]
          : typeof parsed["prompt"] === "string"
            ? parsed["prompt"]
            : undefined;

      if (!content) {
        throw new Error(
          'Role JSON must contain a "content" or "prompt" string field',
        );
      }

      const model =
        typeof parsed["model"] === "string" ? parsed["model"] : undefined;

      if (model && !KNOWN_MODELS.has(model)) {
        logger.warn(
          { model },
          "Unknown model specified in role config — will attempt to use anyway",
        );
      }

      logger.info(
        { chars: content.length, model: model ?? "(default)" },
        "Role loaded (JSON)",
      );
      return { content, model };
    } catch (e) {
      if (contentType.includes("json")) throw e;
      // Fall through to plain text
    }
  }

  // Plain text — use as system prompt directly, no model override
  logger.info({ chars: raw.length }, "Role loaded (plain text)");
  return { content: raw };
}
