import { logger } from "../utils/logger.js";
import { fetch } from "../utils/proxy.js";

const MAX_SKILL_SIZE = 524_288; // 512 KB
const FETCH_TIMEOUT_MS = 10_000;
const SAFE_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

export interface Skill {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  executeCode: string;
}

function validateSkill(data: unknown, url: string): Skill {
  if (typeof data !== "object" || data === null) {
    throw new Error(`Skill from ${url} is not a valid JSON object`);
  }

  const obj = data as Record<string, unknown>;

  if (typeof obj["name"] !== "string" || !obj["name"]) {
    throw new Error(`Skill from ${url} missing required "name" field`);
  }
  if (!SAFE_NAME_RE.test(obj["name"])) {
    throw new Error(
      `Skill "${obj["name"]}" from ${url} has unsafe name (must match ${SAFE_NAME_RE})`,
    );
  }
  if (typeof obj["description"] !== "string" || !obj["description"]) {
    throw new Error(
      `Skill "${obj["name"]}" from ${url} missing "description" field`,
    );
  }
  if (typeof obj["parameters"] !== "object" || obj["parameters"] === null) {
    throw new Error(
      `Skill "${obj["name"]}" from ${url} missing "parameters" object`,
    );
  }
  if (typeof obj["executeCode"] !== "string" || !obj["executeCode"]) {
    throw new Error(
      `Skill "${obj["name"]}" from ${url} missing "executeCode" field`,
    );
  }

  return {
    name: obj["name"],
    description: obj["description"],
    parameters: obj["parameters"] as Record<string, unknown>,
    executeCode: obj["executeCode"],
  };
}

export async function loadSkills(urls: string[]): Promise<Skill[]> {
  logger.info({ count: urls.length }, "Loading skills from remote URLs...");

  const skills: Skill[] = [];

  const results = await Promise.allSettled(
    urls.map(async (url) => {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(
          `Failed to fetch skill from ${url}: ${response.status} ${response.statusText}`,
        );
      }

      const raw = await response.text();
      if (raw.length > MAX_SKILL_SIZE) {
        throw new Error(
          `Skill from ${url} too large: ${raw.length} chars (max ${MAX_SKILL_SIZE})`,
        );
      }

      const parsed: unknown = JSON.parse(raw);
      return validateSkill(parsed, url);
    }),
  );

  for (let i = 0; i < results.length; i++) {
    const result = results[i]!;
    if (result.status === "fulfilled") {
      skills.push(result.value);
      logger.info(
        { name: result.value.name, url: urls[i] },
        "Skill loaded successfully",
      );
    } else {
      logger.error(
        { url: urls[i], error: result.reason },
        "Failed to load skill — skipping",
      );
    }
  }

  logger.info(
    { loaded: skills.length, total: urls.length },
    "Skill loading complete",
  );
  return skills;
}
