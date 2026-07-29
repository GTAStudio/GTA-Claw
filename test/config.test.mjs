import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../dist/config.js";
import { logger } from "../dist/utils/logger.js";

const CONFIG_ENV_KEYS = [
  "AGENT_ROLE_URL",
  "ADMIN_TOKEN",
  "ALLOWED_SKILL_DOMAINS",
  "AUTO_UPDATE",
  "COPILOT_MODEL",
  "DISCORD_BOT_TOKEN",
  "DISCORD_GATEWAY_INTENTS",
  "DISCORD_GATEWAY_URL",
  "DOMAIN",
  "ENABLED_SKILLS",
  "DEVICE_FLOW_ENABLED",
  "ENABLE_DISCORD",
  "ENABLE_TEAMS",
  "ENABLE_TELEGRAM",
  "ENABLE_WHATSAPP",
  "GITHUB_CLIENT_ID",
  "GITHUB_TOKEN",
  "LOG_LEVEL",
  "MAX_SESSIONS",
  "MicrosoftAppId",
  "MicrosoftAppPassword",
  "PORT",
  "RATE_LIMIT_PER_MIN",
  "SDK_REQUEST_TIMEOUT_MS",
  "SESSION_TTL_MS",
  "SKILL_EXEC_TIMEOUT_MS",
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_POLL_INTERVAL_MS",
  "TRUST_PROXY",
  "WHATSAPP_ACCESS_TOKEN",
  "WHATSAPP_APP_SECRET",
  "WHATSAPP_PHONE_NUMBER_ID",
  "WHATSAPP_VERIFY_TOKEN",
  "WHATSAPP_WEBHOOK_PATH",
];

function withConfigEnv(overrides, run) {
  const previous = new Map(
    CONFIG_ENV_KEYS.map((key) => [key, process.env[key]]),
  );

  for (const key of CONFIG_ENV_KEYS) {
    delete process.env[key];
  }
  Object.assign(process.env, {
    AGENT_ROLE_URL: "https://example.com/role.json",
    GITHUB_TOKEN: "github-token",
    ENABLE_TEAMS: "false",
    ...overrides,
  });

  try {
    return run();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("startup rejects enabled WhatsApp without an app secret", () => {
  withConfigEnv(
    {
      ENABLE_WHATSAPP: "true",
      WHATSAPP_VERIFY_TOKEN: "verify-token",
      WHATSAPP_ACCESS_TOKEN: "access-token",
      WHATSAPP_PHONE_NUMBER_ID: "phone-number-id",
    },
    () => {
      assert.throws(
        () => loadConfig(),
        /ENABLE_WHATSAPP=true requires .*WHATSAPP_APP_SECRET/,
      );
    },
  );
});

test("startup loads but does not log the WhatsApp app secret", (t) => {
  const info = t.mock.method(logger, "info", () => undefined);
  withConfigEnv(
    {
      ENABLE_WHATSAPP: "true",
      WHATSAPP_VERIFY_TOKEN: "verify-token",
      WHATSAPP_ACCESS_TOKEN: "access-token",
      WHATSAPP_PHONE_NUMBER_ID: "phone-number-id",
      WHATSAPP_APP_SECRET: "app-secret",
    },
    () => {
      const config = loadConfig();
      assert.equal(config.ENABLE_WHATSAPP, true);
      assert.equal(config.WHATSAPP_APP_SECRET, "app-secret");
      assert.doesNotMatch(
        JSON.stringify(info.mock.calls.map((call) => call.arguments)),
        /app-secret/,
      );
    },
  );
});

test("startup leaves the WhatsApp app secret optional when disabled", () => {
  withConfigEnv({ ENABLE_WHATSAPP: "false" }, () => {
    const config = loadConfig();
    assert.equal(config.ENABLE_WHATSAPP, false);
    assert.equal(config.WHATSAPP_APP_SECRET, undefined);
  });
});
