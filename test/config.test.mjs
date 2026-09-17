import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

async function importConfigModulesWithScrubbedLogLevel() {
  const ambientLogLevel = process.env.LOG_LEVEL;
  delete process.env.LOG_LEVEL;
  const scrubbedBeforeImport = process.env.LOG_LEVEL === undefined;

  try {
    const [{ loadConfig }, { logger }] = await Promise.all([
      import("../dist/config.js"),
      import("../dist/utils/logger.js"),
    ]);
    return { ambientLogLevel, loadConfig, logger, scrubbedBeforeImport };
  } finally {
    if (ambientLogLevel === undefined) {
      delete process.env.LOG_LEVEL;
    } else {
      process.env.LOG_LEVEL = ambientLogLevel;
    }
  }
}

const originalLogLevel = process.env.LOG_LEVEL;
process.env.LOG_LEVEL = "ambient-invalid";
const imported = await importConfigModulesWithScrubbedLogLevel();
const restoredInvalidAmbient = process.env.LOG_LEVEL;
if (originalLogLevel === undefined) {
  delete process.env.LOG_LEVEL;
} else {
  process.env.LOG_LEVEL = originalLogLevel;
}

const { loadConfig, logger } = imported;
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));

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

test("config imports scrub an invalid ambient log level", () => {
  assert.equal(imported.ambientLogLevel, "ambient-invalid");
  assert.equal(imported.scrubbedBeforeImport, true);
  assert.equal(restoredInvalidAmbient, "ambient-invalid");
});

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

test("deployment secret prompt preserves exact bytes in one assignment", async (t) => {
  for (const secret of [
    "-n",
    String.raw`backslash\path\\value`,
    "  leading and trailing  ",
  ]) {
    await t.test(JSON.stringify(secret), () => {
      const result = spawnSync(
        "/bin/bash",
        [
          "-c",
          [
            "source ./deploy/run.sh",
            'secret="$(prompt_secret WHATSAPP_APP_SECRET "WhatsApp App Secret")"',
            'printf "WHATSAPP_APP_SECRET=%s\\n" "$secret"',
          ].join("\n"),
        ],
        {
          cwd: repositoryRoot,
          input: Buffer.from(`\n${secret}\n`),
        },
      );

      const stderr = result.stderr.toString("utf8");
      assert.equal(result.status, 0, stderr);
      assert.deepEqual(
        result.stdout,
        Buffer.from(`WHATSAPP_APP_SECRET=${secret}\n`),
      );
      assert.equal(
        result.stdout
          .toString("utf8")
          .match(/^WHATSAPP_APP_SECRET=/gm)?.length,
        1,
      );
      assert.match(stderr, /WhatsApp App Secret:/);
      assert.match(stderr, /WHATSAPP_APP_SECRET/);
      assert.equal(stderr.includes(secret), false);
    });
  }
});
