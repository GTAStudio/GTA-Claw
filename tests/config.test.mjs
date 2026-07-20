import assert from "node:assert/strict";
import test from "node:test";

import { loadConfig } from "../dist/config.js";

const PERSISTENCE_KEYS = [
  "STATE_DIR",
  "MEMORY_ENABLED",
  "MEMORY_CHAR_LIMIT",
  "USER_PROFILE_CHAR_LIMIT",
  "TRANSCRIPT_ENABLED",
  "TRANSCRIPT_MAX_MESSAGES",
  "TRANSCRIPT_CONTENT_CHAR_LIMIT",
];

function setBaseEnvironment() {
  process.env.GITHUB_TOKEN = "test-token";
  process.env.AGENT_ROLE_URL = "https://example.com/role.json";
  process.env.ENABLE_TEAMS = "false";
  process.env.ENABLE_TELEGRAM = "false";
  process.env.ENABLE_DISCORD = "false";
  process.env.ENABLE_WHATSAPP = "false";
  process.env.DEVICE_FLOW_ENABLED = "false";
  for (const key of PERSISTENCE_KEYS) {
    delete process.env[key];
  }
}

test("persistence configuration is opt-in and enforces aggregate bounds", () => {
  setBaseEnvironment();
  const defaults = loadConfig();
  assert.equal(defaults.STATE_DIR, "./data");
  assert.equal(defaults.MEMORY_ENABLED, false);
  assert.equal(defaults.TRANSCRIPT_ENABLED, false);

  process.env.MEMORY_ENABLED = "true";
  process.env.TRANSCRIPT_ENABLED = "true";
  process.env.STATE_DIR = "custom-state";
  const enabled = loadConfig();
  assert.equal(enabled.STATE_DIR, "custom-state");
  assert.equal(enabled.MEMORY_ENABLED, true);
  assert.equal(enabled.TRANSCRIPT_ENABLED, true);

  process.env.TRANSCRIPT_MAX_MESSAGES = "100000";
  process.env.TRANSCRIPT_CONTENT_CHAR_LIMIT = "1000000";
  assert.throws(loadConfig, /must not exceed 50000000/);
});
