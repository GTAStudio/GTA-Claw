# syntax=docker/dockerfile:1
# ---- Build Stage ----
FROM node:20-bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  git \
  python3 \
  python-is-python3 \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV npm_config_python=/usr/bin/python3

WORKDIR /app

COPY package.json package-lock.json* ./
# Frozen, reproducible install. Unlike `npm install`, `npm ci` refuses to run
# at all if package.json and package-lock.json are out of sync, and it never
# rewrites the lockfile — the sha256 comparison below proves that on every
# build instead of just asserting it. `--ignore-scripts` is safe: the only
# two packages in the whole tree with install scripts are isolated-vm
# (removed — see src/engine/toolExecutor.ts) and restify's optional
# dtrace-provider dependency, which falls back to a no-op stub at runtime
# when its native binding isn't built (see dtrace-provider's own source).
RUN node -v && npm -v && \
  BEFORE_LOCK="$(sha256sum package-lock.json)" && \
  echo "=== package-lock.json before install: $BEFORE_LOCK ===" && \
  ( npm ci --ignore-scripts --no-audit --no-fund || \
    (echo "=== npm ci failed, dumping npm logs ===" && \
     ls -la /root/.npm/_logs || true && \
     cat /root/.npm/_logs/* || true && \
     exit 1) ) && \
  AFTER_LOCK="$(sha256sum package-lock.json)" && \
  echo "=== package-lock.json after install:  $AFTER_LOCK ===" && \
  if [ "$BEFORE_LOCK" != "$AFTER_LOCK" ]; then \
    echo "FAIL: npm ci rewrote package-lock.json - the committed lock is not authoritative" >&2; \
    exit 1; \
  fi && \
  echo "=== production dependency graph (npm ls --omit=dev); a non-zero exit here means the installed tree does not match the reviewed lock ===" && \
  npm ls --omit=dev && \
  echo "=== remediated package versions (evidence for Dependabot alert closure) ===" && \
  npm ls axios form-data undici ws lodash @github/copilot-sdk @github/copilot --omit=dev --all

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build 2>&1 || \
  (echo "=== tsc build failed ===" && \
   npx tsc --noEmit --pretty 2>&1 || true && \
   exit 1)
RUN npm prune --omit=dev

# Fail-closed regression gate. Proves the seven planted-regression acceptance
# criteria from the legacy-node emergency hardening pass hold against the
# ACTUAL compiled dist/ + production node_modules of THIS image, on every
# build (not just at PR-review time): (1) remote skill execution stays
# rejected with no node:vm/isolated-vm/require() in the compiled output,
# (2) a plain http:// AGENT_ROLE_URL is rejected, (3) an unauthenticated
# loopback request to /admin/system is denied while a correctly-tokened one
# still succeeds (the old 127.0.0.1 bypass must stay gone), (4) the updater
# never calls exec/execFile except for the --version check (no npm update /
# curl|bash self-mutation), (5) a plaintext ws:// DISCORD_GATEWAY_URL is
# rejected, (6) restify's http2/spdy options stay unused and the
# find-my-way override stays pinned rather than blind-bumped, (7) the
# bundled Copilot CLI path resolves to an existing, spawnable native binary
# rather than @github/copilot-sdk's default *.js entrypoint (which requires
# Node >=22's Promise.withResolvers and crashes outright on this image's
# Node 20 runtime — see resolveBundledCliPath() in src/updater/sdkUpdater.ts
# for the full empirical trail). The script is never written to disk or
# committed: the quoted heredoc delimiter prevents any Dockerfile ARG/ENV
# substitution from touching its many `${...}` template literals, and it is
# piped straight to node's stdin as an ES module.
RUN node --input-type=module - <<'REGRESSION_CHECK'
// Fail-closed regression gate, embedded verbatim (via a quoted heredoc, so
// no shell/Dockerfile variable substitution touches it) as a Dockerfile RUN
// step in the builder stage, executed via `node --input-type=module -`
// against the actual compiled dist/ + production node_modules for THIS
// image build. Paths below are relative to WORKDIR /app. This script is
// never written to disk or committed; it exists only as literal text in the
// Dockerfile RUN instruction, fed to node over stdin.
import assert from "node:assert/strict";
import http from "node:http";
import { readFile } from "node:fs/promises";

// Strips // line comments and /* */ block comments so the string checks
// below verify actual code, not explanatory prose that names the forbidden
// pattern as a negation (e.g. "no longer uses isolated-vm").
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const results = [];
function record(name, fn) {
  const start = Date.now();
  return fn()
    .then(() => results.push([name, "PASS", "", Date.now() - start]))
    .catch((err) => results.push([name, "FAIL", err.message ?? String(err), Date.now() - start]));
}

// 1. node:vm / arbitrary JS execution rejection -----------------------------
async function checkToolExecutorRejects() {
  const { ToolExecutor } = await import("./dist/engine/toolExecutor.js");
  const exec = new ToolExecutor();
  exec.registerSkill("evil", "(params, api) => { return process.mainModule; }");
  await assert.rejects(
    () => exec.execute("evil", {}),
    /disabled/i,
    "execute() must reject with a disabled-execution error",
  );
  const src = await readFile("./dist/engine/toolExecutor.js", "utf8");
  const code = stripComments(src);
  assert.ok(!/isolated-vm/.test(code), "compiled code must not reference isolated-vm");
  assert.ok(!/node:vm/.test(code), "compiled code must not import node:vm");
  assert.ok(!/\brequire\s*\(/.test(code), "compiled code must not call require() at all");
}

// 2. Non-HTTPS AGENT_ROLE_URL rejection -------------------------------------
function withEnv(env, fn) {
  const prev = { ...process.env };
  Object.keys(process.env).forEach((k) => delete process.env[k]);
  Object.assign(process.env, env);
  try {
    return fn();
  } finally {
    Object.keys(process.env).forEach((k) => delete process.env[k]);
    Object.assign(process.env, prev);
  }
}

async function checkHttpsOnlyConfig() {
  const mod = await import(`./dist/config.js?t=${Date.now()}`);
  const baseEnv = {
    ...process.env,
    GITHUB_TOKEN: "x",
    ENABLE_TEAMS: "false",
    AGENT_ROLE_URL: "http://example.com/role.json",
  };
  assert.throws(
    () => withEnv(baseEnv, () => mod.loadConfig()),
    /https/i,
    "loadConfig() must reject a plain http:// AGENT_ROLE_URL",
  );
  // Sanity: a valid https URL must be accepted.
  const httpsEnv = { ...baseEnv, AGENT_ROLE_URL: "https://example.com/role.json" };
  const cfg = withEnv(httpsEnv, () => mod.loadConfig());
  assert.equal(cfg.AGENT_ROLE_URL, "https://example.com/role.json");
}

// 3. Loopback admin bypass denial -------------------------------------------
async function checkLoopbackAdminDenied() {
  const { createServer } = await import("./dist/server.js");
  const server = createServer({
    bot: {},
    config: {
      ENABLE_TEAMS: false,
      ENABLE_TELEGRAM: false,
      ENABLE_DISCORD: false,
      ENABLE_WHATSAPP: false,
      DEVICE_FLOW_ENABLED: false,
      RATE_LIMIT_PER_MIN: 1000,
      TRUST_PROXY: false,
      ADMIN_TOKEN: "s3cr3t-test-token",
    },
    getEngine: () => null,
    getRuntimeStatus: () => ({ skillCount: 0, activeModel: "test" }),
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const noAuth = await new Promise((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path: "/admin/system" }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      }).on("error", reject);
    });
    assert.equal(
      noAuth,
      403,
      "loopback request without ADMIN_TOKEN must be denied (got " + noAuth + ")",
    );

    const withAuth = await new Promise((resolve, reject) => {
      http.get(
        {
          host: "127.0.0.1",
          port,
          path: "/admin/system",
          headers: { Authorization: "Bearer " + "s3cr3t-test-token" },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode));
        },
      ).on("error", reject);
    });
    assert.equal(withAuth, 200, "loopback request WITH correct token must succeed");
  } finally {
    server.close();
  }
}

// 4. Updater no-mutation -----------------------------------------------------
async function checkUpdaterNoMutation() {
  const src = await readFile("./dist/updater/sdkUpdater.js", "utf8");
  const code = stripComments(src);
  assert.ok(
    !/performSdkUpdate|performCliUpdate/.test(code),
    "the removed self-mutation functions must not be reintroduced",
  );
  assert.ok(!/copilot-install/.test(code), "updater must not curl the installer");
  assert.ok(!/PREFIX=\/usr\/local bash/.test(code), "updater must not self-mutate via curl|bash");
  // The only permitted execFile/execFileAsync call site must target --version;
  // this is the precise behavioral check (the log message legitimately *talks
  // about* npm update/curl|bash in prose to explain what was removed, so a raw
  // substring ban on that phrase would be a false positive against the log text).
  const execCalls = [...code.matchAll(/exec(?:File)?Async?\(([^)]*)\)/g)];
  assert.equal(execCalls.length, 1, `expected exactly one exec call, found ${execCalls.length}`);
  assert.ok(
    /--version/.test(execCalls[0][1]),
    "the sole exec call must be the --version check, not a mutation",
  );
}

// 5. Discord ws:// rejection --------------------------------------------------
async function checkDiscordWssOnly() {
  const mod = await import(`./dist/config.js?t=${Date.now()}-b`);
  const baseEnv = {
    ...process.env,
    GITHUB_TOKEN: "x",
    ENABLE_TEAMS: "false",
    AGENT_ROLE_URL: "https://example.com/role.json",
    DISCORD_GATEWAY_URL: "ws://gateway.discord.gg/?v=10&encoding=json",
  };
  assert.throws(
    () => withEnv(baseEnv, () => mod.loadConfig()),
    /wss/i,
    "loadConfig() must reject a plaintext ws:// DISCORD_GATEWAY_URL",
  );
}

// 6. HTTP/2 + spdy policy (restify stays HTTP/1.1; find-my-way stays pinned) --
async function checkHttp2SpdyDisabled() {
  const src = await readFile("./dist/server.js", "utf8");
  const code = stripComments(src);
  assert.ok(!/http2/i.test(code), "server must not enable restify's http2 option");
  assert.ok(!/spdy/i.test(code), "server must not configure restify's spdy option");

  const pkg = JSON.parse(await readFile("./package.json", "utf8"));
  assert.equal(
    pkg.overrides["find-my-way"],
    "8.2.2",
    "find-my-way override must stay pinned, not blind-bumped to 9.7.0 across two unsupported majors",
  );
}

// 7. Bundled CLI path resolves to an existing, spawnable native binary ------
async function checkCliPathResolvesToNativeBinary() {
  const { resolveBundledCliPath } = await import(
    "./dist/updater/sdkUpdater.js"
  );
  const { existsSync } = await import("node:fs");
  const cliPath = resolveBundledCliPath();
  assert.ok(
    existsSync(cliPath),
    `resolved Copilot CLI path does not exist on disk: ${cliPath}`,
  );
  assert.ok(
    !cliPath.endsWith(".js"),
    "resolved Copilot CLI path must be the platform package's native binary " +
      "(a Node.js Single Executable Application with its own embedded " +
      "runtime), not @github/copilot-sdk's default *.js entrypoint, which " +
      "requires Node >=22 (Promise.withResolvers) and crashes outright on " +
      "this image's Node 20 runtime",
  );
}

await record("1-node-vm-rejection", checkToolExecutorRejects);
await record("2-https-only-config", checkHttpsOnlyConfig);
await record("3-loopback-admin-denied", checkLoopbackAdminDenied);
await record("4-updater-no-mutation", checkUpdaterNoMutation);
await record("5-discord-wss-only", checkDiscordWssOnly);
await record("6-http2-spdy-disabled", checkHttp2SpdyDisabled);
await record("7-cli-path-resolves-native", checkCliPathResolvesToNativeBinary);

console.log("\n=== Image regression check results ===");
let failed = false;
for (const [name, status, msg, ms] of results) {
  console.log(`${status === "PASS" ? "PASS" : "FAIL"}  ${name}  (${ms}ms)${msg ? "  -  " + msg : ""}`);
  if (status !== "PASS") failed = true;
}
if (failed) {
  console.error("\nOne or more planted-regression checks FAILED. Failing the build.");
  process.exit(1);
}
console.log("\nAll planted-regression checks passed.");
REGRESSION_CHECK

# ---- Production Stage ----
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  curl \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Run as non-root
USER node

EXPOSE 3978

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3978/health || exit 1

CMD ["node", "dist/index.js"]
