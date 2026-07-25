# GTA-Claw — Project Plan

> Self-Governing AI Agent Engine: A pure empty-shell engine that dynamically loads roles and skills from remote URLs.

## Architecture Overview

```
                                 ┌──────────────────────┐
                                 │   Caddy (HTTPS/TLS)  │
┌─────────────┐   HTTPS POST    │   :443 → :3978       │
│  MS Teams   │ ───────────────▶│   Auto-cert / manual │
│  Channel    │ ◀───────────────│                      │
└─────────────┘                  └──────────┬───────────┘
                                            │ HTTP
                                 ┌──────────▼───────────────────────────────────────┐
                                 │  GTA-Claw Engine Container                       │
                                 │                                                   │
                                 │  ┌──────────┐   ┌─────────────┐   ┌────────────┐ │
                                 │  │ TeamsBot  │──▶│CopilotEngine│──▶│ CopilotCLI │ │
                                 │  │(botbuildr)│   │(SDK Client) │   │(JSON-RPC)  │ │
                                 │  └──────────┘   └──────┬──────┘   └────────────┘ │
                                 │                        │                          │
                                 │    defineTool() → ToolExecutor (isolated-vm)     │
                                 │                        │                          │
                                 │    Per-role model: role.model → session.model     │
                                 │    e.g. "claude-opus-4.6", "gpt-5.3-codex"       │
                                 │                                                   │
                                 │  Startup: fetch role & skills → register sessions │
                                 └──────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| AI Engine | `@github/copilot-sdk` | JSON-RPC bridge to Copilot CLI |
| AI Runtime | Copilot CLI (`@github/copilot`) | Model inference via GitHub |
| Bot Framework | `botbuilder` | Microsoft Teams integration |
| HTTP Server | `restify` | Bot endpoint hosting |
| Skill Sandbox | `isolated-vm` | V8 isolate-level sandboxing |
| Logging | `pino` | Structured JSON logging |
| Reverse Proxy | Caddy | Automatic HTTPS / TLS termination |
| Language | TypeScript (ES2022, strict) | Type-safe development |
| Container | Docker (Alpine) | Deployment |

## Project Structure

```
d:\GTA-Claw/
├── src/
│   ├── index.ts                  # Entry: validate → load → serve
│   ├── config.ts                 # Env vars parsing & validation
│   ├── server.ts                 # Restify HTTP server + rate limiter
│   ├── loader/
│   │   ├── roleLoader.ts         # Fetch system prompt + model config from AGENT_ROLE_URL
│   │   └── skillLoader.ts        # Fetch & register skills from ENABLED_SKILLS
│   ├── engine/
│   │   ├── copilotEngine.ts      # CopilotClient + session management
│   │   ├── toolExecutor.ts       # isolated-vm sandbox manager
│   │   └── sessionManager.ts     # Map Teams convId → Copilot sessions
│   ├── bot/
│   │   └── teamsBot.ts           # Teams TeamsActivityHandler
│   ├── updater/
│   │   └── sdkUpdater.ts         # SDK + CLI version check & update
│   └── utils/
│       └── logger.ts             # pino structured logging
├── caddy/
│   └── Caddyfile                 # Caddy reverse proxy config template
├── docs/
│   ├── PROJECT_PLAN.md           # This file
│   └── PROGRESS.md               # Implementation progress tracker
├── package.json
├── tsconfig.json
├── Dockerfile                    # Multi-stage Alpine + Copilot CLI install script
├── docker-compose.yml            # Engine + Caddy services
├── deploy.sh                     # Interactive + config-file deployment
├── .env.example
├── .dockerignore
└── README.md
```

## Implementation Phases

### Phase 1: Project Scaffolding
- `package.json` — dependencies, scripts (`--no-node-snapshot` required)
- `tsconfig.json` — ES2022, NodeNext, strict
- `.dockerignore` — exclusion rules

### Phase 2: Core Infrastructure
- `src/config.ts` — env var parsing & validation
- `src/utils/logger.ts` — pino structured logger

### Phase 3: Dynamic Loading
- `src/loader/roleLoader.ts` — fetch role JSON (content + model) from remote URL
- `src/loader/skillLoader.ts` — fetch skill modules, validate, graceful degradation
- `src/engine/toolExecutor.ts` — isolated-vm sandbox with API bridges

### Phase 4: AI Engine
- `src/engine/copilotEngine.ts` — CopilotClient, defineTool, sendAndWait, per-role model
- `src/engine/sessionManager.ts` — session mapping + TTL/LRU eviction

### Phase 5: Teams Integration
- `src/bot/teamsBot.ts` — TeamsActivityHandler, typing indicator, message splitting
- `src/server.ts` — Restify, rate limiter, /health, /admin endpoints
- `src/index.ts` — main orchestrator + graceful shutdown

### Phase 6: SDK/CLI Updater
- `src/updater/sdkUpdater.ts` — version checking + optional auto-update

### Phase 7: Containerization & Deployment
- `Dockerfile` — multi-stage Alpine build, Copilot CLI install
- `caddy/Caddyfile` — reverse proxy with auto HTTPS
- `docker-compose.yml` — engine + Caddy sidecar
- `deploy.sh` — interactive + config-file deployment script
- `.env.example` + `README.md`

## Key Design Decisions

1. **SDK Session Architecture**: No manual conversation store — SDK sessions track history natively via `infiniteSessions`
2. **Per-Role Model Selection**: Role config JSON includes `model` field → `createSession({ model })`; fallback to `COPILOT_MODEL` env var
3. **Copilot CLI Install**: Shell script (`curl -fsSL https://gh.io/copilot-install | bash`) — auto arch detection, supports `VERSION` pinning
4. **Caddy Sidecar**: Zero-config HTTPS via Let's Encrypt; runs alongside engine in Docker Compose
5. **Tool Registration**: `defineTool()` bridges SDK tool calls → isolated-vm sandbox execution
6. **Graceful Degradation**: Individual skill load failures don't crash startup
7. **`sendAndWait()` over manual tool loop**: SDK handles planning → tool invocation → re-call cycle internally
8. **`systemMessage.mode: "replace"`**: Full control over system prompt; removes default SDK persona

## Remote Role Config Format

```json
{
  "content": "You are a project architect specialized in...",
  "model": "claude-opus-4.6"
}
```

## Remote Skill Module Format

```json
{
  "name": "get_weather",
  "description": "Get current weather for a location",
  "parameters": {
    "type": "object",
    "properties": {
      "city": { "type": "string", "description": "City name" }
    },
    "required": ["city"]
  },
  "executeCode": "async function(params, api) { ... }"
}
```

## Available Models (per-role selection)

| Category | Model | Multiplier |
|----------|-------|-----------|
| Reasoning | `claude-opus-4.6` | 3x |
| Reasoning | `gpt-5.2` | 1x |
| Coding | `gpt-5.3-codex` | 1x |
| Coding | `gpt-5.1-codex-max` | 1x |
| Fast/Cheap | `claude-haiku-4.5` | 0.33x |
| Fast/Cheap | `gpt-5-mini` | 0x (free) |
| Balanced | `claude-sonnet-4.6` | 1x |
| Balanced | `gpt-5.1` | 1x |
