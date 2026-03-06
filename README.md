# GTA-Claw — Self-Governing AI Agent Engine

> A pure empty-shell engine that dynamically loads roles and skills from remote URLs. Zero hardcoded intelligence.

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your credentials

# 2. Deploy (docker-only, no compose needed)
cd deploy
chmod +x run.sh
./run.sh

# Or deploy from config file
./run.sh --config conf/gta-claw.conf
```

## Architecture

```
Internet → Reverse Proxy (:443 HTTPS) → GTA-Claw Engine (:3978)
                                            │
                                       ┌────┴───────────────────────┐
                                       │  Multi-Channel Gateway      │
                                       │  • Teams (Bot Framework)    │
                                       │  • Telegram (Polling)       │
                                       │  • Discord (Gateway/WS)     │
                                       │  • WhatsApp (Webhook)       │
                                       └───────────┬─────────────┘
                                       ┌───────────┴─────────────┐
                                       │ CopilotEngine             │
                                       │ @github/copilot-sdk       │
                                       └───────────┬─────────────┘
                                       ┌───────────┴─────────────┐
                                       │ ToolExecutor              │
                                       │ isolated-vm sandbox       │
                                       └─────────────────────────┘
```

**Core Principle**: The engine is an empty shell. All intelligence comes from:
- **Role** (`AGENT_ROLE_URL`): System prompt + model selection loaded from a remote URL
- **Skills** (`ENABLED_SKILLS`): Tool definitions + sandboxed code loaded from remote URLs

## Configuration

### Required Environment Variables

Authentication now supports two modes:
- **PAT mode**: set `GITHUB_TOKEN`
- **OAuth mode**: set `OAUTH_ENABLED=true` and OAuth variables below

| Variable | Description |
|----------|-------------|
| `MicrosoftAppId` | Azure Bot Service App ID |
| `MicrosoftAppPassword` | Azure Bot Service App Password |
| `AGENT_ROLE_URL` | URL to role config JSON |
| `ENABLED_SKILLS` | Comma-separated URLs to skill JSON modules |

### Authentication Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | *(empty)* | PAT token for direct auth mode |
| `DEVICE_FLOW_ENABLED` | `false` | Enable GitHub Device Flow authorization |
| `GITHUB_CLIENT_ID` | *(empty)* | GitHub OAuth App Client ID (for Device Flow) |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COPILOT_MODEL` | `gpt-4o` | Default model (overridden by role config) |
| `DOMAIN` | `localhost` | Domain for Caddy HTTPS |
| `PORT` | `3978` | Internal server port |
| `LOG_LEVEL` | `info` | Logging level |
| `MAX_SESSIONS` | `100` | Max concurrent sessions |
| `SESSION_TTL_MS` | `3600000` | Session idle timeout (1 hour) |
| `SKILL_EXEC_TIMEOUT_MS` | `30000` | Skill execution timeout |
| `SDK_REQUEST_TIMEOUT_MS` | `120000` | SDK request timeout |
| `RATE_LIMIT_PER_MIN` | `30` | Per-IP rate limit for `/api/messages` |
| `ALLOWED_SKILL_DOMAINS` | *(empty)* | Domain whitelist for skill HTTP calls |
| `TRUST_PROXY` | `false` | Trust `x-forwarded-for` from upstream proxy |
| `AUTO_UPDATE` | `false` | Auto-update SDK/CLI on startup |
| `ADMIN_TOKEN` | *(empty)* | Token for admin endpoints |

## Role Configuration

Roles are hosted as JSON files at any accessible URL:

```json
{
  "content": "You are a senior project architect. Your responsibilities include...",
  "model": "claude-opus-4.6"
}
```

- `content` (required): The system prompt defining the AI's persona and behavior
- `model` (optional): Per-role model selection. Falls back to `COPILOT_MODEL` env var

### Available Models

| Category | Model | Multiplier |
|----------|-------|-----------|
| Reasoning | `claude-opus-4.6` | 3x |
| Coding | `gpt-5.3-codex` | 1x |
| Coding | `gpt-5.1-codex-max` | 1x |
| Balanced | `claude-sonnet-4.6` | 1x |
| Balanced | `gpt-5.1` | 1x |
| Fast/Cheap | `gpt-5-mini` | 0x (free) |
| Fast/Cheap | `claude-haiku-4.5` | 0.33x |

## Skill Module Format

Skills are hosted as JSON files at any accessible URL:

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
  "executeCode": "async function(params, api) {\n  const resp = await api.httpGet('https://wttr.in/' + encodeURIComponent(params.city) + '?format=j1');\n  return JSON.parse(resp);\n}"
}
```

### Sandbox API

Skills execute in an isolated V8 sandbox with these bridges:
- `api.httpGet(url)` — HTTP GET (domain whitelisted)
- `api.httpPost(url, body, headers)` — HTTP POST (domain whitelisted)
- `api.log(message)` — Log to host

## Deployment

`deploy/run.sh` uses docker-only mode (`docker pull` + `docker run`),
without requiring docker compose.

### Interactive Mode
```bash
cd deploy
./run.sh
```
Prompts for credentials, role URL, skills, model, channels, and advanced options.

### Config File Mode
```bash
./run.sh --config conf/gta-claw.conf
```

### Update Image
```bash
./run.sh --update
```

### Stop Services
```bash
./run.sh --stop
```

## CI/CD: Auto Push To Docker Hub

This repository includes a GitHub Actions workflow at `.github/workflows/docker-publish.yml`.

It automatically builds and pushes Docker images when:
- code is pushed to `main`
- a tag matching `v*` is pushed
- manually triggered from GitHub Actions (`workflow_dispatch`)

### Required GitHub Secrets

In your GitHub repo, add these secrets:
- `DOCKERHUB_USERNAME`: your Docker Hub username
- `DOCKERHUB_TOKEN`: Docker Hub access token (not password)
- `DOCKERHUB_IMAGE` (recommended): full image name, e.g. `docker.io/aizhihuxiao/gta-claw`

### Published Image

The workflow publishes to:
- `docker.io/<DOCKERHUB_USERNAME>/gta-claw`

If `DOCKERHUB_IMAGE` is not set, the workflow defaults to `docker.io/<DOCKERHUB_USERNAME>/gta-claw` and normalizes the namespace to lowercase. Use `DOCKERHUB_IMAGE` when publishing to org namespaces.

Generated tags include:
- `latest` (default branch)
- branch/tag based tags
- `sha-<commit>`

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/messages` | POST | Bot Framework messages (Teams) |
| `/health` | GET | Health check + status |
| `/admin/reload` | POST | Hot-reload role+skills and reset active sessions (requires `ADMIN_TOKEN`) |

## Channel Compatibility

GTA-Claw supports four channel modes (can be enabled together):

1. Teams (`ENABLE_TEAMS=true`)
2. Telegram Polling (`ENABLE_TELEGRAM=true`) — no public webhook required
3. Discord Gateway (`ENABLE_DISCORD=true`) — no public webhook required
4. WhatsApp Webhook (`ENABLE_WHATSAPP=true`) — public callback usually required

Recommended auth strategy:

1. Enterprise/public deployment: Device Flow (`DEVICE_FLOW_ENABLED=true`) — no domain needed
2. Internal-only deployment: PAT (`GITHUB_TOKEN`) for simplest setup

## Prerequisites

- Docker
- GitHub account with Copilot access
- Azure Bot Service registration (only if using Teams channel)

## Security

- Skills run in V8 isolate sandbox (`isolated-vm`) with memory limits when available
- If `isolated-vm` is unavailable, engine falls back to Node `vm` sandbox mode (reduced isolation)
- Domain whitelist for skill HTTP calls
- Rate limiting on bot endpoint (30 req/min per IP)
- Non-root Docker user
- HTTPS via reverse proxy (Caddy/Nginx/Traefik)

## ⚠️ Notice

`@github/copilot-sdk` is in **Technical Preview** and may not yet be suitable for production use. Monitor the [official repository](https://github.com/github/copilot-sdk) for stability updates.
