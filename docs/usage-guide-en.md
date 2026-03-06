# GTA-Claw Usage Guide

> GTA-Claw is a pure empty-shell AI Agent engine — it dynamically loads roles and skills from remote URLs. Zero hardcoded intelligence.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [1. Deployment](#1-deployment)
  - [1.1 Create a GitHub OAuth App](#11-create-a-github-oauth-app)
  - [1.2 One-Command Deploy](#12-one-command-deploy)
  - [1.3 Config File Deploy](#13-config-file-deploy)
- [2. First-Time Authentication](#2-first-time-authentication)
- [3. Connect Chat Channels](#3-connect-chat-channels)
  - [3.1 Telegram (Recommended)](#31-telegram-recommended)
  - [3.2 Discord](#32-discord)
  - [3.3 Microsoft Teams](#33-microsoft-teams)
  - [3.4 WhatsApp](#34-whatsapp)
- [4. Daily Usage](#4-daily-usage)
  - [4.1 Conversation Examples](#41-conversation-examples)
  - [4.2 Built-in Skills](#42-built-in-skills)
- [5. Customizing Roles & Skills](#5-customizing-roles--skills)
  - [5.1 Role Configuration](#51-role-configuration)
  - [5.2 Skill Modules](#52-skill-modules)
  - [5.3 Hot Reload](#53-hot-reload)
- [6. Operations & Maintenance](#6-operations--maintenance)
- [7. FAQ](#7-faq)

---

## Prerequisites

- A Linux server with Docker installed (Ubuntu 22.04+ recommended)
- A GitHub account with Copilot access
- (Optional) HTTP proxy if deploying from regions with restricted GitHub access

---

## 1. Deployment

### 1.1 Create a GitHub OAuth App

Device Flow is the recommended authentication method — no domain or public IP required.

1. Go to https://github.com/settings/developers
2. Click **OAuth Apps** → **New OAuth App**
3. Fill in:
   - **Application name**: `GTA-Claw` (anything)
   - **Homepage URL**: `http://localhost` (anything)
   - **Authorization callback URL**: `http://localhost/callback` (Device Flow doesn't use it, but it's required)
4. After creation, click **Generate a new client secret**
5. **Important**: Check ✅ **Enable Device Flow**
6. Note your **Client ID** (looks like `Ov23li...`)

### 1.2 One-Command Deploy

```bash
# Download the deploy script
mkdir -p ~/gta-claw/deploy && cd ~/gta-claw/deploy
curl -fsSL https://raw.githubusercontent.com/GTAStudio/GTA-Claw/main/deploy/run.sh -o run.sh
chmod +x run.sh

# Interactive deploy (follow the prompts)
./run.sh
```

The script will ask for:
1. GitHub Token or Device Flow Client ID
2. Role configuration URL
3. Skill module URLs
4. AI model selection
5. Chat channel settings
6. HTTP proxy (optional)
7. Advanced options

### 1.3 Config File Deploy

```bash
# Copy the example config
cp conf/gta-claw.conf.example conf/gta-claw.conf

# Edit with your actual values
nano conf/gta-claw.conf

# Deploy using the config file
./run.sh --config conf/gta-claw.conf
```

Auto-detection is supported — if `conf/gta-claw.conf` exists, simply running `./run.sh` will load it automatically.

---

## 2. First-Time Authentication

After deployment, you need to authorize via GitHub Device Flow once:

1. **Check the container logs** for the authorization prompt:
   ```bash
   docker logs gta-claw --tail 20
   ```

2. You'll see something like:
   ```
   Please visit https://github.com/login/device
   and enter code: XXXX-XXXX
   ```

3. Open https://github.com/login/device in your browser
4. Enter the **user code** from the logs
5. Click **Authorize**
6. Once authorized, the bot is ready to use

> 💡 If using PAT mode (`GITHUB_TOKEN`), no authorization step is needed — it works immediately.

---

## 3. Connect Chat Channels

GTA-Claw supports four chat channels. Multiple channels can be enabled simultaneously.

### 3.1 Telegram (Recommended)

Easiest to set up. No public domain or webhook required.

**Steps:**

1. Find [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts to create a bot
3. Note the **Bot Token** (looks like `123456:ABCdef...`)
4. Add to your config:
   ```
   ENABLE_TELEGRAM=true
   TELEGRAM_BOT_TOKEN=your_bot_token
   ```
5. Restart the container:
   ```bash
   docker rm -f gta-claw && ./run.sh
   ```
6. Find your bot on Telegram and send any message to start chatting

### 3.2 Discord

Connects via Gateway/WebSocket — no public URL needed.

**Steps:**

1. Go to https://discord.com/developers/applications
2. Click **New Application** → enter a name → create
3. Go to **Bot** in the left menu → **Add Bot**
4. Enable **Message Content Intent**
5. Copy the **Bot Token**
6. Go to **OAuth2** → **URL Generator**:
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Read Message History`
7. Open the generated invite link in your browser to add the bot to your server
8. Add to your config:
   ```
   ENABLE_DISCORD=true
   DISCORD_BOT_TOKEN=your_bot_token
   ```
9. Restart the container

### 3.3 Microsoft Teams

Requires Azure Bot Service registration.

**Steps:**

1. Create an **Azure Bot** resource in the [Azure Portal](https://portal.azure.com)
2. Note the **Microsoft App ID** and **App Password**
3. Set the Bot Messaging Endpoint to: `https://your-domain/api/messages`
4. Enable the Teams channel
5. Add to your config:
   ```
   ENABLE_TEAMS=true
   MicrosoftAppId=your_app_id
   MicrosoftAppPassword=your_app_password
   DOMAIN=your-domain
   ```
6. Restart the container

> ⚠️ Teams requires a public HTTPS domain.

### 3.4 WhatsApp

Requires a Meta Business developer account and a public callback URL.

**Steps:**

1. Create an app at [Meta for Developers](https://developers.facebook.com)
2. Add the WhatsApp product and obtain:
   - **Access Token**
   - **Phone Number ID**
3. Set the Webhook callback URL to: `https://your-domain/whatsapp/webhook`
4. Add to your config:
   ```
   ENABLE_WHATSAPP=true
   WHATSAPP_ACCESS_TOKEN=your_access_token
   WHATSAPP_PHONE_NUMBER_ID=your_phone_number_id
   WHATSAPP_VERIFY_TOKEN=your_custom_verify_token
   ```
5. Restart the container

---

## 4. Daily Usage

### 4.1 Conversation Examples

Once connected to a chat channel, just talk naturally:

| You say | Claw does |
|---------|-----------|
| "Search GitHub for the best Rust web frameworks" | Calls GitHub Search skill |
| "Show me details of the GTAStudio/GTA-Claw repo" | Fetches repo info and latest release |
| "Show the last 10 commits" | Retrieves commit history |
| "Read the package.json file" | Reads file content from GitHub |
| "Fetch the content of https://example.com" | Uses Web Fetch skill |
| "Look up DNS records for github.com" | Queries DNS and IP geolocation |
| "Check if these URLs are online" | Batch health check |
| "Show server disk usage" | Runs server admin command |
| "Show Docker container status" | Lists running containers |
| "Create a 5-slide presentation about AI trends" | Generates Marp Markdown slides |
| "Write me an HTTP server in Go" | Writes code directly |
| "Analyze this code for security risks" | Code review and security analysis |

### 4.2 Built-in Skills

10 skill modules are included by default:

| Skill | Description | Trigger |
|-------|-------------|---------|
| `github_search` | Search GitHub repos/issues/code/users | Mention "search GitHub" |
| `github_repo_info` | Get repo details + latest release | Mention a repo name |
| `github_commits` | View commit history | "Recent commits" |
| `github_file_reader` | Read files/directories from repos | "Read file X" |
| `web_fetch` | Fetch any web page content | Provide a URL |
| `json_api_call` | Generic REST API calls (GET/POST) | "Call API" |
| `ip_dns_lookup` | DNS resolution + IP geolocation | "Look up DNS" |
| `server_health_check` | Batch endpoint availability checks | "Check if online" |
| `server_admin` | Server management (disk/memory/Docker) | "Server status" |
| `marp_slides` | Generate Marp-format slide decks | "Make a PPT / slides" |

> All skills run in an isolated V8 sandbox, interacting with the outside world through `httpGet`/`httpPost`/`log` APIs.

---

## 5. Customizing Roles & Skills

### 5.1 Role Configuration

A role is a JSON file loaded from a remote URL:

```json
{
  "content": "You are a senior project architect...",
  "model": "claude-opus-4.6"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `content` | ✅ | System prompt defining the AI's persona and behavior |
| `model` | ❌ | Model to use (overrides the `COPILOT_MODEL` env var) |

**Hosting options**:
- GitHub Gist (recommended — free, version-controlled)
- Raw file URL from a repository
- Any HTTP-accessible URL

### 5.2 Skill Modules

Skills are also JSON files. You can write your own:

```json
{
  "name": "my_skill",
  "description": "Skill description (the AI uses this to decide when to invoke it)",
  "parameters": {
    "type": "object",
    "properties": {
      "query": { "type": "string", "description": "Search keyword" }
    },
    "required": ["query"]
  },
  "executeCode": "async function(params, api) {\n  const resp = await api.httpGet('https://api.example.com?q=' + params.query);\n  return JSON.parse(resp);\n}"
}
```

**Sandbox API**:
- `api.httpGet(url)` — HTTP GET request
- `api.httpPost(url, body, headers)` — HTTP POST request
- `api.log(message)` — Output log message

Concatenate multiple skill URLs with commas and set them as `ENABLED_SKILLS`.

### 5.3 Hot Reload

Update roles and skills without restarting:

```bash
curl -X POST http://localhost:3978/admin/reload \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

This re-fetches all remote JSON files and resets active sessions.

---

## 6. Operations & Maintenance

### Common Commands

```bash
# Check running status
docker ps --filter "name=gta-claw"

# Follow logs in real-time
docker logs -f gta-claw

# View the last 100 log lines
docker logs gta-claw --tail 100

# Health check
curl http://localhost:3978/health

# Stop the service
./run.sh --stop

# Update the image and restart
./run.sh --update

# Full redeploy
docker rm -f gta-claw
./run.sh
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check + status info |
| `/api/messages` | POST | Bot Framework messages (Teams) |
| `/admin/reload` | POST | Hot-reload role and skills (requires `ADMIN_TOKEN`) |
| `/admin/system` | GET | System info (Node.js process + OS) |
| `/admin/exec` | POST | Execute whitelisted system commands |

### HTTP Proxy Configuration

For servers that need a proxy to reach GitHub API:

```
HTTPS_PROXY=http://127.0.0.1:7890
HTTP_PROXY=http://127.0.0.1:7890
```

---

## 7. FAQ

### Q: I don't see the Device Flow authorization code after starting?
Check the logs for errors. Make sure `DEVICE_FLOW_ENABLED=true` and `GITHUB_CLIENT_ID` are set correctly.

### Q: Docker image pull failed?
The script automatically falls back to building from source. If cloning also fails, check your network and proxy settings.

### Q: Skills are not being invoked?
Verify the URLs in `ENABLED_SKILLS` are accessible. Test each URL with `curl` to confirm it returns valid JSON.

### Q: How do I change the AI model?
Edit the `model` field in your role config JSON, then call `/admin/reload` to hot-reload.

### Q: How do I use multiple channels at once?
Set multiple `ENABLE_xxx=true` flags with their corresponding tokens in the config, then restart.

### Q: Telegram bot isn't responding?
1. Verify `TELEGRAM_BOT_TOKEN` is correct
2. Check proxy settings (a proxy is needed to reach the Telegram API from some regions)
3. Check logs for connection errors

### Q: What AI models are supported?

| Category | Model | Notes |
|----------|-------|-------|
| Reasoning | `claude-opus-4.6` | Most powerful, 3x cost |
| Coding | `gpt-5.3-codex` | Code-specialized |
| Balanced | `claude-sonnet-4.6` | Best value |
| Balanced | `gpt-5.1` | General purpose |
| Fast | `gpt-5-mini` | Free tier |
| Fast | `claude-haiku-4.5` | 0.33x low cost |
