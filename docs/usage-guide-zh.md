# GTA-Claw 使用指南

> GTA-Claw 是一个纯空壳 AI Agent 引擎 —— 通过远程 URL 动态加载角色人设和技能模块，零硬编码智能。

---

## 目录

- [前置条件](#前置条件)
- [一、部署](#一部署)
  - [1.1 获取 GitHub OAuth App](#11-获取-github-oauth-app)
  - [1.2 一键部署](#12-一键部署)
  - [1.3 配置文件部署](#13-配置文件部署)
- [二、首次认证](#二首次认证)
- [三、连接聊天频道](#三连接聊天频道)
  - [3.1 Telegram（推荐）](#31-telegram推荐)
  - [3.2 Discord](#32-discord)
  - [3.3 Microsoft Teams](#33-microsoft-teams)
  - [3.4 WhatsApp](#34-whatsapp)
- [四、日常使用](#四日常使用)
  - [4.1 对话示例](#41-对话示例)
  - [4.2 内置技能一览](#42-内置技能一览)
- [五、角色与技能自定义](#五角色与技能自定义)
  - [5.1 角色配置](#51-角色配置)
  - [5.2 技能模块](#52-技能模块)
  - [5.3 热重载](#53-热重载)
- [六、运维管理](#六运维管理)
- [七、常见问题](#七常见问题)

---

## 前置条件

- 一台装有 Docker 的 Linux 服务器（推荐 Ubuntu 22.04+）
- GitHub 账号（需有 Copilot 访问权限）
- （可选）HTTP 代理（中国服务器访问 GitHub API 时需要）

---

## 一、部署

### 1.1 获取 GitHub OAuth App

Device Flow 是推荐的认证方式（无需域名、无需公网）：

1. 打开 https://github.com/settings/developers
2. 点击 **OAuth Apps** → **New OAuth App**
3. 填写信息：
   - **Application name**：`GTA-Claw`（任意）
   - **Homepage URL**：`http://localhost`（任意）
   - **Authorization callback URL**：`http://localhost/callback`（Device Flow 不使用，但必填）
4. 创建后点击 **Generate a new client secret**
5. **关键**：勾选 ✅ **Enable Device Flow**
6. 记下 **Client ID**（形如 `Ov23li...`）

### 1.2 一键部署

```bash
# 下载部署脚本
mkdir -p ~/gta-claw/deploy && cd ~/gta-claw/deploy
curl -fsSL https://raw.githubusercontent.com/GTAStudio/GTA-Claw/main/deploy/run.sh -o run.sh
chmod +x run.sh

# 交互式部署（跟随提示填写）
./run.sh
```

脚本会依次询问：
1. GitHub Token 或 Device Flow Client ID
2. 角色配置 URL
3. 技能模块 URL
4. AI 模型选择
5. 聊天频道设置
6. HTTP 代理（可选）
7. 高级配置

### 1.3 配置文件部署

```bash
# 复制示例配置
cp conf/gta-claw.conf.example conf/gta-claw.conf

# 编辑配置（填写实际值）
nano conf/gta-claw.conf

# 使用配置文件部署
./run.sh --config conf/gta-claw.conf
```

配置文件支持自动检测 —— 如果 `conf/gta-claw.conf` 存在，直接运行 `./run.sh` 即可自动加载。

---

## 二、首次认证

部署完成后，需要进行一次 GitHub Device Flow 授权：

1. **查看容器日志**，找到授权信息：
   ```bash
   docker logs gta-claw --tail 20
   ```

2. 日志中会显示：
   ```
   Please visit https://github.com/login/device
   and enter code: XXXX-XXXX
   ```

3. 在浏览器中打开 https://github.com/login/device
4. 输入日志中的 **user code**
5. 点击 **Authorize**
6. 授权成功后，机器人即可正常工作

> 💡 如果使用 PAT 模式（`GITHUB_TOKEN`），则无需此步骤，启动即可用。

---

## 三、连接聊天频道

GTA-Claw 支持四个聊天频道，可同时启用多个。

### 3.1 Telegram（推荐）

最简单上手，无需公网域名、无需 Webhook。

**步骤：**

1. 在 Telegram 中找到 [@BotFather](https://t.me/BotFather)
2. 发送 `/newbot`，按提示创建机器人
3. 记下返回的 **Bot Token**（形如 `123456:ABCdef...`）
4. 在配置中添加：
   ```
   ENABLE_TELEGRAM=true
   TELEGRAM_BOT_TOKEN=你的Bot Token
   ```
5. 重启容器：
   ```bash
   docker rm -f gta-claw && ./run.sh
   ```
6. 在 Telegram 中找到你的机器人，发送任意消息即可开始对话

### 3.2 Discord

通过 Gateway/WebSocket 连接，同样无需公网。

**步骤：**

1. 打开 https://discord.com/developers/applications
2. 点击 **New Application** → 输入名称 → 创建
3. 左侧菜单 **Bot** → **Add Bot**
4. 开启 **Message Content Intent**
5. 复制 **Bot Token**
6. 左侧菜单 **OAuth2** → **URL Generator**：
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Read Message History`
7. 复制生成的邀请链接，在浏览器打开，把机器人加入你的 Discord 服务器
8. 在配置中添加：
   ```
   ENABLE_DISCORD=true
   DISCORD_BOT_TOKEN=你的Bot Token
   ```
9. 重启容器

### 3.3 Microsoft Teams

需要 Azure Bot Service 注册。

**步骤：**

1. 在 [Azure Portal](https://portal.azure.com) 创建 **Azure Bot** 资源
2. 记下 **Microsoft App ID** 和 **App Password**
3. 配置 Bot 的 Messaging Endpoint 为：`https://你的域名/api/messages`
4. 在 Channels 中启用 Teams
5. 在配置中添加：
   ```
   ENABLE_TEAMS=true
   MicrosoftAppId=你的App ID
   MicrosoftAppPassword=你的App Password
   DOMAIN=你的域名
   ```
6. 重启容器

> ⚠️ Teams 频道需要公网 HTTPS 域名。

### 3.4 WhatsApp

需要 Meta Business 开发者账号和公网回调。

**步骤：**

1. 在 [Meta for Developers](https://developers.facebook.com) 创建应用
2. 添加 WhatsApp 产品，获取：
   - **Access Token**
   - **Phone Number ID**
3. 设置 Webhook 回调 URL 为：`https://你的域名/whatsapp/webhook`
4. 在配置中添加：
   ```
   ENABLE_WHATSAPP=true
   WHATSAPP_ACCESS_TOKEN=你的Access Token
   WHATSAPP_PHONE_NUMBER_ID=你的Phone Number ID
   WHATSAPP_VERIFY_TOKEN=自定义验证Token
   ```
5. 重启容器

---

## 四、日常使用

### 4.1 对话示例

连接好聊天频道后，直接用自然语言和机器人对话即可：

| 你说 | Claw 会做什么 |
|------|--------------|
| "搜索 GitHub 上最火的 Rust Web 框架" | 调用 GitHub Search 技能搜索 |
| "查看 GTAStudio/GTA-Claw 仓库信息" | 获取仓库详情和最新 release |
| "看一下最近 10 次提交" | 获取提交历史 |
| "读一下 package.json 文件" | 从 GitHub 读取文件内容 |
| "抓取 https://example.com 的网页内容" | 使用 Web Fetch 技能抓取 |
| "查询 github.com 的 DNS 解析" | 查询 DNS 记录和 IP 地理位置 |
| "检查这些 URL 是否在线" | 批量健康检查 |
| "看一下服务器磁盘空间" | 执行服务器管理命令 |
| "显示 Docker 容器状态" | 查看运行中的容器 |
| "做一个关于 AI 趋势的 5 页幻灯片" | 生成 Marp Markdown 幻灯片 |
| "帮我用 Go 写一个 HTTP 服务器" | 直接编写代码 |
| "分析这段代码的安全风险" | 代码审查和安全分析 |

### 4.2 内置技能一览

默认提供 10 个技能模块：

| 技能 | 说明 | 触发方式 |
|------|------|---------|
| `github_search` | 搜索 GitHub 仓库/Issue/代码/用户 | 提到"搜索 GitHub" |
| `github_repo_info` | 获取仓库详情 + 最新 Release | 提到仓库名 |
| `github_commits` | 查看提交历史 | "最近的提交" |
| `github_file_reader` | 在线读取仓库文件/目录 | "读取xx文件" |
| `web_fetch` | 抓取任意网页内容 | 给出 URL |
| `json_api_call` | 通用 REST API 调用（GET/POST） | "调用 API" |
| `ip_dns_lookup` | DNS 解析 + IP 地理定位 | "查询 DNS" |
| `server_health_check` | 批量端点可用性检查 | "检查是否在线" |
| `server_admin` | 服务器管理（磁盘/内存/Docker等） | "服务器状态" |
| `marp_slides` | 生成 Marp 格式幻灯片 | "做 PPT / 幻灯片" |

> 所有技能在 V8 沙箱中隔离运行，通过 `httpGet`/`httpPost`/`log` API 与外部交互。

---

## 五、角色与技能自定义

### 5.1 角色配置

角色是一个 JSON 文件，通过 URL 远程加载。格式：

```json
{
  "content": "你是一个高级项目架构师……",
  "model": "claude-opus-4.6"
}
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `content` | ✅ | 系统提示词，定义 AI 的人设和行为 |
| `model` | ❌ | 使用的模型（覆盖 `COPILOT_MODEL` 环境变量） |

**托管方式**：
- GitHub Gist（推荐，免费、可版本控制）
- 仓库中的 raw 文件 URL
- 任何可通过 HTTP 访问的 URL

### 5.2 技能模块

技能也是 JSON 文件，可自行编写扩展。格式：

```json
{
  "name": "my_skill",
  "description": "技能描述（AI 根据此字段决定何时调用）",
  "parameters": {
    "type": "object",
    "properties": {
      "query": { "type": "string", "description": "搜索关键词" }
    },
    "required": ["query"]
  },
  "executeCode": "async function(params, api) {\n  const resp = await api.httpGet('https://api.example.com?q=' + params.query);\n  return JSON.parse(resp);\n}"
}
```

**沙箱 API**：
- `api.httpGet(url)` — HTTP GET 请求
- `api.httpPost(url, body, headers)` — HTTP POST 请求
- `api.log(message)` — 输出日志

将多个技能 URL 用逗号拼接，设置到 `ENABLED_SKILLS` 即可。

### 5.3 热重载

无需重启容器，在线更新角色和技能：

```bash
curl -X POST http://localhost:3978/admin/reload \
  -H "Authorization: Bearer 你的ADMIN_TOKEN"
```

这会重新拉取所有远程 JSON 并重置活跃会话。

---

## 六、运维管理

### 常用命令

```bash
# 查看运行状态
docker ps --filter "name=gta-claw"

# 查看日志（实时跟踪）
docker logs -f gta-claw

# 查看最近 100 行日志
docker logs gta-claw --tail 100

# 健康检查
curl http://localhost:3978/health

# 停止服务
./run.sh --stop

# 更新镜像并重启
./run.sh --update

# 完全重新部署
docker rm -f gta-claw
./run.sh
```

### API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 快速引导信息（推荐先访问） |
| `/auth/device` | GET | 获取 GitHub Device Flow 授权指引和授权码 |
| `/health` | GET | 健康检查 + 状态信息 |
| `/chat` | POST | HTTP 直聊接口（无需聊天频道） |
| `/api/messages` | POST | Bot Framework 消息（Teams） |
| `/admin/reload` | POST | 热重载角色和技能（需 `ADMIN_TOKEN`） |
| `/admin/system` | GET | 系统信息（Node.js 进程 + OS） |
| `/admin/exec` | POST | 执行白名单系统命令 |

### 首次使用推荐路径

```bash
# 1) 看当前状态和推荐操作
curl http://localhost:3978/

# 2) 拉取 Device Flow 授权码
curl http://localhost:3978/auth/device

# 3) 授权后直接 HTTP 对话
curl -X POST http://localhost:3978/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "你好"}'
```

### HTTP 直聊接口

不需要配置任何聊天频道，直接通过 HTTP 和 Claw 对话：

```bash
# 发送消息
curl -X POST http://localhost:3978/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "你好，帮我看一下服务器状态"}'

# 指定会话 ID（保持上下文连续对话）
curl -X POST http://localhost:3978/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "继续", "conversation_id": "my-session-1"}'
```

返回格式：
```json
{"reply": "Claw 的回复内容..."}
```

### HTTP 代理配置

国内服务器访问 GitHub API 需要代理：

```
HTTPS_PROXY=http://127.0.0.1:7890
HTTP_PROXY=http://127.0.0.1:7890
```

---

## 七、常见问题

### Q: 启动后没有看到 Device Flow 授权码？
检查日志中是否有报错。确认 `DEVICE_FLOW_ENABLED=true` 和 `GITHUB_CLIENT_ID` 已正确设置。

### Q: Docker 镜像拉取失败？
脚本会自动回退到从源码构建。如果克隆也失败，检查网络/代理设置。

### Q: 技能没有被调用？
确认 `ENABLED_SKILLS` 中的 URL 可以正常访问。可用 `curl` 测试 URL 是否返回有效 JSON。

### Q: 如何更换 AI 模型？
修改角色配置 JSON 中的 `model` 字段，然后调用 `/admin/reload` 热重载。

### Q: 如何同时使用多个频道？
在配置中同时设置多个 `ENABLE_xxx=true` 及对应的 Token，重启即可。

### Q: Telegram 机器人不回复？
1. 确认 `TELEGRAM_BOT_TOKEN` 正确
2. 检查代理配置（国内需要代理才能连 Telegram API）
3. 查看日志是否有连接错误

### Q: 支持哪些 AI 模型？

| 类型 | 模型 | 特点 |
|------|------|------|
| 推理 | `claude-opus-4.6` | 最强推理，3x 消耗 |
| 编码 | `gpt-5.3-codex` | 代码专精 |
| 均衡 | `claude-sonnet-4.6` | 性价比最佳 |
| 均衡 | `gpt-5.1` | 通用均衡 |
| 快速 | `gpt-5-mini` | 免费 |
| 快速 | `claude-haiku-4.5` | 0.33x 低消耗 |
