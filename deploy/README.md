# GTA-Claw 服务器部署

将此 `deploy/` 目录上传到服务器即可部署，无需源码。

## 快速开始

```bash
# 1. 赋予执行权限
chmod +x run.sh

# 2a. 交互式部署 (跟随向导填写配置)
./run.sh

# 2b. 或从配置文件部署
cp conf/gta-claw.conf.example conf/gta-claw.conf
vim conf/gta-claw.conf    # 填写实际值
./run.sh --config conf/gta-claw.conf
```

默认采用 Docker 单容器模式（`docker pull` + `docker run`），不依赖 compose。

## 鉴权模式

支持两种方式（二选一）：

1. `GITHUB_TOKEN` (PAT)
2. Device Flow 设备授权（推荐，无需域名）

Device Flow 模式只需要在 `conf/gta-claw.conf` 中配置：

```ini
DEVICE_FLOW_ENABLED=true
GITHUB_CLIENT_ID=你的 OAuth App Client ID
```

用户给机器人发消息时，机器人会回复一个验证码和链接（https://github.com/login/device），用户在浏览器中输入验证码即可完成授权。

**不需要域名、回调 URL 或 Client Secret。**

## 四通道兼容

可同时启用以下通道：

1. Teams（默认开启）
2. Telegram Polling（无需公网回调）
3. Discord Gateway（无需公网回调）
4. WhatsApp Webhook（通常需要公网回调）

在 `conf/gta-claw.conf` 里通过以下开关控制：

```ini
ENABLE_TEAMS=true
ENABLE_TELEGRAM=false
ENABLE_DISCORD=false
ENABLE_WHATSAPP=false
```

内网部署建议：优先 Telegram/Discord + PAT (`GITHUB_TOKEN`)。

## 常用命令

| 命令 | 说明 |
|------|------|
| `./run.sh` | 交互式部署向导 |
| `./run.sh --config <file>` | 从配置文件部署 |
| `./run.sh --update` | 拉取最新镜像并重启 |
| `./run.sh --stop` | 停止所有服务 |
| `./run.sh --status` | 查看服务状态 |
| `./run.sh --logs` | 查看实时日志 |

## 目录结构

```
deploy/
├── run.sh                      部署脚本
└── conf/
    └── gta-claw.conf.example   配置模板
```

## 要求

- Docker
- 若需 HTTPS，请在宿主机已有反向代理（Nginx/Caddy/Traefik）上转发到 `127.0.0.1:3978`
