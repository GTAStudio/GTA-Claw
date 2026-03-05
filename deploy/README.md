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
├── docker-compose.yml          容器编排 (从 Docker Hub 拉取镜像)
├── caddy/
│   └── Caddyfile               Caddy 反向代理 (自动 HTTPS)
└── conf/
    └── gta-claw.conf.example   配置模板
```

## 要求

- Docker + Docker Compose 插件
- 80/443 端口开放 (Caddy HTTPS)
- 有效的域名指向服务器 (Caddy 自动申请 Let's Encrypt 证书)
