#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GTA-Claw 一键部署脚本
#
# 用法:
#   ./run.sh                          交互式部署
#   ./run.sh --config conf/gta-claw.conf  从配置文件部署
#   ./run.sh --update                 更新镜像并重启
#   ./run.sh --stop                   停止所有服务
#   ./run.sh --status                 查看服务状态
#   ./run.sh --logs                   查看实时日志
#   ./run.sh --help                   帮助信息
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- 颜色 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ENV_FILE=".env"

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*"; }
log_step()  { echo -e "${CYAN}[»]${NC} ${BOLD}$*${NC}"; }

# ---- 前置检查 ----
check_prerequisites() {
  local missing=0

  if ! command -v docker &>/dev/null; then
    log_error "未检测到 docker，请先安装: https://docs.docker.com/engine/install/"
    missing=1
  fi

  if ! docker compose version &>/dev/null 2>&1; then
    log_error "未检测到 docker compose 插件，请先安装"
    missing=1
  fi

  if [ "$missing" -ne 0 ]; then
    exit 1
  fi

  # 检查 docker daemon 是否运行
  if ! docker info &>/dev/null 2>&1; then
    log_error "Docker daemon 未运行，请先启动 Docker"
    exit 1
  fi
}

# ---- 可选模型列表 ----
MODELS=(
  "gpt-4o             (默认, 均衡)"
  "claude-opus-4.6    (推理, 3x)"
  "gpt-5.3-codex      (编程, 1x)"
  "gpt-5.2-codex      (编程, 1x)"
  "gpt-5.1-codex-max  (编程, 1x)"
  "claude-sonnet-4.6  (均衡, 1x)"
  "gpt-5.2            (推理, 1x)"
  "gemini-3.1-pro     (推理, 1x)"
  "claude-haiku-4.5   (快速/低耗, 0.33x)"
  "gpt-5-mini         (免费, 0x)"
  "gpt-5.1-codex-mini (快速, 0.33x)"
)

# ---- 交互辅助函数 ----
prompt_required() {
  local var_name="$1"
  local prompt_text="$2"
  local value=""
  while [ -z "$value" ]; do
    read -rp "  $prompt_text: " value
    if [ -z "$value" ]; then
      log_error "$var_name 为必填项"
    fi
  done
  echo "$value"
}

prompt_optional() {
  local prompt_text="$1"
  local default="$2"
  local value
  read -rp "  $prompt_text [$default]: " value
  echo "${value:-$default}"
}

prompt_secret() {
  local var_name="$1"
  local prompt_text="$2"
  local value=""
  while [ -z "$value" ]; do
    read -rsp "  $prompt_text: " value
    echo ""
    if [ -z "$value" ]; then
      log_error "$var_name 为必填项"
    fi
  done
  echo "$value"
}

select_model() {
  echo ""
  log_step "选择 AI 模型:"
  for i in "${!MODELS[@]}"; do
    echo "    $((i+1)). ${MODELS[$i]}"
  done
  echo ""
  local choice
  read -rp "  输入编号 [1]: " choice
  choice="${choice:-1}"

  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#MODELS[@]}" ]; then
    echo "${MODELS[$((choice-1))]}" | awk '{print $1}'
  else
    echo "gpt-4o"
  fi
}

validate_url() {
  local url="$1"
  local label="$2"
  if [[ ! "$url" =~ ^https?:// ]]; then
    log_error "无效的 URL ($label): $url"
    return 1
  fi
  return 0
}

# ---- 从配置文件部署 ----
do_config() {
  local config_file="$1"
  if [ ! -f "$config_file" ]; then
    log_error "配置文件不存在: $config_file"
    exit 1
  fi

  log_step "正在加载配置文件: $config_file"

  # 读取配置文件到 .env (去掉注释和空行)
  grep -v '^\s*#' "$config_file" | grep -v '^\s*$' | grep '=' > "$ENV_FILE"

  # 验证必填项
  local has_error=0
  for var in GITHUB_TOKEN MicrosoftAppId MicrosoftAppPassword AGENT_ROLE_URL ENABLED_SKILLS; do
    if ! grep -q "^${var}=.\+" "$ENV_FILE"; then
      log_error "缺少必填配置: $var"
      has_error=1
    fi
  done

  if [ "$has_error" -ne 0 ]; then
    log_error "请检查配置文件并补充必填项"
    rm -f "$ENV_FILE"
    exit 1
  fi

  log_info "配置文件验证通过"
  do_deploy
}

# ---- 交互式部署 ----
do_interactive() {
  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║     GTA-Claw — 交互式部署向导            ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
  echo ""

  # 如果已存在 .env，询问是否覆盖
  if [ -f "$ENV_FILE" ]; then
    echo -e "  ${YELLOW}检测到已有配置文件 (.env)${NC}"
    local overwrite
    read -rp "  是否重新配置？(y/N): " overwrite
    if [[ ! "$overwrite" =~ ^[yY] ]]; then
      log_info "使用现有配置"
      do_deploy
      return
    fi
  fi

  log_step "[1/7] GitHub 认证"
  local github_token
  github_token=$(prompt_secret "GITHUB_TOKEN" "GitHub PAT (需要 Copilot Requests 权限)")

  log_step "[2/7] Azure Bot 凭据"
  local app_id app_password
  app_id=$(prompt_required "MicrosoftAppId" "Microsoft App ID")
  app_password=$(prompt_secret "MicrosoftAppPassword" "Microsoft App Password")

  log_step "[3/7] Role 配置"
  echo -e "  ${CYAN}提示: 指向一个 JSON 文件, 格式: {\"content\": \"You are...\", \"model\": \"gpt-4o\"}${NC}"
  local role_url
  role_url=$(prompt_required "AGENT_ROLE_URL" "Role 配置 URL")
  validate_url "$role_url" "AGENT_ROLE_URL"

  log_step "[4/7] Skills 配置"
  echo -e "  ${CYAN}提示: 多个 Skill URL 用逗号分隔${NC}"
  local skills_urls
  skills_urls=$(prompt_required "ENABLED_SKILLS" "Skill URLs")

  log_step "[5/7] AI 模型"
  local model
  model=$(select_model)
  log_info "已选择模型: $model"

  log_step "[6/7] 域名配置"
  echo -e "  ${CYAN}提示: Caddy 会自动申请 HTTPS 证书, 本地测试用 localhost${NC}"
  local domain
  domain=$(prompt_optional "域名" "localhost")

  log_step "[7/7] 高级选项"
  local docker_image rate_limit admin_token auto_update trust_proxy
  docker_image=$(prompt_optional "Docker 镜像" "gtastudio/gta-claw:latest")
  rate_limit=$(prompt_optional "速率限制 (每IP每分钟请求数)" "30")
  auto_update=$(prompt_optional "自动更新 SDK/CLI (true/false)" "false")
  trust_proxy=$(prompt_optional "信任反向代理头 (true/false)" "false")
  admin_token=$(prompt_optional "Admin API 令牌 (留空禁用)" "")

  # 写入 .env
  cat > "$ENV_FILE" <<EOF
# GTA-Claw 配置 (由 run.sh 自动生成)
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

DOCKER_IMAGE=${docker_image}
GITHUB_TOKEN=${github_token}
MicrosoftAppId=${app_id}
MicrosoftAppPassword=${app_password}
AGENT_ROLE_URL=${role_url}
ENABLED_SKILLS=${skills_urls}
COPILOT_MODEL=${model}
DOMAIN=${domain}
LOG_LEVEL=info
MAX_SESSIONS=100
SESSION_TTL_MS=3600000
SKILL_EXEC_TIMEOUT_MS=30000
SDK_REQUEST_TIMEOUT_MS=120000
RATE_LIMIT_PER_MIN=${rate_limit}
TRUST_PROXY=${trust_proxy}
AUTO_UPDATE=${auto_update}
ADMIN_TOKEN=${admin_token}
EOF

  log_info "配置已保存到 .env"
  echo ""
  do_deploy
}

# ---- 部署 ----
do_deploy() {
  log_step "拉取最新镜像..."
  # 从 .env 读取镜像名 (如果有的话)
  local image
  image=$(grep "^DOCKER_IMAGE=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "gtastudio/gta-claw:latest")
  docker pull "$image" || log_warn "镜像拉取失败，将使用本地缓存 (如有)"

  log_step "启动服务..."
  docker compose up -d

  echo ""
  log_info "部署完成！"
  echo ""

  # 等待健康检查
  log_step "等待服务就绪..."
  local retries=0
  while [ "$retries" -lt 30 ]; do
    if docker compose ps --format json 2>/dev/null | grep -q '"healthy"'; then
      break
    fi
    sleep 2
    retries=$((retries + 1))
  done

  echo ""
  docker compose ps
  echo ""

  local domain
  domain=$(grep "^DOMAIN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "localhost")
  echo -e "${BOLD}═══════════════════════════════════════${NC}"
  log_info "健康检查: https://${domain}/health"
  log_info "Bot 端点:  https://${domain}/api/messages"
  echo -e "${BOLD}═══════════════════════════════════════${NC}"
  echo ""
  log_info "查看日志: ./run.sh --logs"
  log_info "停止服务: ./run.sh --stop"
}

# ---- 更新镜像 ----
do_update() {
  log_step "更新 GTA-Claw 镜像..."

  if [ -f "$ENV_FILE" ]; then
    local image
    image=$(grep "^DOCKER_IMAGE=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "gtastudio/gta-claw:latest")
    docker pull "$image"
  else
    docker pull gtastudio/gta-claw:latest
  fi

  log_step "重启服务..."
  docker compose up -d
  log_info "更新完成"
  docker compose ps
}

# ---- 停止 ----
do_stop() {
  log_step "停止所有 GTA-Claw 服务..."
  docker compose down
  log_info "所有服务已停止"
}

# ---- 状态 ----
do_status() {
  log_step "服务状态:"
  docker compose ps

  echo ""
  # 尝试获取健康检查
  local domain
  domain=$(grep "^DOMAIN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "localhost")
  if curl -sf "http://localhost:3978/health" &>/dev/null 2>&1; then
    log_info "健康检查:"
    curl -s "http://localhost:3978/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || \
      curl -s "http://localhost:3978/health" 2>/dev/null || true
  elif docker compose exec -T gta-claw curl -sf "http://localhost:3978/health" &>/dev/null 2>&1; then
    log_info "健康检查 (容器内):"
    docker compose exec -T gta-claw curl -s "http://localhost:3978/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || true
  fi
}

# ---- 日志 ----
do_logs() {
  docker compose logs -f --tail=100
}

# ---- 帮助 ----
do_help() {
  echo ""
  echo -e "${BOLD}GTA-Claw 部署脚本${NC}"
  echo ""
  echo "用法:"
  echo "  ./run.sh                               交互式部署向导"
  echo "  ./run.sh --config conf/gta-claw.conf   从配置文件部署"
  echo "  ./run.sh --update                      拉取最新镜像并重启"
  echo "  ./run.sh --stop                        停止所有服务"
  echo "  ./run.sh --status                      查看服务状态和健康检查"
  echo "  ./run.sh --logs                        查看实时日志"
  echo "  ./run.sh --help                        显示帮助信息"
  echo ""
  echo "配置文件:"
  echo "  conf/gta-claw.conf.example             配置文件模板"
  echo "  复制为 conf/gta-claw.conf 并填写实际值"
  echo ""
  echo "目录结构:"
  echo "  deploy/"
  echo "  ├── run.sh                 部署脚本"
  echo "  ├── docker-compose.yml     容器编排"
  echo "  ├── caddy/"
  echo "  │   └── Caddyfile          反向代理配置"
  echo "  └── conf/"
  echo "      └── gta-claw.conf.example  配置模板"
  echo ""
}

# ---- Main ----
check_prerequisites

case "${1:-}" in
  --config|-c)
    if [ -z "${2:-}" ]; then
      log_error "用法: ./run.sh --config <配置文件路径>"
      log_error "示例: ./run.sh --config conf/gta-claw.conf"
      exit 1
    fi
    do_config "$2"
    ;;
  --update|-u)
    do_update
    ;;
  --stop|-s)
    do_stop
    ;;
  --status)
    do_status
    ;;
  --logs|-l)
    do_logs
    ;;
  --help|-h)
    do_help
    ;;
  *)
    do_interactive
    ;;
esac
