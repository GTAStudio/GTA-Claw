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
LANG_CHOICE="${APP_LANG:-zh}"

log_info()  { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*"; }
log_step()  { echo -e "${CYAN}[»]${NC} ${BOLD}$*${NC}"; }

is_en() {
  [ "$LANG_CHOICE" = "en" ]
}

msg() {
  local key="$1"
  case "$key" in
    lang_prompt) if is_en; then echo "Choose language: 1) English  2) 中文"; else echo "请选择语言：1) English  2) 中文"; fi ;;
    lang_input) if is_en; then echo "Enter choice [2]:"; else echo "输入选项 [2]："; fi ;;
    banner_top) if is_en; then echo "╔══════════════════════════════════════════╗"; else echo "╔══════════════════════════════════════════╗"; fi ;;
    banner_mid) if is_en; then echo "║      GTA-Claw — Interactive Setup       ║"; else echo "║     GTA-Claw — 交互式部署向导            ║"; fi ;;
    banner_bot) if is_en; then echo "╚══════════════════════════════════════════╝"; else echo "╚══════════════════════════════════════════╝"; fi ;;
    existing_env) if is_en; then echo "Detected existing .env file"; else echo "检测到已有配置文件 (.env)"; fi ;;
    reconfigure) if is_en; then echo "Reconfigure? (y/N):"; else echo "是否重新配置？(y/N):"; fi ;;
    use_existing) if is_en; then echo "Using existing configuration"; else echo "使用现有配置"; fi ;;
    step_auth) if is_en; then echo "[1/8] GitHub auth mode"; else echo "[1/8] GitHub 认证方式"; fi ;;
    step_bot) if is_en; then echo "[2/8] Azure Bot credentials"; else echo "[2/8] Azure Bot 凭据"; fi ;;
    step_role) if is_en; then echo "[3/8] Role configuration"; else echo "[3/8] Role 配置"; fi ;;
    step_skills) if is_en; then echo "[4/8] Skills configuration"; else echo "[4/8] Skills 配置"; fi ;;
    step_model) if is_en; then echo "[5/8] AI model"; else echo "[5/8] AI 模型"; fi ;;
    step_domain) if is_en; then echo "[6/8] Domain configuration"; else echo "[6/8] 域名配置"; fi ;;
    step_advanced) if is_en; then echo "[7/8] Advanced options"; else echo "[7/8] 高级选项"; fi ;;
    step_write) if is_en; then echo "[8/8] Writing configuration"; else echo "[8/8] 写入配置"; fi ;;
    auth_choice) if is_en; then echo "Auth mode number"; else echo "认证方式编号"; fi ;;
    oauth_url_hint) if is_en; then echo "OAuth base URL (e.g. https://bot.example.com)"; else echo "OAuth 回调基础 URL (如 https://bot.example.com)"; fi ;;
    role_hint) if is_en; then echo "Hint: URL to JSON, e.g. {\"content\":\"You are...\",\"model\":\"gpt-4o\"}"; else echo "提示: 指向一个 JSON 文件, 格式: {\"content\": \"You are...\", \"model\": \"gpt-4o\"}"; fi ;;
    skills_hint) if is_en; then echo "Hint: Separate multiple skill URLs with commas"; else echo "提示: 多个 Skill URL 用逗号分隔"; fi ;;
    domain_hint) if is_en; then echo "Hint: Caddy can auto-issue HTTPS certs; use localhost for local testing"; else echo "提示: Caddy 会自动申请 HTTPS 证书, 本地测试用 localhost"; fi ;;
    selected_model) if is_en; then echo "Selected model:"; else echo "已选择模型:"; fi ;;
    ask_domain) if is_en; then echo "Domain"; else echo "域名"; fi ;;
    ask_image) if is_en; then echo "Docker image"; else echo "Docker 镜像"; fi ;;
    ask_rate) if is_en; then echo "Rate limit (requests/min per IP)"; else echo "速率限制 (每IP每分钟请求数)"; fi ;;
    ask_auto_update) if is_en; then echo "Auto-update SDK/CLI (true/false)"; else echo "自动更新 SDK/CLI (true/false)"; fi ;;
    ask_trust_proxy) if is_en; then echo "Trust proxy headers (true/false)"; else echo "信任反向代理头 (true/false)"; fi ;;
    ask_admin_token) if is_en; then echo "Admin API token (empty to disable)"; else echo "Admin API 令牌 (留空禁用)"; fi ;;
    ask_enable_teams) if is_en; then echo "Enable Teams channel (true/false)"; else echo "启用 Teams 通道 (true/false)"; fi ;;
    ask_enable_telegram) if is_en; then echo "Enable Telegram polling channel (true/false)"; else echo "启用 Telegram Polling 通道 (true/false)"; fi ;;
    ask_enable_discord) if is_en; then echo "Enable Discord gateway channel (true/false)"; else echo "启用 Discord Gateway 通道 (true/false)"; fi ;;
    ask_enable_whatsapp) if is_en; then echo "Enable WhatsApp webhook channel (true/false)"; else echo "启用 WhatsApp Webhook 通道 (true/false)"; fi ;;
    ask_tg_interval) if is_en; then echo "Telegram polling interval (ms)"; else echo "Telegram 轮询间隔毫秒"; fi ;;
    ask_discord_gateway_url) if is_en; then echo "Discord gateway URL"; else echo "Discord Gateway URL"; fi ;;
    ask_discord_intents) if is_en; then echo "Discord gateway intents"; else echo "Discord Gateway Intents"; fi ;;
    ask_wa_webhook_path) if is_en; then echo "WhatsApp webhook path"; else echo "WhatsApp Webhook 路径"; fi ;;
    config_saved) if is_en; then echo "Configuration saved to .env"; else echo "配置已保存到 .env"; fi ;;
    *) echo "$key" ;;
  esac
}

select_language() {
  if [ -n "${APP_LANG:-}" ]; then
    case "${APP_LANG}" in
      en|EN|english|English) LANG_CHOICE="en" ;;
      *) LANG_CHOICE="zh" ;;
    esac
    return
  fi

  echo ""
  echo "$(msg lang_prompt)"
  local lang_input
  read -rp "$(msg lang_input) " lang_input
  lang_input="${lang_input:-2}"
  if [ "$lang_input" = "1" ]; then
    LANG_CHOICE="en"
  else
    LANG_CHOICE="zh"
  fi
}

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

validate_boolean() {
  local value="$1"
  local label="$2"
  if [[ "$value" != "true" && "$value" != "false" ]]; then
    log_error "$label 必须是 true 或 false，当前值: $value"
    return 1
  fi
  return 0
}

validate_positive_integer() {
  local value="$1"
  local label="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ]; then
    log_error "$label 必须是正整数，当前值: $value"
    return 1
  fi
  return 0
}

validate_image_ref() {
  local value="$1"
  if [[ ! "$value" =~ ^([a-z0-9.-]+(:[0-9]+)?/)?[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*(:[A-Za-z0-9._-]+)?$ ]]; then
    log_error "DOCKER_IMAGE 格式无效: $value"
    log_error "示例: gtastudio/gta-claw:latest"
    return 1
  fi
  return 0
}

validate_skills_urls() {
  local raw="$1"
  IFS=',' read -r -a items <<< "$raw"
  for item in "${items[@]}"; do
    local url
    url="$(echo "$item" | xargs)"
    if [ -z "$url" ]; then
      continue
    fi
    validate_url "$url" "ENABLED_SKILLS" || return 1
  done
  return 0
}

validate_auth_mode() {
  local github_token="$1"
  local oauth_enabled="$2"
  local client_id="$3"
  local client_secret="$4"
  local auth_base_url="$5"

  if [ -n "$github_token" ]; then
    return 0
  fi

  if [ -n "$client_id" ] && [ -n "$client_secret" ] && [ -n "$auth_base_url" ] && [ "$oauth_enabled" != "false" ]; then
    validate_url "$auth_base_url" "AUTH_BASE_URL" || return 1
    return 0
  fi

  log_error "鉴权配置无效：请提供 GITHUB_TOKEN，或启用 OAuth 并配置 GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET / AUTH_BASE_URL"
  return 1
}

validate_channel_mode() {
  local enable_teams="$1"
  local enable_telegram="$2"
  local telegram_token="$3"
  local enable_discord="$4"
  local discord_token="$5"
  local enable_whatsapp="$6"
  local whatsapp_verify_token="$7"
  local whatsapp_access_token="$8"
  local whatsapp_phone_number_id="$9"

  validate_boolean "$enable_teams" "ENABLE_TEAMS" || return 1
  validate_boolean "$enable_telegram" "ENABLE_TELEGRAM" || return 1
  validate_boolean "$enable_discord" "ENABLE_DISCORD" || return 1
  validate_boolean "$enable_whatsapp" "ENABLE_WHATSAPP" || return 1

  if [ "$enable_telegram" = "true" ] && [ -z "$telegram_token" ]; then
    log_error "ENABLE_TELEGRAM=true 时必须提供 TELEGRAM_BOT_TOKEN"
    return 1
  fi

  if [ "$enable_discord" = "true" ] && [ -z "$discord_token" ]; then
    log_error "ENABLE_DISCORD=true 时必须提供 DISCORD_BOT_TOKEN"
    return 1
  fi

  if [ "$enable_whatsapp" = "true" ]; then
    if [ -z "$whatsapp_verify_token" ] || [ -z "$whatsapp_access_token" ] || [ -z "$whatsapp_phone_number_id" ]; then
      log_error "ENABLE_WHATSAPP=true 时必须提供 WHATSAPP_VERIFY_TOKEN / WHATSAPP_ACCESS_TOKEN / WHATSAPP_PHONE_NUMBER_ID"
      return 1
    fi
  fi

  return 0
}

set_env_file_permissions() {
  if command -v chmod &>/dev/null; then
    chmod 600 "$ENV_FILE" 2>/dev/null || true
  fi
}

compose() {
  if [ -f "$ENV_FILE" ]; then
    docker compose --env-file "$ENV_FILE" "$@"
  else
    docker compose "$@"
  fi
}

# ---- 从配置文件部署 ----
do_config() {
  local config_file="$1"
  if [ ! -f "$config_file" ]; then
    log_error "配置文件不存在: $config_file"
    exit 1
  fi

  log_step "正在加载配置文件: $config_file"

  # 读取配置文件到 .env (去掉注释和空行, 兼容 CRLF)
  local tmp_env
  tmp_env="$(mktemp)"
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$config_file" | tr -d '\r' | grep '=' > "$tmp_env" || true

  if [ ! -s "$tmp_env" ]; then
    rm -f "$tmp_env"
    log_error "配置文件为空或格式无效: $config_file"
    log_error "请至少包含 key=value 形式的配置项"
    exit 1
  fi

  mv "$tmp_env" "$ENV_FILE"
  set_env_file_permissions

  # 验证基础必填项
  local has_error=0
  for var in AGENT_ROLE_URL ENABLED_SKILLS; do
    if ! grep -Eq "^${var}=.+" "$ENV_FILE"; then
      log_error "缺少必填配置: $var"
      has_error=1
    fi
  done

  local enable_teams
  enable_teams="$(grep '^ENABLE_TEAMS=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'true')"
  if [ "$enable_teams" = "true" ]; then
    for var in MicrosoftAppId MicrosoftAppPassword; do
      if ! grep -Eq "^${var}=.+" "$ENV_FILE"; then
        log_error "ENABLE_TEAMS=true 时缺少必填配置: $var"
        has_error=1
      fi
    done
  fi

  if [ "$has_error" -ne 0 ]; then
    log_error "请检查配置文件并补充必填项"
    rm -f "$ENV_FILE"
    exit 1
  fi

  validate_image_ref "$(grep '^DOCKER_IMAGE=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'gtastudio/gta-claw:latest')"
  validate_positive_integer "$(grep '^RATE_LIMIT_PER_MIN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo '30')" "RATE_LIMIT_PER_MIN"
  validate_boolean "$(grep '^AUTO_UPDATE=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" "AUTO_UPDATE"
  validate_boolean "$(grep '^TRUST_PROXY=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" "TRUST_PROXY"
  validate_boolean "$(grep '^OAUTH_ENABLED=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" "OAUTH_ENABLED"
  validate_url "$(grep '^AGENT_ROLE_URL=' "$ENV_FILE" | cut -d'=' -f2-)" "AGENT_ROLE_URL"
  validate_skills_urls "$(grep '^ENABLED_SKILLS=' "$ENV_FILE" | cut -d'=' -f2-)"
  validate_auth_mode \
    "$(grep '^GITHUB_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^OAUTH_ENABLED=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || true)" \
    "$(grep '^GITHUB_CLIENT_ID=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^GITHUB_CLIENT_SECRET=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^AUTH_BASE_URL=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)"
  validate_channel_mode \
    "$(grep '^ENABLE_TEAMS=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'true')" \
    "$(grep '^ENABLE_TELEGRAM=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" \
    "$(grep '^TELEGRAM_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^ENABLE_DISCORD=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" \
    "$(grep '^DISCORD_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^ENABLE_WHATSAPP=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo 'false')" \
    "$(grep '^WHATSAPP_VERIFY_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^WHATSAPP_ACCESS_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)" \
    "$(grep '^WHATSAPP_PHONE_NUMBER_ID=' "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)"

  log_info "配置文件验证通过"
  do_deploy
}

# ---- 交互式部署 ----
do_interactive() {
  select_language

  echo ""
  echo -e "${BOLD}$(msg banner_top)${NC}"
  echo -e "${BOLD}$(msg banner_mid)${NC}"
  echo -e "${BOLD}$(msg banner_bot)${NC}"
  echo ""

  # 如果已存在 .env，询问是否覆盖
  if [ -f "$ENV_FILE" ]; then
    echo -e "  ${YELLOW}$(msg existing_env)${NC}"
    local overwrite
    read -rp "  $(msg reconfigure) " overwrite
    if [[ ! "$overwrite" =~ ^[yY] ]]; then
      log_info "$(msg use_existing)"
      do_deploy
      return
    fi
  fi

  log_step "$(msg step_auth)"
  echo "  1) Personal Access Token"
  echo "  2) OAuth 网页授权 (企业推荐)"
  local auth_mode
  auth_mode=$(prompt_optional "$(msg auth_choice)" "2")

  local github_token=""
  local oauth_enabled="false"
  local github_client_id=""
  local github_client_secret=""
  local auth_base_url=""
  local oauth_callback_path="/auth/callback"
  local oauth_scope="copilot"

  if [ "$auth_mode" = "1" ]; then
    github_token=$(prompt_secret "GITHUB_TOKEN" "GitHub PAT (需要 Copilot Requests 权限)")
  else
    oauth_enabled="true"
    github_client_id=$(prompt_required "GITHUB_CLIENT_ID" "GitHub OAuth Client ID")
    github_client_secret=$(prompt_secret "GITHUB_CLIENT_SECRET" "GitHub OAuth Client Secret")
    auth_base_url=$(prompt_required "AUTH_BASE_URL" "$(msg oauth_url_hint)")
    validate_url "$auth_base_url" "AUTH_BASE_URL"
  fi

  log_step "$(msg step_bot)"
  local app_id app_password
  app_id=$(prompt_required "MicrosoftAppId" "Microsoft App ID")
  app_password=$(prompt_secret "MicrosoftAppPassword" "Microsoft App Password")

  log_step "$(msg step_role)"
  echo -e "  ${CYAN}$(msg role_hint)${NC}"
  local role_url
  role_url=$(prompt_required "AGENT_ROLE_URL" "Role 配置 URL")
  validate_url "$role_url" "AGENT_ROLE_URL"

  log_step "$(msg step_skills)"
  echo -e "  ${CYAN}$(msg skills_hint)${NC}"
  local skills_urls
  skills_urls=$(prompt_required "ENABLED_SKILLS" "Skill URLs")
  validate_skills_urls "$skills_urls"

  log_step "$(msg step_model)"
  local model
  model=$(select_model)
  log_info "$(msg selected_model) $model"

  log_step "$(msg step_domain)"
  echo -e "  ${CYAN}$(msg domain_hint)${NC}"
  local domain
  domain=$(prompt_optional "$(msg ask_domain)" "localhost")

  log_step "$(msg step_advanced)"
  local docker_image rate_limit admin_token auto_update trust_proxy
  docker_image=$(prompt_optional "$(msg ask_image)" "gtastudio/gta-claw:latest")
  rate_limit=$(prompt_optional "$(msg ask_rate)" "30")
  auto_update=$(prompt_optional "$(msg ask_auto_update)" "false")
  trust_proxy=$(prompt_optional "$(msg ask_trust_proxy)" "false")
  admin_token=$(prompt_optional "$(msg ask_admin_token)" "")

  validate_image_ref "$docker_image"
  validate_positive_integer "$rate_limit" "RATE_LIMIT_PER_MIN"
  validate_boolean "$auto_update" "AUTO_UPDATE"
  validate_boolean "$trust_proxy" "TRUST_PROXY"
  validate_auth_mode "$github_token" "$oauth_enabled" "$github_client_id" "$github_client_secret" "$auth_base_url"

  local enable_teams enable_telegram enable_discord enable_whatsapp
  local telegram_bot_token telegram_poll_interval_ms discord_bot_token discord_gateway_url discord_gateway_intents
  local whatsapp_verify_token whatsapp_access_token whatsapp_phone_number_id whatsapp_webhook_path

  enable_teams=$(prompt_optional "$(msg ask_enable_teams)" "true")
  enable_telegram=$(prompt_optional "$(msg ask_enable_telegram)" "false")
  enable_discord=$(prompt_optional "$(msg ask_enable_discord)" "false")
  enable_whatsapp=$(prompt_optional "$(msg ask_enable_whatsapp)" "false")

  telegram_bot_token=""
  telegram_poll_interval_ms="2000"
  if [ "$enable_telegram" = "true" ]; then
    telegram_bot_token=$(prompt_secret "TELEGRAM_BOT_TOKEN" "Telegram Bot Token")
    telegram_poll_interval_ms=$(prompt_optional "$(msg ask_tg_interval)" "2000")
    validate_positive_integer "$telegram_poll_interval_ms" "TELEGRAM_POLL_INTERVAL_MS"
  fi

  discord_bot_token=""
  discord_gateway_url="wss://gateway.discord.gg/?v=10&encoding=json"
  discord_gateway_intents="33281"
  if [ "$enable_discord" = "true" ]; then
    discord_bot_token=$(prompt_secret "DISCORD_BOT_TOKEN" "Discord Bot Token")
    discord_gateway_url=$(prompt_optional "$(msg ask_discord_gateway_url)" "$discord_gateway_url")
    discord_gateway_intents=$(prompt_optional "$(msg ask_discord_intents)" "$discord_gateway_intents")
    validate_positive_integer "$discord_gateway_intents" "DISCORD_GATEWAY_INTENTS"
  fi

  whatsapp_verify_token=""
  whatsapp_access_token=""
  whatsapp_phone_number_id=""
  whatsapp_webhook_path="/whatsapp/webhook"
  if [ "$enable_whatsapp" = "true" ]; then
    whatsapp_verify_token=$(prompt_secret "WHATSAPP_VERIFY_TOKEN" "WhatsApp Verify Token")
    whatsapp_access_token=$(prompt_secret "WHATSAPP_ACCESS_TOKEN" "WhatsApp Access Token")
    whatsapp_phone_number_id=$(prompt_required "WHATSAPP_PHONE_NUMBER_ID" "WhatsApp Phone Number ID")
    whatsapp_webhook_path=$(prompt_optional "$(msg ask_wa_webhook_path)" "$whatsapp_webhook_path")
  fi

  validate_channel_mode \
    "$enable_teams" \
    "$enable_telegram" \
    "$telegram_bot_token" \
    "$enable_discord" \
    "$discord_bot_token" \
    "$enable_whatsapp" \
    "$whatsapp_verify_token" \
    "$whatsapp_access_token" \
    "$whatsapp_phone_number_id"

  log_step "$(msg step_write)"

  # 写入 .env
  cat > "$ENV_FILE" <<EOF
# GTA-Claw 配置 (由 run.sh 自动生成)
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

DOCKER_IMAGE=${docker_image}
GITHUB_TOKEN=${github_token}
OAUTH_ENABLED=${oauth_enabled}
GITHUB_CLIENT_ID=${github_client_id}
GITHUB_CLIENT_SECRET=${github_client_secret}
AUTH_BASE_URL=${auth_base_url}
OAUTH_CALLBACK_PATH=${oauth_callback_path}
OAUTH_SCOPE=${oauth_scope}
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
ENABLE_TEAMS=${enable_teams}
ENABLE_TELEGRAM=${enable_telegram}
TELEGRAM_BOT_TOKEN=${telegram_bot_token}
TELEGRAM_POLL_INTERVAL_MS=${telegram_poll_interval_ms}
ENABLE_DISCORD=${enable_discord}
DISCORD_BOT_TOKEN=${discord_bot_token}
DISCORD_GATEWAY_URL=${discord_gateway_url}
DISCORD_GATEWAY_INTENTS=${discord_gateway_intents}
ENABLE_WHATSAPP=${enable_whatsapp}
WHATSAPP_VERIFY_TOKEN=${whatsapp_verify_token}
WHATSAPP_ACCESS_TOKEN=${whatsapp_access_token}
WHATSAPP_PHONE_NUMBER_ID=${whatsapp_phone_number_id}
WHATSAPP_WEBHOOK_PATH=${whatsapp_webhook_path}
EOF

  set_env_file_permissions

  log_info "$(msg config_saved)"
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
  compose up -d --remove-orphans

  echo ""
  log_info "部署完成！"
  echo ""

  # 等待健康检查
  log_step "等待服务就绪..."
  local container_id
  container_id="$(compose ps -q gta-claw 2>/dev/null || true)"
  local retries=0
  while [ "$retries" -lt 30 ]; do
    if [ -n "$container_id" ]; then
      local health
      health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
      if [ "$health" = "healthy" ] || [ "$health" = "running" ]; then
        break
      fi
    fi
    sleep 2
    retries=$((retries + 1))
  done

  echo ""
  compose ps
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
  compose up -d --remove-orphans
  log_info "更新完成"
  compose ps
}

# ---- 停止 ----
do_stop() {
  log_step "停止所有 GTA-Claw 服务..."
  compose down
  log_info "所有服务已停止"
}

# ---- 状态 ----
do_status() {
  log_step "服务状态:"
  compose ps

  echo ""
  # 尝试获取健康检查
  if curl -sf "http://localhost:3978/health" &>/dev/null 2>&1; then
    log_info "健康检查:"
    curl -s "http://localhost:3978/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || \
      curl -s "http://localhost:3978/health" 2>/dev/null || true
  elif compose exec -T gta-claw curl -sf "http://localhost:3978/health" &>/dev/null 2>&1; then
    log_info "健康检查 (容器内):"
    compose exec -T gta-claw curl -s "http://localhost:3978/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || true
  fi
}

# ---- 日志 ----
do_logs() {
  compose logs -f --tail=100
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
case "${1:-}" in
  --config|-c)
    check_prerequisites
    if [ -z "${2:-}" ]; then
      log_error "用法: ./run.sh --config <配置文件路径>"
      log_error "示例: ./run.sh --config conf/gta-claw.conf"
      exit 1
    fi
    do_config "$2"
    ;;
  --update|-u)
    check_prerequisites
    do_update
    ;;
  --stop|-s)
    check_prerequisites
    do_stop
    ;;
  --status)
    check_prerequisites
    do_status
    ;;
  --logs|-l)
    check_prerequisites
    do_logs
    ;;
  --help|-h)
    do_help
    ;;
  *)
    check_prerequisites
    do_interactive
    ;;
esac
