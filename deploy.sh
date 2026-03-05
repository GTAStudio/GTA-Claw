#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GTA-Claw Deployment Script
# Usage:
#   ./deploy.sh                     # Interactive mode
#   ./deploy.sh --config .env.prod  # Config file mode
#   ./deploy.sh --update            # Update SDK/CLI in running container
#   ./deploy.sh --stop              # Stop all services
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

ENV_FILE=".env"

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

# ---- Available models for selection ----
MODELS=(
  "gpt-4o             (Default, balanced)"
  "claude-opus-4.6    (Reasoning, 3x multiplier)"
  "gpt-5.3-codex      (Coding, 1x multiplier)"
  "gpt-5.2-codex      (Coding, 1x multiplier)"
  "gpt-5.1-codex-max  (Coding, 1x multiplier)"
  "claude-sonnet-4.6  (Balanced, 1x multiplier)"
  "gpt-5.2            (Reasoning, 1x multiplier)"
  "gemini-3.1-pro     (Reasoning, 1x multiplier)"
  "claude-haiku-4.5   (Fast/Cheap, 0.33x)"
  "gpt-5-mini         (Free, 0x multiplier)"
  "gpt-5.1-codex-mini (Fast, 0.33x multiplier)"
)

prompt_required() {
  local var_name="$1"
  local prompt_text="$2"
  local value=""
  while [ -z "$value" ]; do
    read -rp "$prompt_text: " value
    if [ -z "$value" ]; then
      log_error "$var_name is required."
    fi
  done
  echo "$value"
}

prompt_optional() {
  local prompt_text="$1"
  local default="$2"
  local value
  read -rp "$prompt_text [$default]: " value
  echo "${value:-$default}"
}

select_model() {
  echo ""
  log_step "Select AI model for this role:"
  for i in "${!MODELS[@]}"; do
    echo "  $((i+1)). ${MODELS[$i]}"
  done
  echo ""
  local choice
  read -rp "Enter number [1]: " choice
  choice="${choice:-1}"

  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#MODELS[@]}" ]; then
    # Extract model name (first word)
    echo "${MODELS[$((choice-1))]}" | awk '{print $1}'
  else
    echo "gpt-4o"
  fi
}

validate_url() {
  local url="$1"
  local label="$2"
  if [[ ! "$url" =~ ^https?:// ]]; then
    log_error "Invalid URL for $label: $url"
    return 1
  fi
  return 0
}

# ---- Mode: Update SDK/CLI ----
do_update() {
  log_step "Updating SDK/CLI in running container..."
  local container
  container=$(docker compose ps -q gta-claw 2>/dev/null || true)
  if [ -z "$container" ]; then
    log_error "No running gta-claw container found."
    exit 1
  fi

  log_info "Updating @github/copilot-sdk..."
  docker exec "$container" npm update @github/copilot-sdk || log_warn "SDK update failed"

  log_info "Updating Copilot CLI..."
  docker exec "$container" bash -c 'curl -fsSL https://gh.io/copilot-install | PREFIX=/usr/local bash' || log_warn "CLI update failed"

  log_info "Restarting container to apply updates..."
  docker compose restart gta-claw

  log_info "Update complete."
}

# ---- Mode: Stop ----
do_stop() {
  log_step "Stopping all GTA-Claw services..."
  docker compose down
  log_info "All services stopped."
}

# ---- Mode: Config file ----
do_config() {
  local config_file="$1"
  if [ ! -f "$config_file" ]; then
    log_error "Config file not found: $config_file"
    exit 1
  fi

  log_step "Loading configuration from $config_file"
  cp "$config_file" "$ENV_FILE"

  # Validate required vars
  for var in GITHUB_TOKEN MicrosoftAppId MicrosoftAppPassword AGENT_ROLE_URL ENABLED_SKILLS; do
    if ! grep -q "^${var}=.\+" "$ENV_FILE"; then
      log_error "Missing required variable: $var in $config_file"
      exit 1
    fi
  done

  log_info "Configuration validated."
  do_deploy
}

# ---- Mode: Interactive ----
do_interactive() {
  echo ""
  echo "============================================"
  echo "   GTA-Claw — Interactive Deployment Setup"
  echo "============================================"
  echo ""

  log_step "1/7 — GitHub Token"
  local github_token
  github_token=$(prompt_required "GITHUB_TOKEN" "GitHub PAT (Copilot Requests permission)")

  log_step "2/7 — Azure Bot Credentials"
  local app_id app_password
  app_id=$(prompt_required "MicrosoftAppId" "Microsoft App ID")
  app_password=$(prompt_required "MicrosoftAppPassword" "Microsoft App Password")

  log_step "3/7 — Role Configuration"
  local role_url
  role_url=$(prompt_required "AGENT_ROLE_URL" "Role config URL (JSON with content + model)")
  validate_url "$role_url" "AGENT_ROLE_URL"

  log_step "4/7 — Skills Configuration"
  local skills_urls
  skills_urls=$(prompt_required "ENABLED_SKILLS" "Skill URLs (comma-separated)")

  log_step "5/7 — AI Model Selection"
  local model
  model=$(select_model)
  log_info "Selected model: $model"

  log_step "6/7 — Domain Configuration"
  local domain
  domain=$(prompt_optional "Domain for HTTPS (Caddy)" "localhost")

  log_step "7/7 — Optional Settings"
  local auto_update admin_token trust_proxy rate_limit
  auto_update=$(prompt_optional "Auto-update SDK/CLI on startup" "false")
  trust_proxy=$(prompt_optional "Trust x-forwarded-for from upstream proxy" "false")
  rate_limit=$(prompt_optional "Rate limit (requests/min per IP for /api/messages)" "30")
  admin_token=$(prompt_optional "Admin API token (empty to disable)" "")

  # Write .env file
  cat > "$ENV_FILE" <<EOF
GITHUB_TOKEN=${github_token}
MicrosoftAppId=${app_id}
MicrosoftAppPassword=${app_password}
AGENT_ROLE_URL=${role_url}
ENABLED_SKILLS=${skills_urls}
COPILOT_MODEL=${model}
DOMAIN=${domain}
AUTO_UPDATE=${auto_update}
ADMIN_TOKEN=${admin_token}
LOG_LEVEL=info
MAX_SESSIONS=100
SESSION_TTL_MS=3600000
SKILL_EXEC_TIMEOUT_MS=30000
SDK_REQUEST_TIMEOUT_MS=120000
RATE_LIMIT_PER_MIN=${rate_limit}
TRUST_PROXY=${trust_proxy}
EOF

  log_info "Configuration written to $ENV_FILE"
  do_deploy
}

# ---- Deploy ----
do_deploy() {
  log_step "Building and starting GTA-Claw..."
  docker compose up -d --build

  echo ""
  log_info "Deployment complete!"
  log_info "Services:"
  docker compose ps
  echo ""

  local domain
  domain=$(grep "^DOMAIN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "localhost")
  log_info "Health check: https://${domain}/health"
  log_info "Bot endpoint: https://${domain}/api/messages"
  echo ""
  log_info "Logs: docker compose logs -f gta-claw"
}

# ---- Main ----
case "${1:-}" in
  --config)
    if [ -z "${2:-}" ]; then
      log_error "Usage: deploy.sh --config <env-file>"
      exit 1
    fi
    do_config "$2"
    ;;
  --update)
    do_update
    ;;
  --stop)
    do_stop
    ;;
  --help|-h)
    echo "Usage:"
    echo "  ./deploy.sh                     Interactive deployment"
    echo "  ./deploy.sh --config <file>     Deploy from config file"
    echo "  ./deploy.sh --update            Update SDK/CLI in running container"
    echo "  ./deploy.sh --stop              Stop all services"
    ;;
  *)
    do_interactive
    ;;
esac
