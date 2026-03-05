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
RUN node -v && npm -v && \
  npm install --no-audit --no-fund --unsafe-perm --loglevel=verbose || \
  (echo "=== npm install failed, dumping npm logs ===" && \
   ls -la /root/.npm/_logs || true && \
   cat /root/.npm/_logs/* || true && \
   exit 1)

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build 2>&1 || \
  (echo "=== tsc build failed ===" && \
   npx tsc --noEmit --pretty 2>&1 || true && \
   exit 1)
RUN npm prune --omit=dev

# ---- Production Stage ----
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  curl \
  bash \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install Copilot CLI via official install script
ARG COPILOT_CLI_VERSION=""
RUN if [ -n "$COPILOT_CLI_VERSION" ]; then \
      VERSION="$COPILOT_CLI_VERSION" curl -fsSL https://gh.io/copilot-install | PREFIX=/usr/local bash; \
    else \
      curl -fsSL https://gh.io/copilot-install | PREFIX=/usr/local bash; \
    fi

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Required for isolated-vm on Node 20+
ENV NODE_OPTIONS="--no-node-snapshot"
ENV COPILOT_CLI_PATH="/usr/local/bin/copilot"

# Run as non-root
USER node

EXPOSE 3978

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -f http://localhost:3978/health || exit 1

CMD ["node", "dist/index.js"]
