# ---- Build Stage ----
FROM node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  git \
  python3 \
  python-is-python3 \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV npm_config_python=/usr/bin/python3

WORKDIR /app

COPY package.json package-lock.json ./
RUN node -v && npm -v && \
  npm ci --ignore-scripts --no-audit --no-fund && \
  npm rebuild --foreground-scripts isolated-vm@7.0.0 koffi@3.1.2

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build 2>&1 || \
  (echo "=== tsc build failed ===" && \
   ./node_modules/.bin/tsc --noEmit --pretty 2>&1 || true && \
   exit 1)
RUN npm prune --omit=dev --ignore-scripts

# ---- Production Stage ----
FROM node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json /app/package-lock.json ./

ENV NODE_OPTIONS="--no-node-snapshot"
ENV NODE_ENV="production"
ENV COPILOT_CLI_PATH="/app/node_modules/.bin/copilot"

# Run as non-root
USER node

EXPOSE 3978

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://localhost:3978/health').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"]

CMD ["node", "dist/index.js"]
