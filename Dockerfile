# syntax=docker/dockerfile:1

FROM rust:1.97.0-bookworm AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps ./apps
COPY crates ./crates
COPY compat ./compat

RUN cargo build --locked --release --bin gta-claw-daemon

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system gta-claw \
    && useradd --system --gid gta-claw --home-dir /nonexistent --shell /usr/sbin/nologin gta-claw

COPY --from=builder /workspace/target/release/gta-claw-daemon /usr/local/bin/gta-claw-daemon

ENV GTA_CLAW_BIND="0.0.0.0:3978"

USER gta-claw

EXPOSE 3978

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD ["/usr/local/bin/gta-claw-daemon", "--probe-http"]

ENTRYPOINT ["/usr/local/bin/gta-claw-daemon"]
