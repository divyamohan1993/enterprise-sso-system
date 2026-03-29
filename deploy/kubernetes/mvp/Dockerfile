# MILNET SSO — MVP Dockerfile (simpler than production)
# Uses debian-slim runtime instead of distroless to avoid static linking issues.

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

ARG SERVICE_NAME=gateway
ENV CARGO_TERM_COLOR=always

WORKDIR /build

# Copy full source (skip dependency caching for MVP simplicity)
COPY . .

# Build the target service
RUN cargo build --release --bin "${SERVICE_NAME}" \
    && cp "target/release/${SERVICE_NAME}" /build/service-binary \
    && strip /build/service-binary

# ── Stage 2: Runtime ─────────────────��─────────────────────────────────��─────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# UID 65534 = nobody (already exists on Debian)
USER nobody:nogroup

COPY --from=builder --chown=65534:65534 /build/service-binary /service

EXPOSE 9100

ENTRYPOINT ["/service"]
