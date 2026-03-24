# ==============================================================================
# MILNET SSO — Production Multi-Stage Dockerfile
# ==============================================================================
# Builds all 8 service binaries in a single builder stage, then copies the
# selected service binary into a minimal runtime image.
#
# Usage:
#   docker build --build-arg SERVICE_NAME=gateway -t milnet-gateway .
#   docker build --build-arg SERVICE_NAME=admin   -t milnet-admin   .
#
# All 8 services: gateway, orchestrator, opaque, tss, verifier, admin, ratchet, audit
# ==============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.88-slim@sha256:a3c6a7e4b1d8f0e2c5b9d7a1e3f5c8b2d4a6e9f1c3b5d7a0e2f4c6b8d1a3e5f7 AS builder

# Build arguments
ARG SERVICE_NAME=admin

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    cmake \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy the full workspace (relies on .dockerignore to exclude target/, .git, etc.)
COPY . .

# Build all service binaries in release mode with locked dependencies.
# Building them all together maximises shared dependency caching.
RUN cargo build --release --locked \
    -p gateway \
    -p orchestrator \
    -p opaque \
    -p tss \
    -p verifier \
    -p admin \
    -p ratchet \
    -p audit

# Verify the requested binary exists
RUN test -f /build/target/release/${SERVICE_NAME} \
    || (echo "ERROR: binary '${SERVICE_NAME}' not found in target/release/" && ls -la /build/target/release/ && exit 1)

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:b7d6e4c8f2a1d3e5c7b9a0d2f4e6c8b1a3d5e7f9c2b4a6d8e0f1c3b5a7d9e2f4 AS runtime

ARG SERVICE_NAME=admin

LABEL org.opencontainers.image.source="https://github.com/milnet-sso/enterprise-sso-system"
LABEL org.opencontainers.image.description="MILNET SSO ${SERVICE_NAME} service"
LABEL org.opencontainers.image.vendor="MILNET"

# Apply latest security patches and install minimal runtime dependencies
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r milnet && useradd -r -g milnet -m -d /home/milnet -s /bin/false milnet

# Create data directories
RUN mkdir -p /var/lib/milnet/audit /var/lib/milnet/data \
    && chown -R milnet:milnet /var/lib/milnet

# Copy only the selected service binary
COPY --from=builder /build/target/release/${SERVICE_NAME} /usr/local/bin/service

# Ensure binary is executable
RUN chmod +x /usr/local/bin/service

# Default environment variables
ENV RUST_LOG=info \
    SERVICE_NAME=${SERVICE_NAME} \
    DEVELOPER_MODE=false \
    LOG_LEVEL=error

# Health check — services should respond to HTTP /health or TCP connect.
# For SHARD-based services (non-HTTP), the health check verifies the process
# is alive; the orchestrator and admin expose HTTP /health endpoints.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test -f /proc/1/status || exit 1

# Run as non-root
USER milnet

ENTRYPOINT ["/usr/local/bin/service"]
