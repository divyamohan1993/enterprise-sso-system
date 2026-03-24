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
FROM rust:1.88-slim AS builder

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

# Build all service binaries in release mode.
# Building them all together maximises shared dependency caching.
RUN cargo build --release \
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
FROM debian:bookworm-slim AS runtime

ARG SERVICE_NAME=admin

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
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
    CMD curl -f http://localhost:${PORT:-8080}/health 2>/dev/null \
    || curl -f http://localhost:${PORT:-8080}/api/health 2>/dev/null \
    || kill -0 1

# Run as non-root
USER milnet

ENTRYPOINT ["/usr/local/bin/service"]
