# syntax=docker/dockerfile:1
# ── MILNET SSO System — Multi-stage reproducible build ───────────────────────
# Produces a minimal, distroless runtime image with no shell, non-root user,
# and read-only filesystem compatibility.

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

ARG SERVICE_NAME=gateway
ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-D warnings -C target-feature=+crt-static -C link-arg=-Wl,-z,relro,-z,now -C link-arg=-Wl,-z,noexecstack"

WORKDIR /build

# Cache dependency builds: copy manifests first, then build deps
COPY Cargo.toml Cargo.lock ./
COPY common/Cargo.toml common/Cargo.toml
COPY crypto/Cargo.toml crypto/Cargo.toml
COPY shard/Cargo.toml shard/Cargo.toml
COPY gateway/Cargo.toml gateway/Cargo.toml
COPY orchestrator/Cargo.toml orchestrator/Cargo.toml
COPY tss/Cargo.toml tss/Cargo.toml
COPY verifier/Cargo.toml verifier/Cargo.toml
COPY opaque/Cargo.toml opaque/Cargo.toml
COPY ratchet/Cargo.toml ratchet/Cargo.toml
COPY kt/Cargo.toml kt/Cargo.toml
COPY risk/Cargo.toml risk/Cargo.toml
COPY audit/Cargo.toml audit/Cargo.toml
COPY admin/Cargo.toml admin/Cargo.toml
COPY sso-protocol/Cargo.toml sso-protocol/Cargo.toml
COPY fido/Cargo.toml fido/Cargo.toml
COPY e2e/Cargo.toml e2e/Cargo.toml

# Create stub lib.rs for each crate so cargo can resolve the workspace
RUN for dir in common crypto shard gateway orchestrator tss verifier opaque ratchet kt risk audit admin sso-protocol fido e2e; do \
      mkdir -p "$dir/src" && echo '' > "$dir/src/lib.rs"; \
    done

# Pre-build dependencies (cached layer)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy full source and build for real
COPY . .
RUN cargo build --release --bin "${SERVICE_NAME}" \
    && cp "target/release/${SERVICE_NAME}" /build/service-binary \
    && strip /build/service-binary

# ── Stage 2: Runtime (distroless — no shell, no package manager) ─────────────
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="milnet-sso" \
      org.opencontainers.image.description="MILNET SSO System service" \
      org.opencontainers.image.vendor="MILNET" \
      org.opencontainers.image.source="https://github.com/milnet/enterprise-sso-system" \
      org.opencontainers.image.licenses="MIT" \
      io.artifacthub.package.readme-url="https://github.com/milnet/enterprise-sso-system#readme"

# Run as nonroot (UID 65534) — distroless/static:nonroot sets this by default
USER 65534:65534

COPY --from=builder --chown=65534:65534 /build/service-binary /service

# Read-only filesystem: no temp dirs needed, all state is external
# Expose the default service port (overridable via env)
EXPOSE 9100

# Healthcheck — the binary must expose /healthz or a TCP listener.
# Using a TCP check since distroless has no shell or curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/service", "--healthcheck"]

ENTRYPOINT ["/service"]
