# Build stage
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev cmake gcc g++ && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p admin -p gateway -p orchestrator -p tss -p verifier -p audit -p ratchet -p kt -p risk -p opaque

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/admin /usr/local/bin/admin
COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /app/target/release/orchestrator /usr/local/bin/orchestrator
COPY --from=builder /app/target/release/tss /usr/local/bin/tss
COPY --from=builder /app/target/release/verifier /usr/local/bin/verifier
COPY --from=builder /app/target/release/audit /usr/local/bin/audit
COPY --from=builder /app/target/release/ratchet /usr/local/bin/ratchet
COPY --from=builder /app/target/release/kt /usr/local/bin/kt
COPY --from=builder /app/target/release/risk /usr/local/bin/risk
COPY --from=builder /app/target/release/opaque /usr/local/bin/opaque
# Frontend served via reverse proxy or static file server
COPY --from=builder /app/frontend/ /usr/local/share/frontend/

# Run as non-root user
RUN groupadd -r milnet && useradd -r -g milnet -s /bin/false milnet
RUN chown -R milnet:milnet /usr/local/share/frontend/

EXPOSE 8080
ENV ADMIN_PORT=8080
USER milnet
CMD ["admin"]
