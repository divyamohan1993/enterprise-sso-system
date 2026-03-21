# Build stage
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev cmake gcc g++ && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p admin -p gateway

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/admin /usr/local/bin/admin
COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /app/frontend/ /usr/local/share/frontend/

EXPOSE 8080
ENV ADMIN_PORT=8080
CMD ["admin"]
