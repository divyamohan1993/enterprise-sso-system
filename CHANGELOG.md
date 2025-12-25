# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-18

### Added

#### Security
- Quantum-safe digital signatures using ML-DSA-65 (Dilithium)
- Blockchain-backed immutable audit trail
- Argon2id password hashing (OWASP recommended)
- Multi-Factor Authentication with TOTP and backup codes
- Rate limiting for DDoS protection
- Account lockout after failed login attempts
- Security headers via Helmet.js

#### Authentication
- OAuth 2.0 / OIDC compliance with PKCE support
- JWT authentication with ECDSA (ES256) signing
- Refresh token rotation
- Automatic key rotation with graceful transition

#### Configuration
- Automatic key generation script (`npm run autoconfig`)
- Key rotation support (`npm run autoconfig:rotate`)
- Zero placeholder secrets - all cryptographically random
- Environment validation with Joi

#### Infrastructure
- Multi-stage Dockerfile with non-root user
- Kubernetes manifests (StatefulSet, Ingress, Secrets)
- GitHub Actions CI/CD pipeline with Trivy security scanning
- Docker Compose for local development

#### Quality
- 44 unit tests with mocked dependencies
- Strict TypeScript mode enabled
- Global exception filter with correlation IDs
- Health check endpoints (liveness, readiness, startup)

### Security Advisories

- Always use HTTPS in production
- Rotate keys regularly with `npm run autoconfig:rotate`
- Change ADMIN_INITIAL_PASSWORD after first login
- Never commit `.env` files to version control

## [Unreleased]

### Planned
- Redis session storage integration
- MySQL/PostgreSQL database persistence
- Prometheus metrics export
- OpenTelemetry distributed tracing
- WebAuthn support for passwordless authentication
