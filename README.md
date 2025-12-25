# 🔐 Enterprise SSO System

[![Build Status](https://github.com/YOUR_USERNAME/enterprise-sso/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/YOUR_USERNAME/enterprise-sso/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

**Quantum-Safe • Blockchain-Backed • Zero-Trust**

A production-ready, enterprise-grade Single Sign-On system featuring quantum-resistant cryptography, blockchain-based audit trails, and comprehensive security features.

---

## ✨ Features

- � **Quantum-Safe Cryptography** - ML-DSA-65 (Dilithium) signatures
- ⛓️ **Blockchain Audit Trail** - Immutable, cryptographically signed logs
- 🔑 **OAuth 2.0 / OIDC** - Full compliance with PKCE support
- 📱 **MFA Support** - TOTP with QR codes and backup codes
- 🛡️ **Enterprise Security** - Argon2id hashing, rate limiting, account lockout
- 🔄 **Key Rotation** - Graceful secret rotation without service disruption
- 📊 **Health Checks** - Kubernetes-ready liveness, readiness, startup probes

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/enterprise-sso.git
cd enterprise-sso

# Run automatic setup (installs deps, generates keys, builds)
npm run setup

# Start development server
npm run start:dev
```

The setup script automatically generates all cryptographic secrets - no manual configuration needed!

---

## � Project Structure

```
enterprise-sso/
├── src/                    # Source code
│   ├── auth/               # Authentication module (JWT, MFA, OAuth)
│   ├── blockchain/         # Blockchain audit trail
│   ├── common/             # Shared DTOs, filters, middleware
│   ├── health/             # Health check endpoints
│   ├── oauth/              # OIDC controller
│   └── users/              # User management
├── scripts/                # Automation scripts
│   ├── autoconfig.js       # Key generation (Node.js)
│   ├── autoconfig.sh       # Key generation (Bash)
│   └── deploy_k8s.sh       # Kubernetes deployment
├── k8s/                    # Kubernetes manifests
├── docs/                   # Documentation
│   ├── ENTERPRISE_READINESS_REPORT.md
│   ├── INTEGRATION.md
│   └── production_readiness_rubric.md
├── .github/                # GitHub templates & workflows
├── Dockerfile              # Multi-stage production build
├── docker-compose.yml      # Local development
└── README.md
```

---

## ⚙️ Configuration

### Automatic Key Generation

```bash
# First-time setup or check config
npm run autoconfig

# Regenerate all secrets
npm run autoconfig:force

# Rotate keys (preserves old for graceful transition)
npm run autoconfig:rotate
```

### Generated Secrets

| Secret | Description |
|--------|-------------|
| `JWT_SECRET` | 96-byte token signing key |
| `COOKIE_SECRET` | 64-byte cookie signing key |
| `DB_PASS` | Database password |
| `OAUTH_CLIENT_SECRET` | OAuth client credentials |
| `ADMIN_INITIAL_PASSWORD` | Initial admin password |
| `ENCRYPTION_KEY` | 256-bit data encryption key |

---

## 📦 NPM Scripts

| Script | Description |
|--------|-------------|
| `npm run setup` | Complete first-time setup |
| `npm run start:dev` | Start development server |
| `npm run build` | Build for production |
| `npm run test` | Run unit tests |
| `npm run test:cov` | Run tests with coverage |
| `npm run autoconfig:rotate` | Rotate all secrets |
| `npm run lint` | Lint and fix code |

---

## 🔒 API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | POST | User authentication |
| `/auth/logout` | POST | Logout and revoke tokens |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/mfa/setup` | POST | Initialize MFA setup |
| `/auth/mfa/verify` | POST | Verify MFA token |

### OAuth 2.0 / OIDC

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/oauth/authorize` | GET | Authorization endpoint |
| `/oauth/token` | POST | Token exchange |
| `/oauth/jwks` | GET | JSON Web Key Set |

### Health Checks

| Endpoint | Description |
|----------|-------------|
| `/health` | Liveness probe |
| `/health/ready` | Readiness probe |
| `/health/startup` | Startup probe |

---

## 🐳 Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f sso-system
```

---

## ☸️ Kubernetes

```bash
# Deploy
kubectl apply -f k8s/

# Check status
kubectl get pods -n sso-enterprise
```

---

## 🛡️ Security

- **No placeholder secrets** - All keys auto-generated cryptographically
- **Key rotation** - Zero-downtime secret rotation
- **Quantum-safe** - Future-proof cryptography
- **Audit trail** - Blockchain-backed immutable logs

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

---

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## 📄 License

[MIT](./LICENSE) © 2024 Enterprise SSO System Contributors
