# Runbooks Index

Operational runbooks for the MILNET SSO system. All paths are relative to the repository root.

## Available Runbooks

| Runbook | Path | Description |
|---------|------|-------------|
| Key Ceremony | [docs/runbooks/KEY-CEREMONY-RUNBOOK.md](KEY-CEREMONY-RUNBOOK.md) | Multi-person FROST 3-of-5 key generation ceremony procedure, including pre-ceremony preparation, DKG steps, custodian responsibilities, witness attestation form, emergency recovery, and annual rotation |
| Replication Guide | [docs/REPLICATION.md](../REPLICATION.md) | Complete deployment replication from scratch on GCP, including VM provisioning, service build, and inter-service mTLS configuration |
| Deployment Guide | [DEPLOY.md](../../DEPLOY.md) | Quick-start deployment instructions for cloning, building, and running the system |

## Compliance Documentation

| Document | Path | Description |
|----------|------|-------------|
| FIPS 140-3 Readiness | [docs/compliance/FIPS-140-3-READINESS.md](../compliance/FIPS-140-3-READINESS.md) | FIPS 140-3 cryptographic module validation readiness assessment |
| CNSA 2.0 Status | [docs/compliance/CNSA-2-0-STATUS.md](../compliance/CNSA-2-0-STATUS.md) | NSA CNSA 2.0 post-quantum algorithm transition status |
| NIST 800-53 Mapping | [docs/compliance/NIST-800-53-MAPPING.md](../compliance/NIST-800-53-MAPPING.md) | Control mapping to NIST SP 800-53 Rev 5 security controls |
| AAL3 Checklist | [docs/compliance/AAL3-CHECKLIST.md](../compliance/AAL3-CHECKLIST.md) | NIST SP 800-63B AAL3 authenticator assurance level checklist |
| Zero Trust Mapping | [docs/compliance/ZERO-TRUST-MAPPING.md](../compliance/ZERO-TRUST-MAPPING.md) | NIST SP 800-207 Zero Trust Architecture mapping |

## Architecture and Security

| Document | Path | Description |
|----------|------|-------------|
| Architecture Overview | [ARCHITECTURE.md](../../ARCHITECTURE.md) | System architecture, module descriptions, cryptographic design, and threat model |
| Security Policy | [SECURITY.md](../../SECURITY.md) | Vulnerability reporting policy, CNSA 2.0 compliance statement, dependency management |
| Supply Chain Security | [SUPPLY_CHAIN.md](../../SUPPLY_CHAIN.md) | Supply chain integrity policy, SBOM generation, signature verification |
| Changelog | [CHANGELOG.md](../../CHANGELOG.md) | Version history and release notes |

## Formal Verification

| Document | Path | Description |
|----------|------|-------------|
| TLA+ Model | [formal-model/milnet.tla](../../formal-model/milnet.tla) | TLA+ formal model covering all authentication tiers, FROST DKG, OPAQUE, ratchet protocol, cross-domain guard, token lifecycle, and key rotation |
| TLA+ Config | [formal-model/milnet.cfg](../../formal-model/milnet.cfg) | TLC model checker configuration with safety invariants and liveness properties |
| Formal Model README | [formal-model/README.md](../../formal-model/README.md) | Instructions for running the TLA+ model checker |

## Placeholder URLs Requiring Configuration

The following URLs in the documentation require configuration for deployment:

| File | Current Value | Action Required |
|------|---------------|-----------------|
| `SECURITY.md` | `[DEPLOY: configure actual security reporting email]` | Set to organization's security reporting email |
| `docs/runbooks/KEY-CEREMONY-RUNBOOK.md` | `[DEPLOY: configure actual URL]` markers on external NIST/IETF references | Configure local mirror URLs or leave as direct links |

All internal document references use relative paths within the repository. External references to NIST, IETF, and other standards bodies link directly to their canonical URLs.
