# MILNET SSO — Supply Chain Security Policy

This document defines the supply chain security controls for the MILNET SSO system.
All contributors, maintainers, and operators MUST follow these policies.

## 1. Dependency Management Policy

### Rust Crate Dependencies

- **Lockfile enforcement**: All builds use `--locked` to ensure reproducible builds
  from `Cargo.lock`. The lockfile MUST be committed to version control.
- **Advisory scanning**: `cargo-audit` runs on every CI build and nightly.
  Known vulnerabilities cause hard build failures (no soft-fail).
- **Policy enforcement**: `cargo-deny` enforces four check categories:
  - **Advisories**: Block crates with known CVEs or RustSec advisories.
  - **Licenses**: Only permissive licenses (MIT, Apache-2.0, BSD-2-Clause,
    BSD-3-Clause, ISC, Zlib) are allowed. AGPL-3.0 and GPL-3.0 are denied.
  - **Sources**: Crates must originate from crates.io. No git dependencies
    in production builds without explicit maintainer approval.
  - **Bans**: Duplicate crate versions and specifically banned crates are
    rejected.
- **Update cadence**: Dependencies are reviewed weekly. Security-critical
  updates MUST be applied within 24 hours of advisory publication.

### Container Base Images

- **Digest pinning**: All base images in Dockerfiles MUST be pinned to
  SHA256 digests (e.g., `rust:1.88-slim@sha256:abc...`). Floating tags
  like `latest` are prohibited.
- **Minimal images**: Runtime images use `debian:bookworm-slim` with only
  essential packages (`ca-certificates`, `libssl3`).
- **Nightly scanning**: Trivy scans all published container images nightly,
  with results uploaded to GitHub Security (SARIF format).

## 2. Image Signing and Verification

### Cosign Keyless Signing (Sigstore)

- **Signing**: All container images pushed to `ghcr.io` are signed using
  cosign keyless signing (Fulcio + Rekor) via GitHub Actions OIDC identity.
- **Verification**: Image signatures are verified in CI before deployment
  using `cosign verify` with:
  - `--certificate-identity-regexp` matching the repository's GitHub Actions
    identity.
  - `--certificate-oidc-issuer` set to `https://token.actions.githubusercontent.com`.
- **Transparency log**: All signatures are recorded in the Rekor transparency
  log for public auditability.

### SLSA Provenance

- **Level**: SLSA Level 3 provenance is generated for all container images
  using `slsa-framework/slsa-github-generator`.
- **Attestation**: Provenance attestations are attached to container images
  in the registry.
- **Verification**: Consumers can verify provenance using `slsa-verifier`.

## 3. SBOM Generation and Distribution

### Build-Time SBOMs

- **Formats**: SBOMs are generated in both CycloneDX JSON and SPDX JSON
  formats for maximum tooling compatibility.
- **Generation**: `cargo-cyclonedx` and `cargo-spdx` produce SBOMs from
  `Cargo.lock` during every CI build. Generation is a hard requirement
  (pipeline fails if SBOM is empty or missing).
- **Signing**: All SBOMs are signed with cosign (`sign-blob`) and the
  signature bundle is stored alongside the SBOM.
- **Artifacts**: SBOMs and their signatures are uploaded as GitHub Actions
  build artifacts.

### Container Image SBOMs

- **Generation**: `syft` generates a CycloneDX SBOM for each container image
  after build.
- **Attachment**: Container SBOMs are attached to images in the registry
  using `cosign attach sbom`.
- **Signing**: Attached SBOMs are signed with cosign.
- **Retrieval**: Consumers can retrieve SBOMs using `cosign download sbom`.

### Vulnerability Scanning

- **Tool**: Grype scans all SBOMs against known vulnerability databases.
- **Policy**: Builds fail on `critical` severity vulnerabilities.
- **Nightly**: Full SBOM regeneration and vulnerability scan runs nightly
  to catch newly published CVEs.

## 4. Vulnerability Response SLA

| Severity | Response Time | Patch Deadline | Communication |
|----------|---------------|----------------|---------------|
| Critical | 4 hours | 24 hours | Immediate notification to all operators |
| High | 24 hours | 72 hours | Notification within 24 hours |
| Medium | 72 hours | 2 weeks | Included in next release notes |
| Low | 1 week | Next release | Documented in changelog |

### Response Process

1. **Triage**: Security team evaluates the advisory and determines impact
   on MILNET SSO within the response time SLA.
2. **Mitigation**: If a patch is not immediately available, apply a workaround
   (e.g., WAF rule, configuration change, feature flag).
3. **Patch**: Apply the fix, run full CI (including security checks), and
   publish a new release within the patch deadline.
4. **Communication**: Notify operators via the security advisory channel.
   For Critical/High, include a recommended action (upgrade, workaround,
   or compensating control).
5. **Post-mortem**: Critical vulnerabilities receive a written post-mortem
   within 1 week of resolution.

## 5. Cargo Vendoring for Air-Gapped Deployments

MILNET SSO supports deployment in air-gapped (disconnected) environments
where crates.io and GitHub are not accessible.

### Vendoring Process

```bash
# Generate the vendor directory from Cargo.lock
cargo vendor vendor/

# This creates:
#   vendor/          — all crate source code
#   .cargo/config.toml — cargo configuration to use vendored sources
```

### Air-Gapped Build

```bash
# On the air-gapped build machine:
# 1. Transfer the full source tree (including vendor/) via approved media
# 2. Build using vendored dependencies only
cargo build --release --locked --offline

# The --offline flag ensures no network access is attempted.
# The --locked flag ensures Cargo.lock is respected exactly.
```

### Vendored Dependency Verification

```bash
# Before transferring to the air-gapped environment, verify:
# 1. Generate checksums of all vendored crates
find vendor/ -name "*.crate" -exec sha256sum {} \; > vendor-checksums.txt

# 2. On the air-gapped machine, verify checksums match
sha256sum -c vendor-checksums.txt
```

### Policy

- The `vendor/` directory is NOT committed to git (it is in `.gitignore`).
- Vendored archives are generated on a trusted build machine with network
  access, checksummed, and transferred via approved secure media.
- The vendor archive MUST be regenerated whenever `Cargo.lock` changes.
- Vendored dependencies are subject to the same advisory scanning as
  non-vendored dependencies (scan before transferring to air-gapped
  environment).

## 6. CI/CD Pipeline Security

### Pipeline Integrity

- **Pinned actions**: All GitHub Actions are pinned to SHA256 commit hashes,
  not floating tags, to prevent supply chain attacks via action compromise.
- **Minimal permissions**: Each job declares only the permissions it needs
  (principle of least privilege).
- **Secret scanning**: Gitleaks scans the full git history for leaked
  credentials on every push and nightly.
- **Dependency review**: Pull requests are automatically checked for new
  dependencies with known vulnerabilities or disallowed licenses.

### Branch Protection Requirements

- Require pull request reviews before merging to `master`.
- Require status checks to pass (CI, security, SBOM jobs).
- Require signed commits (warning for unsigned, enforcement at maintainer
  discretion).
- No force pushes to `master`.

### Artifact Integrity

- Build artifacts include SHA256 checksums.
- Container images are signed and have SLSA provenance.
- SBOMs are signed and attached to container images.
- All signatures use the Sigstore transparency log for auditability.
