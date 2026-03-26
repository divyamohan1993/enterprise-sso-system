#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Cross-Compile & Push Binaries to GCS
# ==============================================================================
# Builds all MILNET service binaries for x86_64-unknown-linux-gnu (release
# profile) and uploads them to a versioned GCS bucket. A LATEST pointer file
# is updated so that VMs can discover the current version at boot.
#
# Prerequisites:
#   - Rust toolchain with x86_64-unknown-linux-gnu target installed
#   - gcloud CLI authenticated with storage.admin on the project
#   - (Optional) cross or a musl/glibc sysroot for cross compilation
#
# Usage:
#   ./build-and-push.sh                        # defaults to GCP_PROJECT
#   GCP_PROJECT=my-proj ./build-and-push.sh    # override project
#   ./build-and-push.sh --skip-build           # upload pre-built binaries only
# ==============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PROJECT_ID="${GCP_PROJECT:-lmsforshantithakur}"
VERSION=$(date +%Y%m%d-%H%M%S)
BUCKET="gs://milnet-sso-binaries-${PROJECT_ID}"
TARGET="x86_64-unknown-linux-gnu"
PROFILE="release"
SKIP_BUILD=false

# All service binaries produced by the workspace.
readonly -a SERVICES=(gateway orchestrator opaque tss verifier ratchet audit admin)

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info()  { echo "[BUILD] INFO:  $*"; }
log_error() { echo "[BUILD] ERROR: $*" >&2; }
die()       { log_error "$@"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)  SKIP_BUILD=true; shift ;;
        --project)     PROJECT_ID="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--project PROJECT] [--version TAG]"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# Recompute bucket in case --project changed it.
BUCKET="gs://milnet-sso-binaries-${PROJECT_ID}"

# ── Step 1: Cross-compile all service binaries ───────────────────────────────

if [[ "${SKIP_BUILD}" == "false" ]]; then
    log_info "Cross-compiling for ${TARGET} (profile=${PROFILE}) ..."

    # Ensure the target is installed.
    rustup target add "${TARGET}" 2>/dev/null || true

    cd "${REPO_ROOT}"

    # Build every workspace member that produces a binary.  The --release flag
    # enables LTO, strip, and optimisation settings from the workspace profile.
    cargo build \
        --target "${TARGET}" \
        --profile "${PROFILE}" \
        --workspace \
        --exclude e2e \
        --exclude common \
        --exclude crypto \
        --exclude sso-protocol \
        --exclude fido

    log_info "Build complete."
else
    log_info "Skipping build (--skip-build)."
fi

# ── Step 2: Verify binaries exist ────────────────────────────────────────────

BIN_DIR="${REPO_ROOT}/target/${TARGET}/${PROFILE}"
MISSING=0

for svc in "${SERVICES[@]}"; do
    if [[ ! -f "${BIN_DIR}/${svc}" ]]; then
        log_error "Missing binary: ${BIN_DIR}/${svc}"
        ((MISSING++))
    fi
done

if [[ ${MISSING} -gt 0 ]]; then
    die "${MISSING} binary(ies) not found. Aborting upload."
fi

# ── Step 3: Compute SHA-256 manifest ─────────────────────────────────────────

log_info "Computing SHA-256 checksums ..."
MANIFEST_FILE=$(mktemp)
trap 'rm -f "${MANIFEST_FILE}"' EXIT

for svc in "${SERVICES[@]}"; do
    sha256sum "${BIN_DIR}/${svc}" | awk -v s="${svc}" '{print $1 "  " s}' >> "${MANIFEST_FILE}"
done

log_info "Manifest:"
cat "${MANIFEST_FILE}"

# ── Step 4: Create GCS bucket if it does not exist ───────────────────────────

if ! gsutil ls "${BUCKET}" &>/dev/null; then
    log_info "Creating bucket ${BUCKET} in asia-south1 ..."
    gsutil mb \
        -p "${PROJECT_ID}" \
        -l asia-south1 \
        -b on \
        "${BUCKET}"

    # Enable versioning for rollback safety.
    gsutil versioning set on "${BUCKET}"

    # Set uniform bucket-level access (no per-object ACLs).
    gsutil uniformbucketlevelaccess set on "${BUCKET}"

    log_info "Bucket created with versioning enabled."
else
    log_info "Bucket ${BUCKET} already exists."
fi

# ── Step 5: Upload binaries to versioned path ────────────────────────────────

DEST="${BUCKET}/v${VERSION}"

log_info "Uploading binaries to ${DEST}/ ..."

for svc in "${SERVICES[@]}"; do
    gsutil -o "GSUtil:parallel_composite_upload_threshold=50M" \
        cp "${BIN_DIR}/${svc}" "${DEST}/${svc}"
    log_info "  Uploaded ${svc}"
done

# Upload the manifest alongside the binaries.
gsutil cp "${MANIFEST_FILE}" "${DEST}/SHA256SUMS"
log_info "  Uploaded SHA256SUMS manifest"

# ── Step 6: Update LATEST pointer ────────────────────────────────────────────

log_info "Updating LATEST pointer to v${VERSION} ..."
echo "v${VERSION}" | gsutil cp - "${BUCKET}/LATEST"

# ── Done ─────────────────────────────────────────────────────────────────────

log_info "==========================================="
log_info "Build & push complete."
log_info "  Version : v${VERSION}"
log_info "  Bucket  : ${BUCKET}"
log_info "  Binaries: ${SERVICES[*]}"
log_info "==========================================="
