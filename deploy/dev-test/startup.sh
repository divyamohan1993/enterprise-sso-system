#!/bin/bash
# ============================================================================
# MILNET SSO — Dev/Test Startup Script
# ============================================================================
# Runs on a Spot (preemptible) GCE VM. Installs Rust, clones repo, runs tests.
# Reports results to instance metadata. Self-destructs on failure if configured.
# ============================================================================
set -euo pipefail

LOG_FILE="/var/log/milnet-test.log"
exec > >(tee -a "$LOG_FILE") 2>&1

METADATA_URL="http://metadata.google.internal/computeMetadata/v1"
METADATA_HEADER="Metadata-Flavor: Google"

# ── Helper Functions ─────────────────────────────────────────────────────────

get_metadata() {
  curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/instance/attributes/$1" 2>/dev/null || echo ""
}

set_metadata() {
  local key="$1" value="$2"
  local zone project instance
  zone=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/instance/zone" | rev | cut -d'/' -f1 | rev)
  project=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/project/project-id")
  instance=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/instance/name")
  gcloud compute instances add-metadata "$instance" \
    --zone="$zone" --project="$project" \
    --metadata="${key}=${value}" 2>/dev/null || true
}

self_destruct() {
  local zone project instance
  zone=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/instance/zone" | rev | cut -d'/' -f1 | rev)
  project=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/project/project-id")
  instance=$(curl -sf -H "$METADATA_HEADER" "${METADATA_URL}/instance/name")
  echo ">>> SELF-DESTRUCT: Deleting instance $instance in 60 seconds..."
  sleep 60
  gcloud compute instances delete "$instance" --zone="$zone" --project="$project" --quiet || true
}

# ── Read Configuration ───────────────────────────────────────────────────────

GITHUB_REPO=$(get_metadata "github-repo")
GITHUB_BRANCH=$(get_metadata "github-branch")
LOG_LEVEL=$(get_metadata "log-level")
DB_HOST=$(get_metadata "db-host")
DB_PASSWORD=$(get_metadata "db-password")
DB_NAME=$(get_metadata "db-name")
DB_USER=$(get_metadata "db-user")
AUTO_DESTROY=$(get_metadata "auto-destroy")

echo "============================================================"
echo "MILNET SSO Test Runner Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo "Repo:    $GITHUB_REPO"
echo "Branch:  $GITHUB_BRANCH"
echo "DB Host: $DB_HOST"
echo "Log:     $LOG_LEVEL"
echo "============================================================"

set_metadata "test-status" "running"
set_metadata "test-started-at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── 1. Install System Dependencies ──────────────────────────────────────────

echo ">>> [1/6] Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential \
  pkg-config \
  libssl-dev \
  git \
  curl \
  postgresql-client \
  ca-certificates \
  jq \
  protobuf-compiler

echo ">>> System dependencies installed."

# ── 2. Install Rust 1.88.0 ──────────────────────────────────────────────────

echo ">>> [2/6] Installing Rust 1.88.0..."
export HOME="/root"
export RUSTUP_HOME="/root/.rustup"
export CARGO_HOME="/root/.cargo"

if [ ! -f "$CARGO_HOME/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
fi

source "$CARGO_HOME/env"
rustup toolchain install 1.88.0 --profile minimal --component clippy,rustfmt
rustup default 1.88.0

echo ">>> Rust version: $(rustc --version)"
echo ">>> Cargo version: $(cargo --version)"

# ── 3. Clone Repository ─────────────────────────────────────────────────────

echo ">>> [3/6] Cloning repository..."
REPO_DIR="/opt/milnet-sso"

if [ -d "$REPO_DIR" ]; then
  rm -rf "$REPO_DIR"
fi

git clone --depth 1 --branch "$GITHUB_BRANCH" "$GITHUB_REPO" "$REPO_DIR"
cd "$REPO_DIR"

COMMIT_SHA=$(git rev-parse --short HEAD)
echo ">>> Cloned at commit: $COMMIT_SHA"
set_metadata "test-commit" "$COMMIT_SHA"

# ── 4. Wait for Cloud SQL ───────────────────────────────────────────────────

echo ">>> [4/6] Waiting for Cloud SQL to be reachable..."
DB_CONNSTR="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}"

MAX_RETRIES=30
RETRY=0
until pg_isready -h "$DB_HOST" -p 5432 -U "$DB_USER" -q 2>/dev/null; do
  RETRY=$((RETRY + 1))
  if [ $RETRY -ge $MAX_RETRIES ]; then
    echo "ERROR: Cloud SQL not reachable after $MAX_RETRIES attempts"
    set_metadata "test-status" "failed:db-unreachable"
    set_metadata "test-completed-at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    set_metadata "test-exit-code" "1"
    if [ "$AUTO_DESTROY" = "true" ]; then
      self_destruct &
    fi
    exit 1
  fi
  echo "  Waiting for Cloud SQL... ($RETRY/$MAX_RETRIES)"
  sleep 10
done

echo ">>> Cloud SQL is reachable."

# ── 5. Run Tests ────────────────────────────────────────────────────────────

echo ">>> [5/6] Running cargo test..."
export DATABASE_URL="$DB_CONNSTR"
export RUST_LOG="${LOG_LEVEL}"
export RUST_BACKTRACE=1

TEST_LOG="/var/log/milnet-test-output.log"

# Set cargo test flags based on log level
CARGO_FLAGS="--workspace --release"
if [ "$LOG_LEVEL" = "verbose" ]; then
  CARGO_FLAGS="$CARGO_FLAGS -- --nocapture"
fi

set_metadata "test-status" "testing"

# Run cargo test, capture exit code
set +e
cargo test $CARGO_FLAGS 2>&1 | tee "$TEST_LOG"
TEST_EXIT_CODE=${PIPESTATUS[0]}
set -e

# Count test results from output
TESTS_PASSED=$(grep -c "^test .* ok$" "$TEST_LOG" 2>/dev/null || echo "0")
TESTS_FAILED=$(grep -c "^test .* FAILED$" "$TEST_LOG" 2>/dev/null || echo "0")
TESTS_IGNORED=$(grep -c "^test .* ignored$" "$TEST_LOG" 2>/dev/null || echo "0")

echo ""
echo "============================================================"
echo "Test Results"
echo "============================================================"
echo "Exit code: $TEST_EXIT_CODE"
echo "Passed:    $TESTS_PASSED"
echo "Failed:    $TESTS_FAILED"
echo "Ignored:   $TESTS_IGNORED"
echo "============================================================"

# ── 6. Report Results ───────────────────────────────────────────────────────

echo ">>> [6/6] Reporting results..."
set_metadata "test-completed-at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set_metadata "test-exit-code" "$TEST_EXIT_CODE"
set_metadata "test-passed" "$TESTS_PASSED"
set_metadata "test-failed" "$TESTS_FAILED"
set_metadata "test-ignored" "$TESTS_IGNORED"

if [ "$TEST_EXIT_CODE" -eq 0 ]; then
  set_metadata "test-status" "passed"
  echo ">>> ALL TESTS PASSED"
else
  set_metadata "test-status" "failed"
  echo ">>> TESTS FAILED (exit code: $TEST_EXIT_CODE)"

  # Extract failure summary
  FAILURE_SUMMARY=$(grep -A 5 "failures:" "$TEST_LOG" 2>/dev/null | head -20 || echo "See full log")
  set_metadata "test-failure-summary" "$FAILURE_SUMMARY"

  if [ "$AUTO_DESTROY" = "true" ]; then
    echo ">>> Auto-destroy is enabled. VM will self-destruct in 60 seconds."
    echo ">>> SSH in now to debug, or set auto_destroy_on_failure=false to keep the VM."
    self_destruct &
  fi
fi

echo ">>> Startup script complete: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
