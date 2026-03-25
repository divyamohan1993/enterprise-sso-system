#!/usr/bin/env bash
#
# verify-reproducible-build.sh
#
# Performs two independent release builds from the same source tree and
# compares the output binaries to verify reproducibility.  Generates a
# JSON build manifest with full provenance metadata.
#
# Usage:
#   ./deploy/verify-reproducible-build.sh [--manifest-dir DIR] [--features FEATURES]
#
# Options:
#   --manifest-dir DIR   Directory to write the build manifest JSON (default: ./build-manifests)
#   --features FEATURES  Cargo features to enable (comma-separated, default: none)
#
# Exit codes:
#   0 - Build is reproducible (all binary hashes match)
#   1 - Build is NOT reproducible (at least one binary differs)
#   2 - Build or setup failure
#
# Requirements:
#   - Rust toolchain with cargo and rustc
#   - git (for commit hash)
#   - sha256sum, jq (for manifest generation)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST_DIR="$PROJECT_ROOT/build-manifests"
FEATURES=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest-dir)
            MANIFEST_DIR="$2"
            shift 2
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# ── Colour output helpers ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ── Step 1: Record build environment ─────────────────────────────────

info "Recording build environment..."

RUSTC_VERSION="$(rustc --version 2>/dev/null || echo 'rustc not found')"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo 'cargo not found')"
TARGET_TRIPLE="$(rustc -vV 2>/dev/null | grep '^host:' | awk '{print $2}' || echo 'unknown')"
GIT_COMMIT="$(cd "$PROJECT_ROOT" && git rev-parse HEAD 2>/dev/null || echo 'unknown')"
GIT_DIRTY="$(cd "$PROJECT_ROOT" && git diff --quiet 2>/dev/null && echo 'false' || echo 'true')"
BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

FEATURE_FLAGS=""
if [[ -n "$FEATURES" ]]; then
    FEATURE_FLAGS="--features $FEATURES"
fi

echo ""
info "Build environment:"
info "  rustc:       $RUSTC_VERSION"
info "  cargo:       $CARGO_VERSION"
info "  target:      $TARGET_TRIPLE"
info "  git commit:  $GIT_COMMIT"
info "  git dirty:   $GIT_DIRTY"
info "  features:    ${FEATURES:-<none>}"
info "  timestamp:   $BUILD_TIMESTAMP"
echo ""

if [[ "$GIT_DIRTY" == "true" ]]; then
    warn "Working tree has uncommitted changes. Reproducibility may be affected."
fi

# ── Step 2: Record dependency versions ────────────────────────────────

info "Recording dependency versions..."

LOCKFILE="$PROJECT_ROOT/Cargo.lock"
if [[ -f "$LOCKFILE" ]]; then
    DEPENDENCY_HASH="$(sha256sum "$LOCKFILE" | awk '{print $1}')"
    info "  Cargo.lock SHA-256: $DEPENDENCY_HASH"
else
    warn "No Cargo.lock found. Build reproducibility requires --locked."
    DEPENDENCY_HASH="no-lockfile"
fi

# Capture cargo tree output if available
CARGO_TREE_OUTPUT=""
if command -v cargo &>/dev/null; then
    CARGO_TREE_OUTPUT="$(cd "$PROJECT_ROOT" && cargo tree --locked 2>/dev/null | head -100 || echo 'cargo tree unavailable')"
fi

# ── Step 3: Perform two independent builds ───────────────────────────

BUILD_DIR_1="$(mktemp -d /tmp/reproducible-build-1.XXXXXX)"
BUILD_DIR_2="$(mktemp -d /tmp/reproducible-build-2.XXXXXX)"

cleanup() {
    info "Cleaning up temporary directories..."
    rm -rf "$BUILD_DIR_1" "$BUILD_DIR_2"
}
trap cleanup EXIT

# Common cargo flags for reproducible builds
CARGO_FLAGS="--release --locked"
if [[ -n "$FEATURE_FLAGS" ]]; then
    CARGO_FLAGS="$CARGO_FLAGS $FEATURE_FLAGS"
fi

# Export environment variables to improve reproducibility
export CARGO_TARGET_DIR="$BUILD_DIR_1"
export SOURCE_DATE_EPOCH="$(date -d "$BUILD_TIMESTAMP" +%s 2>/dev/null || date +%s)"

info "Build 1: target directory $BUILD_DIR_1"
info "  Running: cargo build $CARGO_FLAGS"
if ! (cd "$PROJECT_ROOT" && CARGO_TARGET_DIR="$BUILD_DIR_1" cargo build $CARGO_FLAGS 2>&1); then
    fail "Build 1 failed!"
    exit 2
fi
ok "Build 1 completed successfully."

info "Build 2: target directory $BUILD_DIR_2"
info "  Running: cargo build $CARGO_FLAGS"
if ! (cd "$PROJECT_ROOT" && CARGO_TARGET_DIR="$BUILD_DIR_2" cargo build $CARGO_FLAGS 2>&1); then
    fail "Build 2 failed!"
    exit 2
fi
ok "Build 2 completed successfully."

# ── Step 4: Compare outputs ──────────────────────────────────────────

info "Comparing build outputs..."
echo ""

RELEASE_DIR_1="$BUILD_DIR_1/release"
RELEASE_DIR_2="$BUILD_DIR_2/release"

# Find all ELF binaries and .rlib/.so files in the release directory
ALL_MATCH=true
BINARY_HASHES_JSON="{"
FIRST_BINARY=true

# Compare executable binaries
for binary in "$RELEASE_DIR_1"/*; do
    # Skip directories and non-executable files
    [[ -d "$binary" ]] && continue
    [[ ! -f "$binary" ]] && continue

    filename="$(basename "$binary")"

    # Skip intermediate build artifacts
    case "$filename" in
        *.d | *.fingerprint | build | deps | examples | incremental | .cargo-lock)
            continue
            ;;
    esac

    # Only compare actual binaries (ELF files and libraries)
    if ! file "$binary" 2>/dev/null | grep -qE '(ELF|shared object|ar archive)'; then
        continue
    fi

    binary_2="$RELEASE_DIR_2/$filename"
    if [[ ! -f "$binary_2" ]]; then
        warn "  $filename: present in build 1 but not build 2"
        ALL_MATCH=false
        continue
    fi

    hash_1="$(sha256sum "$binary" | awk '{print $1}')"
    hash_2="$(sha256sum "$binary_2" | awk '{print $1}')"

    if [[ "$hash_1" == "$hash_2" ]]; then
        ok "  $filename: MATCH (SHA-256: ${hash_1:0:16}...)"
    else
        fail "  $filename: DIFFER"
        fail "    Build 1: $hash_1"
        fail "    Build 2: $hash_2"
        ALL_MATCH=false
    fi

    # Add to JSON
    if [[ "$FIRST_BINARY" == "true" ]]; then
        FIRST_BINARY=false
    else
        BINARY_HASHES_JSON+=","
    fi
    BINARY_HASHES_JSON+="\"$filename\":{\"build_1\":\"$hash_1\",\"build_2\":\"$hash_2\",\"match\":$([ "$hash_1" == "$hash_2" ] && echo true || echo false)}"
done

BINARY_HASHES_JSON+="}"

echo ""

if [[ "$ALL_MATCH" == "true" ]]; then
    ok "All binaries are reproducible!"
    REPRODUCIBLE=true
else
    fail "Some binaries differ between builds."
    REPRODUCIBLE=false
fi

# ── Step 5: Generate build manifest ──────────────────────────────────

info "Generating build manifest..."

mkdir -p "$MANIFEST_DIR"

MANIFEST_FILE="$MANIFEST_DIR/build-manifest-$(date -u +%Y%m%d-%H%M%S).json"

# Use a heredoc + cat to build the JSON (avoids jq dependency)
cat > "$MANIFEST_FILE" << MANIFEST_EOF
{
  "git_commit": "$GIT_COMMIT",
  "git_dirty": $GIT_DIRTY,
  "rustc_version": "$RUSTC_VERSION",
  "cargo_version": "$CARGO_VERSION",
  "target": "$TARGET_TRIPLE",
  "features": "$FEATURES",
  "dependency_lock_hash": "$DEPENDENCY_HASH",
  "binary_hashes": $BINARY_HASHES_JSON,
  "build_time": "$BUILD_TIMESTAMP",
  "reproducible": $REPRODUCIBLE,
  "source_date_epoch": $SOURCE_DATE_EPOCH,
  "verification_script": "deploy/verify-reproducible-build.sh"
}
MANIFEST_EOF

ok "Build manifest written to: $MANIFEST_FILE"

# Also write a "latest" symlink
LATEST_LINK="$MANIFEST_DIR/build-manifest-latest.json"
cp "$MANIFEST_FILE" "$LATEST_LINK"
info "Latest manifest: $LATEST_LINK"

echo ""
info "── Summary ──"
info "  Git commit:    $GIT_COMMIT"
info "  Reproducible:  $REPRODUCIBLE"
info "  Manifest:      $MANIFEST_FILE"
echo ""

if [[ "$REPRODUCIBLE" == "true" ]]; then
    ok "Reproducible build verification PASSED."
    exit 0
else
    fail "Reproducible build verification FAILED."
    exit 1
fi
