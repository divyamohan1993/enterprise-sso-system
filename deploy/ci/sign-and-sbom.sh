#!/usr/bin/env bash
set -euo pipefail
# MILNET SSO — Binary Signing & SBOM Generation
# Runs as part of CI/CD pipeline after cargo build --release

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/target/release"
DIST_DIR="$PROJECT_ROOT/dist"
SBOM_DIR="$DIST_DIR/sbom"

# List of all service binaries
BINARIES=(gateway orchestrator opaque tss verifier ratchet risk audit kt admin)

echo "=== MILNET Binary Signing & SBOM Pipeline ==="

# Step 1: Build release binaries
echo "[1/5] Building release binaries..."
cd "$PROJECT_ROOT"
cargo build --release --workspace 2>&1

# Step 2: Generate CycloneDX SBOM
echo "[2/5] Generating CycloneDX SBOM..."
mkdir -p "$SBOM_DIR"
# Generate dependency tree as JSON
cargo tree --workspace --depth 256 --format "{p} {v} {l}" > "$SBOM_DIR/dep-tree.txt" 2>/dev/null

# Build CycloneDX 1.5 SBOM from Cargo.lock + cargo metadata
cat > "$SBOM_DIR/milnet-sso-sbom.json" << SBOM_EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tools": [{"vendor": "MILNET", "name": "sign-and-sbom", "version": "1.0.0"}],
    "component": {
      "type": "application",
      "name": "milnet-sso",
      "version": "$(cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["packages"][0]["version"])' 2>/dev/null || echo '0.1.0')"
    }
  },
  "components": [
$(cargo metadata --format-version 1 2>/dev/null | python3 -c '
import sys, json
meta = json.load(sys.stdin)
lines = []
for pkg in meta.get("packages", []):
    lines.append(f"""    {{
      "type": "library",
      "name": "{pkg["name"]}",
      "version": "{pkg["version"]}",
      "purl": "pkg:cargo/{pkg["name"]}@{pkg["version"]}",
      "licenses": [{{"license": {{"id": "{pkg.get("license", "UNKNOWN")}"}}}}]
    }}""")
print(",\n".join(lines))
' 2>/dev/null || echo '    {"type": "library", "name": "unknown", "version": "0.0.0"}')
  ]
}
SBOM_EOF
echo "  SBOM written to $SBOM_DIR/milnet-sso-sbom.json"

# Step 3: Compute SHA-512 hashes of all binaries
echo "[3/5] Computing binary hashes..."
mkdir -p "$DIST_DIR/hashes"
for bin in "${BINARIES[@]}"; do
  if [ -f "$BUILD_DIR/$bin" ]; then
    sha512sum "$BUILD_DIR/$bin" > "$DIST_DIR/hashes/$bin.sha512"
    echo "  $bin: $(cut -c1-16 "$DIST_DIR/hashes/$bin.sha512")..."
  else
    echo "  WARNING: $bin not found in $BUILD_DIR"
  fi
done

# Step 4: Sign binaries
echo "[4/5] Signing binaries..."
mkdir -p "$DIST_DIR/signatures"

# Prefer cosign, fall back to GPG
if command -v cosign &>/dev/null; then
  SIGN_METHOD="cosign"
  echo "  Using cosign for signing"

  # Ensure cosign key exists
  if [ ! -f "$DIST_DIR/cosign.key" ] && [ -z "${COSIGN_KEY:-}" ]; then
    echo "  ERROR: No cosign key found. Set COSIGN_KEY env var or place cosign.key in $DIST_DIR"
    echo "  Generate with: cosign generate-key-pair"
    exit 1
  fi
  COSIGN_KEY="${COSIGN_KEY:-$DIST_DIR/cosign.key}"

  for bin in "${BINARIES[@]}"; do
    if [ -f "$BUILD_DIR/$bin" ]; then
      cosign sign-blob --key "$COSIGN_KEY" \
        --output-signature "$DIST_DIR/signatures/$bin.sig" \
        --output-certificate "$DIST_DIR/signatures/$bin.cert" \
        "$BUILD_DIR/$bin" 2>/dev/null || \
      cosign sign-blob --key "$COSIGN_KEY" \
        --output-signature "$DIST_DIR/signatures/$bin.sig" \
        "$BUILD_DIR/$bin"
      echo "  Signed: $bin"
    fi
  done

elif command -v gpg &>/dev/null; then
  SIGN_METHOD="gpg"
  echo "  Using GPG for signing"

  GPG_KEY="${MILNET_GPG_KEY_ID:-milnet-release@milnet.mil}"
  for bin in "${BINARIES[@]}"; do
    if [ -f "$BUILD_DIR/$bin" ]; then
      gpg --detach-sign --armor --local-user "$GPG_KEY" \
        --output "$DIST_DIR/signatures/$bin.sig" \
        "$BUILD_DIR/$bin"
      echo "  Signed: $bin"
    fi
  done

else
  echo "  ERROR: Neither cosign nor gpg found. Cannot sign binaries."
  exit 1
fi

# Step 5: Verify all signatures
echo "[5/5] Verifying signatures..."
VERIFY_FAILED=0
for bin in "${BINARIES[@]}"; do
  if [ -f "$BUILD_DIR/$bin" ] && [ -f "$DIST_DIR/signatures/$bin.sig" ]; then
    if [ "$SIGN_METHOD" = "cosign" ]; then
      COSIGN_PUB="${COSIGN_KEY%.key}.pub"
      if cosign verify-blob --key "$COSIGN_PUB" \
        --signature "$DIST_DIR/signatures/$bin.sig" \
        "$BUILD_DIR/$bin" 2>/dev/null; then
        echo "  VERIFIED: $bin"
      else
        echo "  FAILED: $bin signature verification failed!"
        VERIFY_FAILED=1
      fi
    elif [ "$SIGN_METHOD" = "gpg" ]; then
      if gpg --verify "$DIST_DIR/signatures/$bin.sig" "$BUILD_DIR/$bin" 2>/dev/null; then
        echo "  VERIFIED: $bin"
      else
        echo "  FAILED: $bin signature verification failed!"
        VERIFY_FAILED=1
      fi
    fi
  fi
done

if [ $VERIFY_FAILED -ne 0 ]; then
  echo "FATAL: One or more signature verifications failed!"
  exit 1
fi

# Summary
echo ""
echo "=== Signing Complete ==="
echo "  Method: $SIGN_METHOD"
echo "  Binaries: ${#BINARIES[@]}"
echo "  SBOM: $SBOM_DIR/milnet-sso-sbom.json"
echo "  Hashes: $DIST_DIR/hashes/"
echo "  Signatures: $DIST_DIR/signatures/"
echo ""
echo "Deploy with: scp $DIST_DIR/* target-vm:/opt/milnet/"
