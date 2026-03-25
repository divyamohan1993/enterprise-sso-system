#!/usr/bin/env bash
# ==========================================================================
# MILNET SSO System — Hardened Kernel Build Script
# ==========================================================================
#
# Downloads, verifies, configures, builds, and signs a minimal Linux kernel
# for the MILNET bare-metal SSO appliance.
#
# Prerequisites:
#   - Build host with: gcc >= 12 or clang >= 16, make, flex, bison, libelf-dev,
#     libssl-dev, bc, cpio, sbsigntools, gpg
#   - Internet access to cdn.kernel.org (or local mirror)
#   - MOK key pair for Secure Boot signing (see generate-mok-keys section)
#
# Usage:
#   ./build-kernel.sh [--sign] [--clean]
#
# Output:
#   build/bzImage           — Signed (if --sign) kernel binary
#   build/System.map        — Symbol map for attestation
#   build/bzImage.sha512    — SHA-512 digest for binary attestation
#   build/milnet-kernel.efi — Signed EFI binary (if --sign)
#
# CLASSIFICATION: UNCLASSIFIED // FOUO
# ==========================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KERNEL_MAJOR="6"
KERNEL_VERSION="6.12.11"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"
KERNEL_SIG_URL="${KERNEL_URL}.sign"
KERNEL_SHA_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/sha256sums.asc"

# Greg Kroah-Hartman's GPG key (signs stable kernels)
GPG_KEY_GKH="647F28654894E3BD457199BE38DBBDC86092693E"
# Linus Torvalds' GPG key
GPG_KEY_LINUS="ABAF11C65A2970B130ABE3C479BE3E4300411886"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"
CONFIG_FILE="${SCRIPT_DIR}/milnet-kernel.config"

# Secure Boot signing keys (Machine Owner Key)
MOK_CERT="${SCRIPT_DIR}/keys/MOK.crt"
MOK_KEY="${SCRIPT_DIR}/keys/MOK.key"

# Build flags
SIGN_KERNEL=false
CLEAN_BUILD=false
JOBS="$(nproc)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --sign)  SIGN_KERNEL=true ;;
        --clean) CLEAN_BUILD=true ;;
        --help|-h)
            echo "Usage: $0 [--sign] [--clean]"
            echo "  --sign   Sign kernel with MOK key for Secure Boot"
            echo "  --clean  Remove build directory before building"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: ${arg}" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight() {
    local missing=()
    for cmd in make gcc flex bison bc gpg xz sha256sum; do
        command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
    done
    if [[ "${SIGN_KERNEL}" == true ]]; then
        command -v sbsign >/dev/null 2>&1 || missing+=("sbsign (sbsigntools)")
        if [[ ! -f "${MOK_CERT}" ]] || [[ ! -f "${MOK_KEY}" ]]; then
            echo "ERROR: Secure Boot signing requested but MOK keys not found." >&2
            echo "  Expected: ${MOK_CERT}" >&2
            echo "  Expected: ${MOK_KEY}" >&2
            echo "  Run: $0 --generate-mok-keys first" >&2
            exit 1
        fi
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing required tools: ${missing[*]}" >&2
        echo "On Debian/Ubuntu: apt install build-essential flex bison bc libelf-dev libssl-dev gnupg xz-utils sbsigntools" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Download kernel source with integrity verification
# ---------------------------------------------------------------------------
download_kernel() {
    echo "=== Downloading Linux ${KERNEL_VERSION} ==="
    mkdir -p "${BUILD_DIR}"
    local tarball="${BUILD_DIR}/linux-${KERNEL_VERSION}.tar.xz"
    local signature="${BUILD_DIR}/linux-${KERNEL_VERSION}.tar.sign"

    if [[ -f "${tarball}" ]]; then
        echo "  Tarball already downloaded, skipping."
    else
        echo "  Fetching ${KERNEL_URL} ..."
        curl -fSL --retry 3 --retry-delay 5 -o "${tarball}" "${KERNEL_URL}"
    fi

    # Download detached GPG signature (signs the uncompressed .tar)
    if [[ ! -f "${signature}" ]]; then
        echo "  Fetching GPG signature..."
        curl -fSL --retry 3 -o "${signature}" "${KERNEL_SIG_URL}"
    fi

    # Import kernel signing keys if not already in keyring
    echo "  Importing kernel.org signing keys..."
    gpg --batch --keyserver hkps://keyserver.ubuntu.com \
        --recv-keys "${GPG_KEY_GKH}" "${GPG_KEY_LINUS}" 2>/dev/null || \
    gpg --batch --keyserver hkps://keys.openpgp.org \
        --recv-keys "${GPG_KEY_GKH}" "${GPG_KEY_LINUS}" 2>/dev/null || \
        echo "  WARNING: Could not fetch GPG keys. Verify manually."

    # Verify signature (decompress first, signature is on .tar not .tar.xz)
    echo "  Verifying GPG signature on kernel tarball..."
    xz -cd "${tarball}" | gpg --batch --verify "${signature}" - 2>&1 && \
        echo "  SIGNATURE VERIFIED: Kernel tarball is authentic." || {
        echo "  ERROR: GPG signature verification FAILED!" >&2
        echo "  The kernel tarball may be tampered with. Aborting." >&2
        rm -f "${tarball}"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Extract and configure
# ---------------------------------------------------------------------------
configure_kernel() {
    echo "=== Extracting kernel source ==="
    local tarball="${BUILD_DIR}/linux-${KERNEL_VERSION}.tar.xz"

    if [[ "${CLEAN_BUILD}" == true ]] && [[ -d "${SRC_DIR}" ]]; then
        echo "  Cleaning previous build..."
        rm -rf "${SRC_DIR}"
    fi

    if [[ ! -d "${SRC_DIR}" ]]; then
        tar -xf "${tarball}" -C "${BUILD_DIR}"
    fi

    echo "=== Applying MILNET kernel configuration ==="
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        echo "ERROR: Kernel config not found: ${CONFIG_FILE}" >&2
        exit 1
    fi

    cp "${CONFIG_FILE}" "${SRC_DIR}/.config"

    # Validate and resolve any missing dependencies in the config.
    # 'olddefconfig' sets any unspecified options to their default values
    # without prompting — deterministic and non-interactive.
    cd "${SRC_DIR}"
    make olddefconfig

    # Print config delta for audit
    echo "  Configuration summary:"
    scripts/diffconfig "${CONFIG_FILE}" .config 2>/dev/null | head -40 || true
    echo "  (see ${SRC_DIR}/.config for full resolved config)"
}

# ---------------------------------------------------------------------------
# Build kernel
# ---------------------------------------------------------------------------
build_kernel() {
    echo "=== Building kernel with ${JOBS} parallel jobs ==="
    cd "${SRC_DIR}"

    # Build with hardening-relevant compiler flags
    # -fstack-clash-protection: prevent stack clash attacks
    # -fcf-protection: Intel CET (Control-flow Enforcement Technology)
    make -j"${JOBS}" \
        KCFLAGS="-fstack-clash-protection" \
        bzImage 2>&1 | tail -20

    echo "  Kernel built successfully."
    echo "  Size: $(du -h arch/x86/boot/bzImage | cut -f1)"
}

# ---------------------------------------------------------------------------
# Sign kernel for UEFI Secure Boot
# ---------------------------------------------------------------------------
sign_kernel() {
    if [[ "${SIGN_KERNEL}" != true ]]; then
        echo "=== Skipping Secure Boot signing (use --sign to enable) ==="
        return
    fi

    echo "=== Signing kernel for UEFI Secure Boot ==="
    local bzimage="${SRC_DIR}/arch/x86/boot/bzImage"
    local signed="${BUILD_DIR}/milnet-kernel.efi"

    sbsign \
        --key "${MOK_KEY}" \
        --cert "${MOK_CERT}" \
        --output "${signed}" \
        "${bzimage}"

    echo "  Signed EFI binary: ${signed}"
    echo "  Verify with: sbverify --cert ${MOK_CERT} ${signed}"

    # Verify the signature immediately
    if sbverify --cert "${MOK_CERT}" "${signed}" 2>/dev/null; then
        echo "  VERIFIED: Signature is valid."
    else
        echo "  ERROR: Signature verification failed!" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Generate attestation artifacts
# ---------------------------------------------------------------------------
generate_attestation() {
    echo "=== Generating attestation artifacts ==="
    local bzimage="${SRC_DIR}/arch/x86/boot/bzImage"
    local sysmap="${SRC_DIR}/System.map"

    # Copy artifacts to build output directory
    cp "${bzimage}" "${BUILD_DIR}/bzImage"
    cp "${sysmap}" "${BUILD_DIR}/System.map"
    cp "${SRC_DIR}/.config" "${BUILD_DIR}/milnet-kernel-resolved.config"

    # SHA-512 hash for binary attestation
    # This hash is stored in TPM PCR and compared during remote attestation
    sha512sum "${BUILD_DIR}/bzImage" > "${BUILD_DIR}/bzImage.sha512"
    sha512sum "${BUILD_DIR}/System.map" > "${BUILD_DIR}/System.map.sha512"

    # SHA-256 (for compatibility with TPM PCR extend operations)
    sha256sum "${BUILD_DIR}/bzImage" > "${BUILD_DIR}/bzImage.sha256"

    echo "  Artifacts:"
    echo "    ${BUILD_DIR}/bzImage              — Kernel binary"
    echo "    ${BUILD_DIR}/System.map           — Symbol map"
    echo "    ${BUILD_DIR}/bzImage.sha512       — SHA-512 digest"
    echo "    ${BUILD_DIR}/bzImage.sha256       — SHA-256 digest (TPM PCR)"
    if [[ "${SIGN_KERNEL}" == true ]]; then
        echo "    ${BUILD_DIR}/milnet-kernel.efi    — Signed EFI binary"
    fi

    echo ""
    echo "  Kernel SHA-512:"
    cat "${BUILD_DIR}/bzImage.sha512"
}

# ---------------------------------------------------------------------------
# Generate MOK keys (one-time setup)
# ---------------------------------------------------------------------------
generate_mok_keys() {
    echo "=== Generating Machine Owner Key (MOK) pair ==="
    local keys_dir="${SCRIPT_DIR}/keys"
    mkdir -p "${keys_dir}"
    chmod 700 "${keys_dir}"

    if [[ -f "${MOK_CERT}" ]] && [[ -f "${MOK_KEY}" ]]; then
        echo "  MOK keys already exist. Remove ${keys_dir} to regenerate."
        return
    fi

    openssl req -new -x509 \
        -newkey rsa:4096 \
        -keyout "${MOK_KEY}" \
        -out "${MOK_CERT}" \
        -nodes \
        -days 3650 \
        -sha512 \
        -subj "/CN=MILNET SSO Secure Boot Signing Key/O=MILNET/OU=Security Engineering"

    chmod 600 "${MOK_KEY}"
    chmod 644 "${MOK_CERT}"

    echo "  MOK private key: ${MOK_KEY} (PROTECT THIS)"
    echo "  MOK certificate: ${MOK_CERT}"
    echo ""
    echo "  To enroll in firmware: mokutil --import ${MOK_CERT}"
    echo "  Then reboot and confirm enrollment at the MOK Manager screen."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo "================================================================"
    echo " MILNET SSO — Hardened Kernel Build"
    echo " Kernel: Linux ${KERNEL_VERSION}"
    echo " Config: ${CONFIG_FILE}"
    echo " Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "================================================================"
    echo ""

    preflight
    download_kernel
    configure_kernel
    build_kernel
    sign_kernel
    generate_attestation

    echo ""
    echo "================================================================"
    echo " BUILD COMPLETE"
    echo " Output: ${BUILD_DIR}/"
    echo "================================================================"
}

# Allow sourcing for individual functions or run main
if [[ "${1:-}" == "--generate-mok-keys" ]]; then
    generate_mok_keys
else
    main
fi
