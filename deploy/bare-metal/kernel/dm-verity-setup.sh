#!/usr/bin/env bash
# ==========================================================================
# MILNET SSO System — dm-verity Immutable Root Filesystem Setup
# ==========================================================================
#
# Creates a cryptographically verified, immutable root filesystem for the
# MILNET SSO appliance. After running this script:
#
#   - The root partition is read-only and cannot be modified
#   - Every 4K block is verified against a Merkle hash tree on read
#   - Any tampering (even a single bit flip) causes an I/O error
#   - The root hash is signed and can be verified at boot
#   - The signed root hash is embedded in the kernel command line
#
# This provides:
#   - Runtime integrity verification (not just at boot)
#   - Protection against offline disk tampering
#   - Protection against partial disk corruption
#   - Cryptographic binding between kernel and rootfs
#
# Prerequisites:
#   - veritysetup (cryptsetup package)
#   - Target disk partitioned per partition-layout.md
#   - Root filesystem contents staged in a directory
#   - Signing key for root hash
#
# Usage:
#   ./dm-verity-setup.sh --root-dir /path/to/rootfs --disk /dev/sdX
#   ./dm-verity-setup.sh --verify --disk /dev/sdX
#
# CLASSIFICATION: UNCLASSIFIED // FOUO
# ==========================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/build/verity"

# Partition layout (matches partition-layout.md)
# These can be overridden via command-line arguments
EFI_PART=""       # /dev/sdX1 — set via --disk
ROOT_PART=""      # /dev/sdX2
HASH_PART=""      # /dev/sdX3
DATA_PART=""      # /dev/sdX4

# Filesystem parameters
BLOCK_SIZE=4096
HASH_ALGORITHM="sha256"

# Root filesystem source directory
ROOT_DIR=""

# Signing key (reuse MOK key or dedicated verity signing key)
SIGN_KEY="${SCRIPT_DIR}/keys/MOK.key"
SIGN_CERT="${SCRIPT_DIR}/keys/MOK.crt"

# Operation mode
MODE="create"  # create or verify

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    cat <<USAGE
Usage: $0 [OPTIONS]

Create dm-verity protected root filesystem:
  $0 --root-dir /path/to/staged/rootfs --disk /dev/sdX

Verify existing dm-verity setup:
  $0 --verify --disk /dev/sdX --root-hash <hash>

Options:
  --root-dir DIR     Directory containing the staged root filesystem
  --disk DEV         Target disk device (e.g., /dev/sda, /dev/nvme0n1)
  --part-root DEV    Override root partition device
  --part-hash DEV    Override hash partition device
  --sign-key FILE    Private key for signing root hash (default: keys/MOK.key)
  --sign-cert FILE   Certificate for signing root hash (default: keys/MOK.crt)
  --verify           Verify mode (check existing verity setup)
  --root-hash HASH   Root hash to verify against (verify mode)
  --help             Show this help

USAGE
    exit 1
}

ROOT_HASH_VERIFY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --root-dir)   ROOT_DIR="$2"; shift 2 ;;
        --disk)
            DISK="$2"
            # Auto-detect partition naming (sda1 vs nvme0n1p1)
            if [[ "${DISK}" == *nvme* ]] || [[ "${DISK}" == *loop* ]]; then
                EFI_PART="${DISK}p1"
                ROOT_PART="${DISK}p2"
                HASH_PART="${DISK}p3"
                DATA_PART="${DISK}p4"
            else
                EFI_PART="${DISK}1"
                ROOT_PART="${DISK}2"
                HASH_PART="${DISK}3"
                DATA_PART="${DISK}4"
            fi
            shift 2
            ;;
        --part-root)  ROOT_PART="$2"; shift 2 ;;
        --part-hash)  HASH_PART="$2"; shift 2 ;;
        --sign-key)   SIGN_KEY="$2"; shift 2 ;;
        --sign-cert)  SIGN_CERT="$2"; shift 2 ;;
        --verify)     MODE="verify"; shift ;;
        --root-hash)  ROOT_HASH_VERIFY="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            echo "ERROR: Unknown option: $1" >&2; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
validate_create() {
    if [[ -z "${ROOT_DIR}" ]]; then
        echo "ERROR: --root-dir is required" >&2
        usage
    fi
    if [[ ! -d "${ROOT_DIR}" ]]; then
        echo "ERROR: Root directory does not exist: ${ROOT_DIR}" >&2
        exit 1
    fi
    if [[ -z "${ROOT_PART}" ]] || [[ -z "${HASH_PART}" ]]; then
        echo "ERROR: --disk is required" >&2
        usage
    fi
    for dev in "${ROOT_PART}" "${HASH_PART}"; do
        if [[ ! -b "${dev}" ]]; then
            echo "ERROR: Block device not found: ${dev}" >&2
            exit 1
        fi
    done
    for cmd in veritysetup mkfs.ext4 openssl; do
        command -v "${cmd}" >/dev/null 2>&1 || {
            echo "ERROR: Required tool not found: ${cmd}" >&2
            exit 1
        }
    done
}

validate_verify() {
    if [[ -z "${ROOT_PART}" ]] || [[ -z "${HASH_PART}" ]]; then
        echo "ERROR: --disk is required for verify mode" >&2
        usage
    fi
    if [[ -z "${ROOT_HASH_VERIFY}" ]]; then
        echo "ERROR: --root-hash is required for verify mode" >&2
        usage
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Create ext4 root filesystem image
# ---------------------------------------------------------------------------
create_rootfs() {
    echo "=== Creating ext4 root filesystem on ${ROOT_PART} ==="

    # Format root partition as ext4 with security-focused mount options
    # -O ^huge_file,^dir_nlink: disable features we don't need
    # -O metadata_csum: enable metadata checksums for corruption detection
    mkfs.ext4 \
        -L "milnet-root" \
        -O metadata_csum,^huge_file \
        -m 0 \
        -b "${BLOCK_SIZE}" \
        "${ROOT_PART}"

    # Mount and populate root filesystem
    local mnt_root
    mnt_root=$(mktemp -d /tmp/milnet-root.XXXXXX)

    mount "${ROOT_PART}" "${mnt_root}"

    echo "  Copying root filesystem contents..."
    # Use rsync for accurate permission/ownership preservation
    rsync -aAX --info=progress2 "${ROOT_DIR}/" "${mnt_root}/"

    # Set immutable attribute on critical files
    echo "  Setting immutable attributes on critical binaries..."
    for bin in \
        "${mnt_root}/usr/local/bin/milnet-"* \
        "${mnt_root}/sbin/init" \
        "${mnt_root}/usr/bin/postgresql"*; do
        if [[ -f "${bin}" ]]; then
            chattr +i "${bin}" 2>/dev/null || true
        fi
    done

    # Remove anything that shouldn't be on a read-only root
    rm -rf "${mnt_root}/tmp/"* "${mnt_root}/var/tmp/"* 2>/dev/null || true

    # Ensure /etc/milnet points to data partition (will be bind-mounted)
    mkdir -p "${mnt_root}/etc/milnet"
    mkdir -p "${mnt_root}/var/lib/milnet"
    mkdir -p "${mnt_root}/var/lib/postgresql"
    mkdir -p "${mnt_root}/var/log"

    # Create fstab for the verified system
    cat > "${mnt_root}/etc/fstab" <<'FSTAB'
# MILNET SSO — Filesystem Table
# Root is dm-verity (mounted by initramfs, read-only)
# Data is LUKS2+ext4 (mounted by initramfs, encrypted)
#
# <device>                   <mount>              <type>  <options>                    <dump> <pass>
/dev/mapper/verity-root      /                    ext4    ro,noatime                   0      1
/dev/mapper/milnet-data      /var/lib/milnet      ext4    nosuid,nodev,noatime         0      2
tmpfs                        /tmp                 tmpfs   nosuid,nodev,noexec,size=1G  0      0
tmpfs                        /run                 tmpfs   nosuid,nodev,noexec,size=64M 0      0
FSTAB

    sync
    umount "${mnt_root}"
    rmdir "${mnt_root}"

    echo "  Root filesystem created and populated."
}

# ---------------------------------------------------------------------------
# Step 2: Generate dm-verity hash tree
# ---------------------------------------------------------------------------
generate_verity() {
    echo "=== Generating dm-verity hash tree ==="
    mkdir -p "${OUTPUT_DIR}"

    # veritysetup format creates the Merkle hash tree on HASH_PART
    # and outputs the root hash.
    #
    # Options:
    #   --data-block-size=4096: match filesystem block size
    #   --hash-block-size=4096: match filesystem block size
    #   --hash=sha256: collision-resistant hash for block verification
    #   --salt=random: per-image salt prevents rainbow table attacks
    #   --format=1: verity format version 1

    local verity_output
    verity_output=$(veritysetup format \
        --data-block-size="${BLOCK_SIZE}" \
        --hash-block-size="${BLOCK_SIZE}" \
        --hash=sha256 \
        --format=1 \
        "${ROOT_PART}" \
        "${HASH_PART}" 2>&1)

    echo "${verity_output}"

    # Extract root hash and salt from veritysetup output
    ROOT_HASH=$(echo "${verity_output}" | grep "Root hash:" | awk '{print $NF}')
    SALT=$(echo "${verity_output}" | grep "Salt:" | awk '{print $NF}')
    DATA_BLOCKS=$(echo "${verity_output}" | grep "Data blocks:" | awk '{print $NF}')
    DATA_BLOCK_SIZE=$(echo "${verity_output}" | grep "Data block size:" | awk '{print $NF}')
    HASH_BLOCK_SIZE=$(echo "${verity_output}" | grep "Hash block size:" | awk '{print $NF}')
    UUID=$(echo "${verity_output}" | grep "UUID:" | awk '{print $NF}')

    if [[ -z "${ROOT_HASH}" ]]; then
        echo "ERROR: Failed to extract root hash from veritysetup output" >&2
        exit 1
    fi

    echo ""
    echo "  ROOT HASH: ${ROOT_HASH}"
    echo "  SALT:      ${SALT}"
    echo "  BLOCKS:    ${DATA_BLOCKS}"
    echo "  UUID:      ${UUID}"

    # Save verity parameters for boot configuration
    cat > "${OUTPUT_DIR}/verity-params.env" <<PARAMS
# dm-verity parameters — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# PROTECT THIS FILE — root hash is the trust anchor
VERITY_ROOT_HASH="${ROOT_HASH}"
VERITY_SALT="${SALT}"
VERITY_DATA_BLOCKS="${DATA_BLOCKS}"
VERITY_DATA_BLOCK_SIZE="${DATA_BLOCK_SIZE}"
VERITY_HASH_BLOCK_SIZE="${HASH_BLOCK_SIZE}"
VERITY_UUID="${UUID}"
VERITY_ROOT_PART="${ROOT_PART}"
VERITY_HASH_PART="${HASH_PART}"
VERITY_ALGORITHM="sha256"
PARAMS

    echo "  Parameters saved to ${OUTPUT_DIR}/verity-params.env"
}

# ---------------------------------------------------------------------------
# Step 3: Sign the root hash
# ---------------------------------------------------------------------------
sign_root_hash() {
    echo "=== Signing root hash ==="

    if [[ ! -f "${SIGN_KEY}" ]] || [[ ! -f "${SIGN_CERT}" ]]; then
        echo "  WARNING: Signing keys not found. Skipping signature."
        echo "  Expected: ${SIGN_KEY} and ${SIGN_CERT}"
        echo "  Root hash signing is REQUIRED for production."
        return
    fi

    # Create a file containing the root hash for signing
    echo -n "${ROOT_HASH}" > "${OUTPUT_DIR}/root-hash.txt"

    # Sign root hash with PKCS#7 (detached signature)
    # This signature is verified by the kernel's dm-verity signature
    # verification (CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG)
    openssl smime -sign \
        -inkey "${SIGN_KEY}" \
        -signer "${SIGN_CERT}" \
        -binary \
        -in "${OUTPUT_DIR}/root-hash.txt" \
        -outform der \
        -out "${OUTPUT_DIR}/root-hash.p7s" \
        -noattr

    echo "  Root hash signature: ${OUTPUT_DIR}/root-hash.p7s"

    # Verify the signature immediately
    openssl smime -verify \
        -binary \
        -in "${OUTPUT_DIR}/root-hash.p7s" \
        -inform der \
        -content "${OUTPUT_DIR}/root-hash.txt" \
        -certfile "${SIGN_CERT}" \
        -nointern \
        -noverify \
        > /dev/null 2>&1 && \
        echo "  VERIFIED: Root hash signature is valid." || {
        echo "  ERROR: Root hash signature verification FAILED!" >&2
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Step 4: Generate kernel command line with verity parameters
# ---------------------------------------------------------------------------
generate_boot_entry() {
    echo "=== Generating boot configuration ==="

    local root_sectors
    root_sectors=$(blockdev --getsz "${ROOT_PART}" 2>/dev/null || echo "UNKNOWN")

    # Generate the kernel command line with dm-verity parameters
    cat > "${OUTPUT_DIR}/cmdline.txt" <<CMDLINE
root=/dev/mapper/verity-root ro milnet.roothash=${ROOT_HASH} milnet.salt=${SALT} lockdown=confidentiality init=/sbin/init quiet loglevel=3 mitigations=auto,nosmt mce=0 vsyscall=none slab_nomerge init_on_alloc=1 init_on_free=1 iommu=force randomize_kstack_offset=on spec_store_bypass_disable=on tsx=off nosmt
CMDLINE

    echo "  Boot command line: ${OUTPUT_DIR}/cmdline.txt"

    # Generate systemd-boot entry
    cat > "${OUTPUT_DIR}/milnet.conf" <<BOOTENTRY
# systemd-boot entry for MILNET SSO
# Install to ESP: /loader/entries/milnet.conf
title   MILNET SSO System
linux   /milnet-kernel.efi
initrd  /milnet-initramfs.img
options root=/dev/mapper/verity-root ro milnet.roothash=${ROOT_HASH} milnet.salt=${SALT} lockdown=confidentiality init=/sbin/init quiet loglevel=3 mitigations=auto,nosmt mce=0 vsyscall=none slab_nomerge init_on_alloc=1 init_on_free=1 iommu=force randomize_kstack_offset=on spec_store_bypass_disable=on tsx=off nosmt
BOOTENTRY

    echo "  Boot entry: ${OUTPUT_DIR}/milnet.conf"
}

# ---------------------------------------------------------------------------
# Step 5: Verify existing dm-verity setup
# ---------------------------------------------------------------------------
verify_verity() {
    echo "=== Verifying dm-verity integrity ==="

    if [[ -z "${ROOT_HASH_VERIFY}" ]]; then
        echo "ERROR: Root hash required for verification" >&2
        exit 1
    fi

    echo "  Verifying ${ROOT_PART} against hash tree on ${HASH_PART}..."
    echo "  Expected root hash: ${ROOT_HASH_VERIFY}"

    veritysetup verify \
        "${ROOT_PART}" \
        "${HASH_PART}" \
        "${ROOT_HASH_VERIFY}" && {
        echo ""
        echo "  VERIFICATION PASSED: Root filesystem integrity confirmed."
        echo "  All blocks match the Merkle hash tree."
    } || {
        echo ""
        echo "  VERIFICATION FAILED: Root filesystem has been TAMPERED WITH!" >&2
        echo "  Do NOT boot this system. Re-image from a trusted source." >&2
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Step 6: Set up LUKS2 encrypted data partition
# ---------------------------------------------------------------------------
setup_data_partition() {
    echo "=== Setting up LUKS2 encrypted data partition ==="

    if [[ -z "${DATA_PART}" ]] || [[ ! -b "${DATA_PART}" ]]; then
        echo "  WARNING: Data partition ${DATA_PART} not found. Skipping."
        return
    fi

    # Check if already formatted as LUKS
    if cryptsetup isLuks "${DATA_PART}" 2>/dev/null; then
        echo "  Data partition already formatted as LUKS. Skipping format."
        return
    fi

    echo "  Formatting ${DATA_PART} as LUKS2..."
    echo ""
    echo "  *** WARNING: This will DESTROY all data on ${DATA_PART} ***"
    echo "  Press Ctrl+C within 10 seconds to abort."
    sleep 10

    # Generate a random key for LUKS
    local luks_key
    luks_key=$(mktemp /tmp/milnet-luks-key.XXXXXX)
    chmod 600 "${luks_key}"
    dd if=/dev/urandom of="${luks_key}" bs=64 count=1 2>/dev/null

    # Format with LUKS2 using Argon2id KDF (memory-hard, resists GPU cracking)
    cryptsetup luksFormat \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --hash sha512 \
        --pbkdf argon2id \
        --pbkdf-memory 1048576 \
        --pbkdf-parallel 4 \
        --pbkdf-force-iterations 4 \
        --label "milnet-data" \
        --batch-mode \
        --key-file "${luks_key}" \
        "${DATA_PART}"

    # Open the LUKS volume
    cryptsetup luksOpen \
        --key-file "${luks_key}" \
        "${DATA_PART}" milnet-data

    # Create ext4 filesystem on the encrypted volume
    mkfs.ext4 \
        -L "milnet-data" \
        -O metadata_csum \
        -m 1 \
        /dev/mapper/milnet-data

    # Create directory structure
    local mnt_data
    mnt_data=$(mktemp -d /tmp/milnet-data.XXXXXX)
    mount /dev/mapper/milnet-data "${mnt_data}"

    mkdir -p "${mnt_data}/postgresql/16/main"
    mkdir -p "${mnt_data}/milnet/config"
    mkdir -p "${mnt_data}/milnet/state"
    mkdir -p "${mnt_data}/milnet/audit-log"
    mkdir -p "${mnt_data}/milnet/tls"

    # Set ownership (PostgreSQL runs as uid 26, MILNET services as uid 1000)
    chown -R 26:26 "${mnt_data}/postgresql"
    chown -R 1000:1000 "${mnt_data}/milnet"
    chmod 700 "${mnt_data}/postgresql"
    chmod 700 "${mnt_data}/milnet/tls"
    chmod 750 "${mnt_data}/milnet"

    sync
    umount "${mnt_data}"
    rmdir "${mnt_data}"
    cryptsetup luksClose milnet-data

    echo ""
    echo "  Now seal the LUKS key to TPM2 PCRs:"
    echo "    tpm2_createprimary -C o -c primary.ctx"
    echo "    tpm2_create -C primary.ctx -i ${luks_key} \\"
    echo "      -u sealed.pub -r sealed.priv \\"
    echo "      -L 'sha256:0,2,4,7'"
    echo "    tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx"
    echo "    tpm2_evictcontrol -C o -c sealed.ctx 0x81000001"
    echo ""
    echo "  Then SECURELY DELETE the key file:"
    echo "    shred -vfz -n 10 ${luks_key}"

    echo "  Data partition setup complete."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo "================================================================"
    echo " MILNET SSO — dm-verity Immutable Root Filesystem Setup"
    echo " Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "================================================================"
    echo ""

    case "${MODE}" in
        create)
            validate_create
            create_rootfs
            generate_verity
            sign_root_hash
            generate_boot_entry
            setup_data_partition

            echo ""
            echo "================================================================"
            echo " dm-verity SETUP COMPLETE"
            echo ""
            echo " ROOT HASH: ${ROOT_HASH}"
            echo " This value is your root of trust for the filesystem."
            echo " Store it securely and embed it in the boot configuration."
            echo ""
            echo " Output files: ${OUTPUT_DIR}/"
            echo "   verity-params.env  — Verity parameters"
            echo "   root-hash.txt      — Root hash (plaintext)"
            echo "   root-hash.p7s      — Root hash signature (PKCS#7)"
            echo "   cmdline.txt        — Kernel command line"
            echo "   milnet.conf        — systemd-boot entry"
            echo "================================================================"
            ;;
        verify)
            validate_verify
            verify_verity
            ;;
    esac
}

main
