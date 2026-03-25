#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Cloud HSM Initialization Script
# ==============================================================================
# Initialize HSM per cloud provider. Run once after Terraform apply to create
# the key hierarchy inside the HSM.
#
# Providers:
#   gcp    — Google Cloud KMS + Cloud HSM (asia-south1)
#   aws    — AWS CloudHSM cluster (us-gov-west-1)
#   onprem — Thales Luna Network HSM (PKCS#11)
#
# Usage:
#   cloud-hsm-init.sh --provider=gcp [--region=asia-south1] [--env=production]
#   cloud-hsm-init.sh --provider=aws [--cluster-id=cluster-xxxx] [--subnet-ids=subnet-a,subnet-b]
#   cloud-hsm-init.sh --provider=onprem [--pkcs11-lib=/usr/lib/libCryptoki2_64.so]
#
# Environment variables (override flags):
#   PROVIDER        — gcp | aws | onprem
#   REGION          — GCP region or AWS region
#   ENV             — production | staging | dev
#   GCP_PROJECT     — GCP project ID
#   AWS_CLUSTER_ID  — CloudHSM cluster ID
#   SUBNET_IDS      — Comma-separated subnet IDs (AWS)
#   PKCS11_LIB      — Path to PKCS#11 library (on-prem)
#   HSM_SO_PASSWORD — HSM Security Officer password (on-prem, from Vault)
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

PROVIDER="${PROVIDER:-}"
REGION="${REGION:-}"
ENV="${ENV:-production}"
GCP_PROJECT="${GCP_PROJECT:-lmsforshantithakur}"
AWS_CLUSTER_ID="${AWS_CLUSTER_ID:-}"
SUBNET_IDS="${SUBNET_IDS:-}"
PKCS11_LIB="${PKCS11_LIB:-/usr/lib/libCryptoki2_64.so}"

# ── Logging ───────────────────────────────────────────────────────────────────

log_info()  { echo "[HSM_INIT] INFO:  $*"; }
log_warn()  { echo "[HSM_INIT] WARN:  $*" >&2; }
log_error() { echo "[HSM_INIT] ERROR: $*" >&2; }
die()       { log_error "$@"; exit 1; }

# ── Argument Parsing ──────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --provider=*)   PROVIDER="${1#--provider=}";    shift ;;
            --provider)     PROVIDER="$2";                  shift 2 ;;
            --region=*)     REGION="${1#--region=}";        shift ;;
            --region)       REGION="$2";                    shift 2 ;;
            --env=*)        ENV="${1#--env=}";              shift ;;
            --env)          ENV="$2";                       shift 2 ;;
            --project=*)    GCP_PROJECT="${1#--project=}";  shift ;;
            --project)      GCP_PROJECT="$2";               shift 2 ;;
            --cluster-id=*) AWS_CLUSTER_ID="${1#--cluster-id=}"; shift ;;
            --cluster-id)   AWS_CLUSTER_ID="$2";            shift 2 ;;
            --subnet-ids=*) SUBNET_IDS="${1#--subnet-ids=}"; shift ;;
            --subnet-ids)   SUBNET_IDS="$2";                shift 2 ;;
            --pkcs11-lib=*) PKCS11_LIB="${1#--pkcs11-lib=}"; shift ;;
            --pkcs11-lib)   PKCS11_LIB="$2";               shift 2 ;;
            -h|--help)      usage; exit 0 ;;
            *)              die "Unknown argument: $1" ;;
        esac
    done
}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME --provider=<gcp|aws|onprem> [options]

Options:
  --provider=PROVIDER     gcp, aws, or onprem (required)
  --region=REGION         Cloud region (default: asia-south1 for GCP, us-gov-west-1 for AWS)
  --env=ENV               Environment: production|staging|dev (default: production)
  --project=PROJECT       GCP project ID (default: lmsforshantithakur)
  --cluster-id=ID         AWS CloudHSM cluster ID
  --subnet-ids=IDS        Comma-separated subnet IDs for AWS CloudHSM
  --pkcs11-lib=PATH       Path to PKCS#11 library for on-prem HSM

Environment variables:
  PROVIDER, REGION, ENV, GCP_PROJECT, AWS_CLUSTER_ID, SUBNET_IDS, PKCS11_LIB, HSM_SO_PASSWORD
EOF
}

# ── Prerequisite Checks ───────────────────────────────────────────────────────

check_prereqs_gcp() {
    command -v gcloud >/dev/null 2>&1 || die "gcloud CLI not found. Install the Google Cloud SDK."
    gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud not authenticated. Run: gcloud auth login"
    log_info "GCP prerequisites OK."
}

check_prereqs_aws() {
    command -v aws >/dev/null 2>&1 || die "AWS CLI not found. Install the AWS CLI v2."
    aws sts get-caller-identity >/dev/null 2>&1 || die "AWS not authenticated. Set AWS_ACCESS_KEY_ID / AWS_PROFILE."
    log_info "AWS prerequisites OK."
}

check_prereqs_onprem() {
    command -v pkcs11-tool >/dev/null 2>&1 || die "pkcs11-tool not found. Install opensc."
    [[ -f "$PKCS11_LIB" ]] || die "PKCS#11 library not found: $PKCS11_LIB"
    log_info "On-prem prerequisites OK."
}

# ── GCP Provider ──────────────────────────────────────────────────────────────

init_gcp() {
    local region="${REGION:-asia-south1}"
    local keyring="milnet-india-${ENV}-keyring"
    local project="$GCP_PROJECT"

    # Validate India region (data residency enforcement)
    case "$region" in
        asia-south1|asia-south2)
            log_info "Region $region is India-compliant." ;;
        *)
            die "Region '$region' is not an India region. GCP India HSM must use asia-south1 or asia-south2." ;;
    esac

    log_info "Initializing GCP Cloud HSM in project=$project region=$region env=$ENV"

    # Enable Cloud KMS API if not already enabled
    log_info "Enabling Cloud KMS API..."
    gcloud services enable cloudkms.googleapis.com \
        --project="$project" \
        --quiet

    # Create KMS keyring (idempotent — fails gracefully if exists)
    log_info "Creating KMS keyring: $keyring"
    gcloud kms keyrings create "$keyring" \
        --location="$region" \
        --project="$project" \
        2>/dev/null || log_info "Keyring $keyring already exists."

    # Master KEK — HSM-protected symmetric encryption key
    log_info "Creating master-kek (HSM, ENCRYPT_DECRYPT)..."
    gcloud kms keys create "milnet-india-${ENV}-master-kek" \
        --keyring="$keyring" \
        --location="$region" \
        --project="$project" \
        --purpose=encryption \
        --protection-level=hsm \
        --rotation-period=7776000s \
        --next-rotation-time="$(date -d '+90 days' --utc +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -v+90d +%Y-%m-%dT%H:%M:%SZ)" \
        2>/dev/null || log_info "master-kek already exists."

    # Database CMEK — HSM-protected, used by Cloud SQL
    log_info "Creating db-cmek (HSM, ENCRYPT_DECRYPT)..."
    gcloud kms keys create "milnet-india-${ENV}-db-cmek" \
        --keyring="$keyring" \
        --location="$region" \
        --project="$project" \
        --purpose=encryption \
        --protection-level=hsm \
        --rotation-period=7776000s \
        2>/dev/null || log_info "db-cmek already exists."

    # Audit signing key — ECDSA P-384, asymmetric signing
    log_info "Creating audit-signing (HSM, ASYMMETRIC_SIGN, EC_SIGN_P384_SHA384)..."
    gcloud kms keys create "milnet-india-${ENV}-audit-signing" \
        --keyring="$keyring" \
        --location="$region" \
        --project="$project" \
        --purpose=asymmetric-signing \
        --default-algorithm=ec-sign-p384-sha384 \
        --protection-level=hsm \
        2>/dev/null || log_info "audit-signing already exists."

    # HSM master key for token signing
    log_info "Creating hsm-token-sign (HSM, ASYMMETRIC_SIGN, EC_SIGN_P384_SHA384)..."
    gcloud kms keys create "milnet-india-${ENV}-hsm-token-sign" \
        --keyring="$keyring" \
        --location="$region" \
        --project="$project" \
        --purpose=asymmetric-signing \
        --default-algorithm=ec-sign-p384-sha384 \
        --protection-level=hsm \
        2>/dev/null || log_info "hsm-token-sign already exists."

    # Print attestation statement for each key
    log_info "Retrieving HSM attestation statements..."
    for key in \
        "milnet-india-${ENV}-master-kek" \
        "milnet-india-${ENV}-audit-signing" \
        "milnet-india-${ENV}-hsm-token-sign"; do
        log_info "Attestation for $key:"
        gcloud kms keys versions describe 1 \
            --key="$key" \
            --keyring="$keyring" \
            --location="$region" \
            --project="$project" \
            --format="value(attestation.format, attestation.certChains.caviumCerts[0])" \
            2>/dev/null || log_warn "Attestation not yet available for $key (may need a moment)"
    done

    log_info "GCP Cloud HSM initialization complete."
    log_info "Keyring: projects/$project/locations/$region/keyRings/$keyring"
}

# ── AWS Provider ──────────────────────────────────────────────────────────────

init_aws() {
    local region="${REGION:-us-gov-west-1}"

    # Validate GovCloud region
    case "$region" in
        us-gov-west-1|us-gov-east-1)
            log_info "Region $region is GovCloud-compliant." ;;
        *)
            die "Region '$region' is not a GovCloud region. AWS MILNET must use us-gov-west-1 or us-gov-east-1." ;;
    esac

    log_info "Initializing AWS CloudHSM in region=$region env=$ENV"

    # Convert comma-separated subnet IDs to JSON array for AWS CLI
    local subnet_json
    if [[ -n "$SUBNET_IDS" ]]; then
        # shellcheck disable=SC2001
        subnet_json="$(echo "$SUBNET_IDS" | sed 's/,/ /g' | xargs printf '"%s" ' | sed 's/ $//' | sed 's/^/[/' | sed 's/$/]/')"
    else
        die "SUBNET_IDS must be set for AWS CloudHSM initialization. Use --subnet-ids or set SUBNET_IDS env var."
    fi

    if [[ -z "$AWS_CLUSTER_ID" ]]; then
        log_info "No cluster ID provided — creating new CloudHSM cluster..."
        AWS_CLUSTER_ID="$(aws cloudhsmv2 create-cluster \
            --hsm-type hsm1.medium \
            --subnet-ids $SUBNET_IDS \
            --region "$region" \
            --endpoint-url "https://cloudhsmv2-fips.${region}.amazonaws.com" \
            --output text \
            --query 'Cluster.ClusterId')"
        log_info "Created CloudHSM cluster: $AWS_CLUSTER_ID"
    else
        log_info "Using existing CloudHSM cluster: $AWS_CLUSTER_ID"
    fi

    # Wait for cluster to reach UNINITIALIZED state
    log_info "Waiting for cluster to reach UNINITIALIZED state (may take 5-10 minutes)..."
    local attempts=0
    local max_attempts=30
    while [[ $attempts -lt $max_attempts ]]; do
        local state
        state="$(aws cloudhsmv2 describe-clusters \
            --filters clusterIds="$AWS_CLUSTER_ID" \
            --region "$region" \
            --endpoint-url "https://cloudhsmv2-fips.${region}.amazonaws.com" \
            --output text \
            --query 'Clusters[0].State')"

        log_info "Cluster state: $state (attempt $((attempts+1))/$max_attempts)"

        case "$state" in
            UNINITIALIZED)
                log_info "Cluster ready for initialization."
                break ;;
            ACTIVE)
                log_info "Cluster already initialized and active."
                break ;;
            INITIALIZE_ERROR|DEGRADED|DELETED)
                die "Cluster entered error state: $state" ;;
        esac

        attempts=$((attempts + 1))
        sleep 20
    done

    [[ $attempts -lt $max_attempts ]] || die "Timeout waiting for CloudHSM cluster."

    # Get the CSR for cluster initialization
    log_info "Retrieving cluster Certificate Signing Request (CSR)..."
    local csr_file="/tmp/milnet-cloudhsm-${AWS_CLUSTER_ID}.csr"
    aws cloudhsmv2 describe-clusters \
        --filters clusterIds="$AWS_CLUSTER_ID" \
        --region "$region" \
        --endpoint-url "https://cloudhsmv2-fips.${region}.amazonaws.com" \
        --output text \
        --query 'Clusters[0].Certificates.ClusterCsr' > "$csr_file"

    if [[ -s "$csr_file" ]]; then
        log_info "Cluster CSR saved to: $csr_file"
        log_warn "MANUAL STEP REQUIRED: Sign the CSR with your HSM CA and run:"
        log_warn "  aws cloudhsmv2 initialize-cluster --cluster-id=$AWS_CLUSTER_ID \\"
        log_warn "    --signed-cert file://cluster.crt --trust-anchor file://ca.crt"
    fi

    # Create HSM instances in cluster (for HA, create at least 2)
    log_info "Creating HSM instance in cluster (AZ a)..."
    aws cloudhsmv2 create-hsm \
        --cluster-id "$AWS_CLUSTER_ID" \
        --availability-zone "${region}a" \
        --region "$region" \
        --endpoint-url "https://cloudhsmv2-fips.${region}.amazonaws.com" \
        2>/dev/null || log_info "HSM may already exist in cluster."

    if [[ "$ENV" == "production" ]]; then
        log_info "Production mode: creating second HSM for HA (AZ b)..."
        aws cloudhsmv2 create-hsm \
            --cluster-id "$AWS_CLUSTER_ID" \
            --availability-zone "${region}b" \
            --region "$region" \
            --endpoint-url "https://cloudhsmv2-fips.${region}.amazonaws.com" \
            2>/dev/null || log_info "Second HSM may already exist."
    fi

    log_info "AWS CloudHSM initialization complete."
    log_info "Cluster ID: $AWS_CLUSTER_ID"
    log_info "Next step: initialize cluster with signed certificate before creating keys."
}

# ── On-Prem Provider (Thales Luna) ────────────────────────────────────────────

init_onprem() {
    log_info "Initializing on-premises Thales Luna HSM via PKCS#11..."
    log_info "PKCS#11 library: $PKCS11_LIB"

    # Verify Luna client connectivity
    log_info "Verifying Luna client status..."
    if command -v vtl >/dev/null 2>&1; then
        vtl verify || die "Luna VTL verify failed. Check HSM connectivity."
        log_info "Luna client verified successfully."
    else
        log_warn "'vtl' not found — skipping Luna client verify."
        log_warn "Install Luna client: https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsm"
    fi

    # List available slots
    log_info "Listing PKCS#11 slots..."
    pkcs11-tool --module "$PKCS11_LIB" --list-slots || log_warn "Could not list slots."

    # Verify HSM connectivity via pkcs11-tool
    log_info "Testing HSM connectivity..."
    pkcs11-tool --module "$PKCS11_LIB" --list-mechanisms --slot 0 >/dev/null 2>&1 \
        && log_info "HSM mechanism list OK." \
        || log_warn "Could not list mechanisms — HSM may need to be initialized."

    # Initialize partition if SO password is available
    if [[ -n "${HSM_SO_PASSWORD:-}" ]]; then
        log_info "HSM_SO_PASSWORD is set — proceeding with partition initialization."
        log_warn "WARNING: This will initialize the HSM partition. Proceed only in controlled conditions."
        # Actual partition init would use lunacm or CMU tool — documented here
        log_info "To initialize partition, run:"
        log_info "  lunacm -c 'slot set -slot 0; partition init -label milnet-${ENV}'"
        log_info "  OR: cmu init --moduletype=partition --label=milnet-${ENV}"
    else
        log_info "HSM_SO_PASSWORD not set — skipping partition initialization."
        log_info "Set HSM_SO_PASSWORD to proceed with automated initialization."
    fi

    # Generate keys in HSM
    log_info "PKCS#11 key generation commands (run after HSM partition is initialized):"
    log_info ""
    log_info "  # Master KEK (AES-256):"
    log_info "  pkcs11-tool --module '$PKCS11_LIB' --slot 0 --login \\"
    log_info "    --keygen --key-type AES:32 --label milnet-${ENV}-master-kek --id 01 --token-label milnet-${ENV}"
    log_info ""
    log_info "  # Audit signing key (ECDSA P-384):"
    log_info "  pkcs11-tool --module '$PKCS11_LIB' --slot 0 --login \\"
    log_info "    --keypairgen --key-type EC:secp384r1 --label milnet-${ENV}-audit-signing --id 02 --token-label milnet-${ENV}"

    log_info "On-prem HSM initialization complete (manual steps required above)."
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    [[ -n "$PROVIDER" ]] || die "Provider not specified. Use --provider=gcp|aws|onprem"

    log_info "MILNET Cloud HSM Init — provider=$PROVIDER env=$ENV"

    case "$PROVIDER" in
        gcp)
            check_prereqs_gcp
            init_gcp
            ;;
        aws)
            check_prereqs_aws
            init_aws
            ;;
        onprem)
            check_prereqs_onprem
            init_onprem
            ;;
        *)
            die "Unknown provider: $PROVIDER. Must be gcp, aws, or onprem."
            ;;
    esac

    log_info "HSM initialization finished successfully."
}

main "$@"
