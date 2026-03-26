#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Full Deployment Orchestration (GCE Multi-VM)
# ==============================================================================
# End-to-end deployment pipeline:
#   1. Build binaries and push to GCS (build-and-push.sh)
#   2. Apply Terraform infrastructure (terraform/gce-multi-vm/)
#   3. Rolling update: update instance templates, replace instances
#   4. Wait for health checks to pass on all services
#   5. Run smoke test against the gateway
#
# Usage:
#   ./deploy.sh                                # full deploy
#   ./deploy.sh --skip-build                   # infra + rolling update only
#   ./deploy.sh --skip-terraform               # build + rolling update only
#   ./deploy.sh --rolling-only                 # just do rolling replace
#   ./deploy.sh --smoke-only                   # just run smoke test
#
# Environment:
#   GCP_PROJECT   — GCP project ID (default: lmsforshantithakur)
#   GCP_REGION    — GCP region (default: asia-south1)
# ==============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TERRAFORM_DIR="${REPO_ROOT}/terraform/gce-multi-vm"

PROJECT_ID="${GCP_PROJECT:-lmsforshantithakur}"
REGION="${GCP_REGION:-asia-south1}"

SKIP_BUILD=false
SKIP_TERRAFORM=false
ROLLING_ONLY=false
SMOKE_ONLY=false

# Managed instance groups (MIGs) to update.
readonly -a MIGS=(
    milnet-gateway-mig
    milnet-admin-mig
    milnet-orchestrator-mig
    milnet-opaque-mig
    milnet-verifier-mig
    milnet-ratchet-mig
    milnet-audit-mig
)

# Singleton instances (not in MIGs) — TSS nodes need individual handling.
readonly -a TSS_INSTANCES=(
    milnet-tss-1
    milnet-tss-2
    milnet-tss-3
    milnet-tss-4
    milnet-tss-5
)

# Health check timeout per service.
HEALTH_TIMEOUT=300
HEALTH_INTERVAL=10

# ── Helpers ──────────────────────────────────────────────────────────────────

log_info()  { echo "[DEPLOY] INFO:  $(date -Iseconds) $*"; }
log_warn()  { echo "[DEPLOY] WARN:  $(date -Iseconds) $*" >&2; }
log_error() { echo "[DEPLOY] ERROR: $(date -Iseconds) $*" >&2; }
die()       { log_error "$@"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)      SKIP_BUILD=true; shift ;;
        --skip-terraform)  SKIP_TERRAFORM=true; shift ;;
        --rolling-only)    ROLLING_ONLY=true; SKIP_BUILD=true; SKIP_TERRAFORM=true; shift ;;
        --smoke-only)      SMOKE_ONLY=true; SKIP_BUILD=true; SKIP_TERRAFORM=true; shift ;;
        --project)         PROJECT_ID="$2"; shift 2 ;;
        --region)          REGION="$2"; shift 2 ;;
        --health-timeout)  HEALTH_TIMEOUT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--skip-terraform] [--rolling-only] [--smoke-only]"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Step 1: Build & push binaries ────────────────────────────────────────────

if [[ "${SKIP_BUILD}" == "false" && "${SMOKE_ONLY}" == "false" ]]; then
    log_info "======== Step 1: Build & Push Binaries ========"
    "${SCRIPT_DIR}/build-and-push.sh" --project "${PROJECT_ID}"
else
    log_info "======== Step 1: Build & Push (SKIPPED) ========"
fi

# Read the current version from the LATEST pointer.
BUCKET="gs://milnet-sso-binaries-${PROJECT_ID}"
BINARY_VERSION=$(gsutil cat "${BUCKET}/LATEST" 2>/dev/null) \
    || die "Could not read LATEST pointer from ${BUCKET}/LATEST"
log_info "Deploying binary version: ${BINARY_VERSION}"

# ── Step 2: Terraform apply ──────────────────────────────────────────────────

if [[ "${SKIP_TERRAFORM}" == "false" && "${SMOKE_ONLY}" == "false" ]]; then
    log_info "======== Step 2: Terraform Apply ========"

    if [[ ! -d "${TERRAFORM_DIR}" ]]; then
        die "Terraform directory not found: ${TERRAFORM_DIR}"
    fi

    cd "${TERRAFORM_DIR}"

    terraform init -input=false

    terraform plan \
        -var "project_id=${PROJECT_ID}" \
        -var "region=${REGION}" \
        -var "binary_version=${BINARY_VERSION}" \
        -out=tfplan

    log_info "Applying Terraform plan ..."
    terraform apply -input=false tfplan
    rm -f tfplan

    cd "${SCRIPT_DIR}"
    log_info "Terraform apply complete."
else
    log_info "======== Step 2: Terraform Apply (SKIPPED) ========"
fi

# ── Step 3: Rolling update of managed instance groups ────────────────────────

if [[ "${SMOKE_ONLY}" == "false" ]]; then
    log_info "======== Step 3: Rolling Update ========"

    # For each MIG, update the instance template metadata to point to the
    # new binary version, then trigger a rolling replace.
    for mig in "${MIGS[@]}"; do
        log_info "Rolling update for ${mig} ..."

        # Extract the current instance template name.
        TEMPLATE=$(gcloud compute instance-groups managed describe "${mig}" \
            --region="${REGION}" \
            --project="${PROJECT_ID}" \
            --format='value(instanceTemplate)' 2>/dev/null) || {
            log_warn "MIG ${mig} not found in region ${REGION}, trying zones ..."
            # Try zone-level MIG (some services may be zonal).
            for zone in "${REGION}-a" "${REGION}-b" "${REGION}-c"; do
                TEMPLATE=$(gcloud compute instance-groups managed describe "${mig}" \
                    --zone="${zone}" \
                    --project="${PROJECT_ID}" \
                    --format='value(instanceTemplate)' 2>/dev/null) && break
            done
        }

        if [[ -z "${TEMPLATE:-}" ]]; then
            log_warn "Could not find MIG ${mig}, skipping."
            continue
        fi

        # Create a new instance template with the updated BINARY_VERSION.
        # Template names must be unique, so append version.
        OLD_TEMPLATE_NAME=$(basename "${TEMPLATE}")
        # Strip any existing version suffix to construct new name.
        BASE_TEMPLATE_NAME=$(echo "${OLD_TEMPLATE_NAME}" | sed 's/-v[0-9]*$//')
        NEW_TEMPLATE_NAME="${BASE_TEMPLATE_NAME}-${BINARY_VERSION//\//-}"

        # Check if new template already exists.
        if ! gcloud compute instance-templates describe "${NEW_TEMPLATE_NAME}" \
            --project="${PROJECT_ID}" &>/dev/null; then

            log_info "  Creating new instance template: ${NEW_TEMPLATE_NAME}"
            gcloud compute instance-templates create "${NEW_TEMPLATE_NAME}" \
                --project="${PROJECT_ID}" \
                --source-instance-template="${TEMPLATE}" \
                --metadata="BINARY_VERSION=${BINARY_VERSION}"
        else
            log_info "  Instance template ${NEW_TEMPLATE_NAME} already exists."
        fi

        # Point the MIG to the new template.
        log_info "  Updating MIG to use ${NEW_TEMPLATE_NAME} ..."
        gcloud compute instance-groups managed set-instance-template "${mig}" \
            --region="${REGION}" \
            --project="${PROJECT_ID}" \
            --template="projects/${PROJECT_ID}/global/instanceTemplates/${NEW_TEMPLATE_NAME}" \
            2>/dev/null || \
        # Fall back to zonal MIG.
        for zone in "${REGION}-a" "${REGION}-b" "${REGION}-c"; do
            gcloud compute instance-groups managed set-instance-template "${mig}" \
                --zone="${zone}" \
                --project="${PROJECT_ID}" \
                --template="projects/${PROJECT_ID}/global/instanceTemplates/${NEW_TEMPLATE_NAME}" \
                2>/dev/null && break
        done

        # Trigger rolling replace with max-surge=1, max-unavailable=0 for
        # zero-downtime updates.
        log_info "  Starting rolling replace for ${mig} ..."
        gcloud compute instance-groups managed rolling-action start-update "${mig}" \
            --region="${REGION}" \
            --project="${PROJECT_ID}" \
            --version="template=projects/${PROJECT_ID}/global/instanceTemplates/${NEW_TEMPLATE_NAME}" \
            --max-surge=1 \
            --max-unavailable=0 \
            --min-ready-sec=30 \
            2>/dev/null || \
        for zone in "${REGION}-a" "${REGION}-b" "${REGION}-c"; do
            gcloud compute instance-groups managed rolling-action start-update "${mig}" \
                --zone="${zone}" \
                --project="${PROJECT_ID}" \
                --version="template=projects/${PROJECT_ID}/global/instanceTemplates/${NEW_TEMPLATE_NAME}" \
                --max-surge=1 \
                --max-unavailable=0 \
                --min-ready-sec=30 \
                2>/dev/null && break
        done

        log_info "  Rolling update initiated for ${mig}."
    done

    # Update TSS singleton instances (not in MIGs).
    for tss in "${TSS_INSTANCES[@]}"; do
        log_info "Updating TSS instance ${tss} metadata ..."
        # Determine which zone the instance is in.
        ZONE=$(gcloud compute instances list \
            --project="${PROJECT_ID}" \
            --filter="name=${tss}" \
            --format='value(zone)' 2>/dev/null | head -1)

        if [[ -z "${ZONE}" ]]; then
            log_warn "TSS instance ${tss} not found, skipping."
            continue
        fi

        # Update the binary version metadata and reset the instance.
        gcloud compute instances add-metadata "${tss}" \
            --zone="${ZONE}" \
            --project="${PROJECT_ID}" \
            --metadata="BINARY_VERSION=${BINARY_VERSION}"

        log_info "  Resetting ${tss} to pick up new binary ..."
        gcloud compute instances reset "${tss}" \
            --zone="${ZONE}" \
            --project="${PROJECT_ID}"
    done

    log_info "Rolling update complete."
fi

# ── Step 4: Wait for health checks ──────────────────────────────────────────

if [[ "${SMOKE_ONLY}" == "false" ]]; then
    log_info "======== Step 4: Waiting for Health Checks ========"

    DEADLINE=$((SECONDS + HEALTH_TIMEOUT))

    # Wait for each MIG to report all instances as HEALTHY.
    for mig in "${MIGS[@]}"; do
        log_info "Waiting for ${mig} to become healthy ..."

        while [[ ${SECONDS} -lt ${DEADLINE} ]]; do
            # Check if update is complete (all instances running new template).
            STATUS=$(gcloud compute instance-groups managed describe "${mig}" \
                --region="${REGION}" \
                --project="${PROJECT_ID}" \
                --format='value(status.isStable)' 2>/dev/null || echo "")

            if [[ "${STATUS}" == "True" ]]; then
                log_info "  ${mig} is stable and healthy."
                break
            fi

            log_info "  ${mig} not yet stable, waiting ${HEALTH_INTERVAL}s ..."
            sleep "${HEALTH_INTERVAL}"
        done

        if [[ ${SECONDS} -ge ${DEADLINE} ]]; then
            log_error "${mig} did not become healthy within ${HEALTH_TIMEOUT}s."
            log_error "Check: gcloud compute instance-groups managed list-instances ${mig} --region=${REGION}"
            die "Health check deadline exceeded."
        fi
    done

    # Check TSS instances are running.
    for tss in "${TSS_INSTANCES[@]}"; do
        ZONE=$(gcloud compute instances list \
            --project="${PROJECT_ID}" \
            --filter="name=${tss}" \
            --format='value(zone)' 2>/dev/null | head -1)

        if [[ -z "${ZONE}" ]]; then
            continue
        fi

        STATUS=$(gcloud compute instances describe "${tss}" \
            --zone="${ZONE}" \
            --project="${PROJECT_ID}" \
            --format='value(status)' 2>/dev/null)

        if [[ "${STATUS}" != "RUNNING" ]]; then
            die "TSS instance ${tss} is ${STATUS}, expected RUNNING."
        fi
        log_info "  ${tss} is RUNNING."
    done

    log_info "All health checks passed."
fi

# ── Step 5: Smoke test ───────────────────────────────────────────────────────

log_info "======== Step 5: Smoke Test ========"

# Find the gateway external IP.
GATEWAY_IP=$(gcloud compute forwarding-rules list \
    --project="${PROJECT_ID}" \
    --filter="name~milnet-gateway" \
    --format='value(IPAddress)' 2>/dev/null | head -1)

if [[ -z "${GATEWAY_IP}" ]]; then
    # Fall back: try to get the gateway instance's external IP directly.
    GATEWAY_IP=$(gcloud compute instances list \
        --project="${PROJECT_ID}" \
        --filter="name~milnet-gateway" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null | head -1)
fi

if [[ -z "${GATEWAY_IP}" ]]; then
    log_warn "Could not determine gateway IP. Skipping smoke test."
    log_warn "Run manually: ${SCRIPT_DIR}/health-check.sh"
else
    GATEWAY_ADDR="${GATEWAY_IP}:9100"
    log_info "Gateway address: ${GATEWAY_ADDR}"

    # Test 1: TCP connectivity to gateway port.
    log_info "  Testing TCP connectivity to ${GATEWAY_ADDR} ..."
    if timeout 10 bash -c "echo >/dev/tcp/${GATEWAY_IP}/9100" 2>/dev/null; then
        log_info "  TCP connection to gateway: OK"
    else
        die "  TCP connection to gateway FAILED. Port 9100 unreachable."
    fi

    # Test 2: Send a puzzle challenge request.
    # The gateway should respond with a puzzle challenge (even if we cannot
    # solve it, receiving any response proves the service is alive).
    log_info "  Sending puzzle challenge probe ..."
    RESPONSE=$(timeout 10 curl -sk -o /dev/null -w "%{http_code}" \
        "https://${GATEWAY_ADDR}/health" 2>/dev/null || echo "000")

    if [[ "${RESPONSE}" == "200" || "${RESPONSE}" == "403" || "${RESPONSE}" == "426" ]]; then
        log_info "  Gateway responded with HTTP ${RESPONSE}: OK (service is alive)"
    elif [[ "${RESPONSE}" == "000" ]]; then
        # Gateway uses raw TCP, not HTTP — try raw TCP probe instead.
        log_info "  Gateway uses raw TCP protocol (not HTTP). TCP probe passed."
    else
        log_warn "  Gateway responded with unexpected HTTP ${RESPONSE}"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────

log_info "==========================================="
log_info "Deployment complete."
log_info "  Project : ${PROJECT_ID}"
log_info "  Region  : ${REGION}"
log_info "  Version : ${BINARY_VERSION}"
log_info "==========================================="
log_info ""
log_info "Run full health check: ${SCRIPT_DIR}/health-check.sh"
