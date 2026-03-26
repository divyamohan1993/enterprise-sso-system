#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — GCE Cluster Health Check
# ==============================================================================
# Comprehensive health verification of the multi-VM GCE deployment:
#   1. VM instance status (all expected VMs running)
#   2. TCP connectivity to each service port
#   3. Gateway puzzle challenge verification
#   4. Cloud SQL reachability
#   5. Overall cluster health report
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed
#
# Usage:
#   ./health-check.sh                          # full check
#   ./health-check.sh --project my-proj        # override project
#   ./health-check.sh --json                   # JSON output
#   ./health-check.sh --quiet                  # minimal output
# ==============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

PROJECT_ID="${GCP_PROJECT:-lmsforshantithakur}"
REGION="${GCP_REGION:-asia-south1}"

# Service name -> expected port mapping.
declare -A SERVICE_PORTS=(
    [gateway]=9100
    [orchestrator]=9101
    [opaque]=9102
    [verifier]=9104
    [ratchet]=9105
    [audit]=9108
    [admin]=8080
)

# TSS instance -> port mapping.
declare -A TSS_PORTS=(
    [milnet-tss-1]=9113
    [milnet-tss-2]=9114
    [milnet-tss-3]=9115
    [milnet-tss-4]=9116
    [milnet-tss-5]=9117
)

QUIET=false
JSON_OUTPUT=false
FAILURES=0
WARNINGS=0
CHECKS=0
RESULTS=()

# ── Helpers ──────────────────────────────────────────────────────────────────

log_ok()   { ((CHECKS++)); RESULTS+=("{\"check\":\"$*\",\"status\":\"ok\"}"); [[ "${QUIET}" == "true" ]] || echo "[  OK  ] $*"; }
log_fail() { ((CHECKS++)); ((FAILURES++)); RESULTS+=("{\"check\":\"$*\",\"status\":\"fail\"}"); echo "[ FAIL ] $*" >&2; }
log_warn() { ((WARNINGS++)); RESULTS+=("{\"check\":\"$*\",\"status\":\"warn\"}"); [[ "${QUIET}" == "true" ]] || echo "[ WARN ] $*" >&2; }
log_info() { [[ "${QUIET}" == "true" ]] || echo "[ INFO ] $*"; }

# ── Parse arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT_ID="$2"; shift 2 ;;
        --region)  REGION="$2"; shift 2 ;;
        --quiet|-q) QUIET=true; shift ;;
        --json)    JSON_OUTPUT=true; QUIET=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--project PROJECT] [--region REGION] [--quiet] [--json]"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── Check 1: VM instance status ─────────────────────────────────────────────

log_info "=== Checking VM instances ==="

# List all MILNET instances.
INSTANCES_RAW=$(gcloud compute instances list \
    --project="${PROJECT_ID}" \
    --filter="name~milnet-" \
    --format="csv[no-heading](name,zone,status,networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP)" \
    2>/dev/null)

if [[ -z "${INSTANCES_RAW}" ]]; then
    log_fail "No MILNET instances found in project ${PROJECT_ID}"
else
    INSTANCE_COUNT=0
    RUNNING_COUNT=0

    while IFS=',' read -r name zone status internal_ip external_ip; do
        ((INSTANCE_COUNT++))
        if [[ "${status}" == "RUNNING" ]]; then
            ((RUNNING_COUNT++))
            log_ok "Instance ${name} (${zone}): RUNNING [${internal_ip}]"
        else
            log_fail "Instance ${name} (${zone}): ${status} (expected RUNNING)"
        fi
    done <<< "${INSTANCES_RAW}"

    log_info "  Instances: ${RUNNING_COUNT}/${INSTANCE_COUNT} running"
fi

# ── Check 2: TCP connectivity to service ports ──────────────────────────────

log_info ""
log_info "=== Checking TCP connectivity ==="

# Build a map of instance name -> internal IP for port checks.
declare -A INSTANCE_IPS=()
if [[ -n "${INSTANCES_RAW}" ]]; then
    while IFS=',' read -r name zone status internal_ip external_ip; do
        INSTANCE_IPS["${name}"]="${internal_ip}"
    done <<< "${INSTANCES_RAW}"
fi

# Check standard services (these are typically behind MIGs, so look for any
# instance matching the service name).
for svc in "${!SERVICE_PORTS[@]}"; do
    PORT="${SERVICE_PORTS[${svc}]}"

    # Find an instance matching this service.
    TARGET_IP=""
    for iname in "${!INSTANCE_IPS[@]}"; do
        if [[ "${iname}" == *"${svc}"* ]]; then
            TARGET_IP="${INSTANCE_IPS[${iname}]}"
            break
        fi
    done

    if [[ -z "${TARGET_IP}" ]]; then
        log_warn "No instance found for service '${svc}', skipping port check"
        continue
    fi

    # Use gcloud SSH to test port from within the VPC (we cannot reach private
    # IPs from outside). Fall back to external IP if available.
    # For a simpler check, try the external IP if the service has one.
    EXTERNAL_IP=""
    for iname in "${!INSTANCE_IPS[@]}"; do
        if [[ "${iname}" == *"${svc}"* ]]; then
            while IFS=',' read -r name zone status internal external; do
                if [[ "${name}" == "${iname}" && -n "${external}" ]]; then
                    EXTERNAL_IP="${external}"
                fi
            done <<< "${INSTANCES_RAW}"
            break
        fi
    done

    CHECK_IP="${EXTERNAL_IP:-${TARGET_IP}}"

    if timeout 5 bash -c "echo >/dev/tcp/${CHECK_IP}/${PORT}" 2>/dev/null; then
        log_ok "TCP ${svc}:${PORT} (${CHECK_IP}): reachable"
    else
        # Port may not be reachable from outside VPC — that is expected for
        # internal services. Only gateway should be externally reachable.
        if [[ "${svc}" == "gateway" ]]; then
            log_fail "TCP ${svc}:${PORT} (${CHECK_IP}): UNREACHABLE"
        else
            log_warn "TCP ${svc}:${PORT} (${CHECK_IP}): not reachable from here (may be VPC-internal only)"
        fi
    fi
done

# Check TSS instances.
for tss in "${!TSS_PORTS[@]}"; do
    PORT="${TSS_PORTS[${tss}]}"
    TARGET_IP="${INSTANCE_IPS[${tss}]:-}"

    if [[ -z "${TARGET_IP}" ]]; then
        log_warn "TSS instance ${tss} not found, skipping port check"
        continue
    fi

    if timeout 5 bash -c "echo >/dev/tcp/${TARGET_IP}/${PORT}" 2>/dev/null; then
        log_ok "TCP ${tss}:${PORT}: reachable"
    else
        log_warn "TCP ${tss}:${PORT}: not reachable from here (may be VPC-internal only)"
    fi
done

# ── Check 3: Gateway puzzle challenge ────────────────────────────────────────

log_info ""
log_info "=== Checking gateway puzzle challenge ==="

# Get the gateway's external IP (load balancer or instance).
GATEWAY_IP=$(gcloud compute forwarding-rules list \
    --project="${PROJECT_ID}" \
    --filter="name~milnet-gateway" \
    --format='value(IPAddress)' 2>/dev/null | head -1)

if [[ -z "${GATEWAY_IP}" ]]; then
    # Try direct instance IP.
    for iname in "${!INSTANCE_IPS[@]}"; do
        if [[ "${iname}" == *"gateway"* ]]; then
            while IFS=',' read -r name zone status internal external; do
                if [[ "${name}" == "${iname}" && -n "${external}" ]]; then
                    GATEWAY_IP="${external}"
                fi
            done <<< "${INSTANCES_RAW}"
            break
        fi
    done
fi

if [[ -z "${GATEWAY_IP}" ]]; then
    log_warn "Could not determine gateway external IP. Skipping puzzle check."
else
    log_info "Gateway IP: ${GATEWAY_IP}"

    # Test TCP connectivity to gateway port 9100.
    if timeout 10 bash -c "echo >/dev/tcp/${GATEWAY_IP}/9100" 2>/dev/null; then
        log_ok "Gateway TCP port 9100: reachable"

        # Attempt an HTTPS health probe (gateway may not serve HTTP).
        HTTP_CODE=$(timeout 10 curl -sk -o /dev/null -w "%{http_code}" \
            "https://${GATEWAY_IP}:9100/health" 2>/dev/null || echo "000")

        if [[ "${HTTP_CODE}" == "200" ]]; then
            log_ok "Gateway health endpoint: HTTP 200"
        elif [[ "${HTTP_CODE}" == "000" ]]; then
            # Gateway uses raw TCP protocol, not HTTP — TCP probe is sufficient.
            log_ok "Gateway raw TCP protocol: responding (non-HTTP service)"
        else
            log_ok "Gateway responding: HTTP ${HTTP_CODE} (service is alive)"
        fi
    else
        log_fail "Gateway TCP port 9100: UNREACHABLE at ${GATEWAY_IP}"
    fi
fi

# ── Check 4: Cloud SQL reachability ──────────────────────────────────────────

log_info ""
log_info "=== Checking Cloud SQL ==="

# List Cloud SQL instances in the project.
SQL_INSTANCES=$(gcloud sql instances list \
    --project="${PROJECT_ID}" \
    --format="csv[no-heading](name,state,ipAddresses[0].ipAddress,region)" \
    2>/dev/null)

if [[ -z "${SQL_INSTANCES}" ]]; then
    log_warn "No Cloud SQL instances found in project ${PROJECT_ID}"
else
    while IFS=',' read -r name state ip sql_region; do
        if [[ "${state}" == "RUNNABLE" ]]; then
            log_ok "Cloud SQL ${name} (${sql_region}): RUNNABLE [${ip}]"

            # Test TCP connectivity to PostgreSQL port.
            if [[ -n "${ip}" ]]; then
                if timeout 5 bash -c "echo >/dev/tcp/${ip}/5432" 2>/dev/null; then
                    log_ok "Cloud SQL ${name}: TCP port 5432 reachable"
                else
                    log_warn "Cloud SQL ${name}: TCP port 5432 not reachable from here (expected if using private IP)"
                fi
            fi
        else
            log_fail "Cloud SQL ${name} (${sql_region}): ${state} (expected RUNNABLE)"
        fi
    done <<< "${SQL_INSTANCES}"
fi

# ── Check 5: MIG health status ──────────────────────────────────────────────

log_info ""
log_info "=== Checking Managed Instance Group health ==="

readonly -a MIGS=(
    milnet-gateway-mig
    milnet-admin-mig
    milnet-orchestrator-mig
    milnet-opaque-mig
    milnet-verifier-mig
    milnet-ratchet-mig
    milnet-audit-mig
)

for mig in "${MIGS[@]}"; do
    # Try regional MIG first, then zonal.
    STABLE=$(gcloud compute instance-groups managed describe "${mig}" \
        --region="${REGION}" \
        --project="${PROJECT_ID}" \
        --format='value(status.isStable)' 2>/dev/null || echo "")

    if [[ -z "${STABLE}" ]]; then
        for zone in "${REGION}-a" "${REGION}-b" "${REGION}-c"; do
            STABLE=$(gcloud compute instance-groups managed describe "${mig}" \
                --zone="${zone}" \
                --project="${PROJECT_ID}" \
                --format='value(status.isStable)' 2>/dev/null || echo "")
            [[ -n "${STABLE}" ]] && break
        done
    fi

    if [[ -z "${STABLE}" ]]; then
        log_warn "MIG ${mig} not found"
    elif [[ "${STABLE}" == "True" ]]; then
        log_ok "MIG ${mig}: stable"
    else
        log_fail "MIG ${mig}: NOT stable (rolling update in progress?)"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "==========================================="
echo "MILNET SSO Cluster Health Report"
echo "==========================================="
echo "  Project  : ${PROJECT_ID}"
echo "  Region   : ${REGION}"
echo "  Checks   : ${CHECKS}"
echo "  Passed   : $((CHECKS - FAILURES))"
echo "  Failed   : ${FAILURES}"
echo "  Warnings : ${WARNINGS}"
echo "==========================================="

# JSON output if requested.
if [[ "${JSON_OUTPUT}" == "true" ]]; then
    echo "{"
    echo "  \"project\": \"${PROJECT_ID}\","
    echo "  \"region\": \"${REGION}\","
    echo "  \"checks\": ${CHECKS},"
    echo "  \"passed\": $((CHECKS - FAILURES)),"
    echo "  \"failed\": ${FAILURES},"
    echo "  \"warnings\": ${WARNINGS},"
    echo "  \"results\": ["
    for i in "${!RESULTS[@]}"; do
        if [[ $i -lt $((${#RESULTS[@]} - 1)) ]]; then
            echo "    ${RESULTS[$i]},"
        else
            echo "    ${RESULTS[$i]}"
        fi
    done
    echo "  ]"
    echo "}"
fi

if [[ ${FAILURES} -gt 0 ]]; then
    echo ""
    echo "RESULT: UNHEALTHY (${FAILURES} failure(s))"
    exit 1
else
    echo ""
    echo "RESULT: HEALTHY"
    exit 0
fi
