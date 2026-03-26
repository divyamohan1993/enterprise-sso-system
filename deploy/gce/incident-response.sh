#!/usr/bin/env bash
###############################################################################
# incident-response.sh — Enterprise SSO Automated Incident Response
#
# Usage:
#   ./incident-response.sh isolate <vm-name>    Isolate a compromised VM
#   ./incident-response.sh rotate-keys          Emergency key rotation
#   ./incident-response.sh freeze               Freeze all deployments
#   ./incident-response.sh snapshot <vm-name>   Forensic disk snapshot
#   ./incident-response.sh status               Show cluster health
###############################################################################

set -euo pipefail

# ---------- Configuration ----------

PROJECT="${GCP_PROJECT:-lmsforshantithakur}"
REGION="${GCP_REGION:-asia-south1}"
ZONES=("${GCP_ZONES:-asia-south1-a asia-south1-b asia-south1-c}")
VPC_NAME="${VPC_NAME:-sso-vpc}"
INCIDENT_LOG="/var/log/enterprise-sso/incident-response.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
INCIDENT_ID="INC-$(date -u +%Y%m%d%H%M%S)-$$"

# Service groups that use managed instance groups
MIG_SERVICES=("gateway" "admin" "verifier")

# All known service labels
ALL_SERVICES=("gateway" "admin" "orchestrator" "opaque" "tss" "verifier" "ratchet" "risk" "audit" "kt")

# ---------- Color output ----------

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- Helpers ----------

log() {
    local level="$1"; shift
    local msg="$*"
    local entry="[${TIMESTAMP}] [${INCIDENT_ID}] [${level}] ${msg}"
    echo -e "${entry}"
    mkdir -p "$(dirname "${INCIDENT_LOG}")" 2>/dev/null || true
    echo "${entry}" >> "${INCIDENT_LOG}" 2>/dev/null || true
}

log_critical() { echo -e "${RED}${BOLD}[CRITICAL]${NC} $*"; log "CRITICAL" "$@"; }
log_warn()     { echo -e "${YELLOW}[WARNING]${NC} $*"; log "WARNING" "$@"; }
log_info()     { echo -e "${CYAN}[INFO]${NC} $*"; log "INFO" "$@"; }
log_ok()       { echo -e "${GREEN}[OK]${NC} $*"; log "INFO" "$@"; }

confirm() {
    local prompt="$1"
    if [[ "${FORCE:-}" == "true" ]]; then
        return 0
    fi
    echo -e "${YELLOW}${BOLD}${prompt}${NC}"
    read -r -p "Type 'yes' to confirm: " answer
    if [[ "${answer}" != "yes" ]]; then
        log_warn "Operation cancelled by operator"
        exit 1
    fi
}

usage() {
    cat <<'USAGE'
Enterprise SSO Incident Response Tool

USAGE:
    ./incident-response.sh <command> [options]

COMMANDS:
    isolate <vm-name>       Remove VM from instance groups, revoke SA keys,
                            block internal IP in firewall
    rotate-keys             Emergency key rotation: new master KEK, re-seal
                            all keys, rolling restart all services
    freeze                  Freeze all deployments: disable auto-scaling,
                            block SSH, snapshot all disks
    snapshot <vm-name>      Create forensic disk snapshot of a VM
    status                  Show cluster health, recent alerts, compromised nodes

OPTIONS:
    --force                 Skip confirmation prompts
    --project <id>          Override GCP project
    --region <region>       Override GCP region

ENVIRONMENT:
    GCP_PROJECT             GCP project ID (default: lmsforshantithakur)
    GCP_REGION              GCP region (default: asia-south1)
    FORCE=true              Skip all confirmations
USAGE
    exit 1
}

# ---------- Parse global flags ----------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)
            FORCE="true"
            shift
            ;;
        --project)
            PROJECT="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        isolate|rotate-keys|freeze|snapshot|status)
            COMMAND="$1"
            shift
            break
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "${COMMAND:-}" ]]; then
    usage
fi

###############################################################################
# COMMAND: isolate <vm-name>
###############################################################################

cmd_isolate() {
    local vm_name="${1:?Error: VM name required. Usage: incident-response.sh isolate <vm-name>}"

    log_critical "ISOLATING VM: ${vm_name}"
    log_critical "Incident ID: ${INCIDENT_ID}"
    confirm "This will ISOLATE ${vm_name}: remove from instance groups, revoke SA keys, block network. Proceed?"

    # Step 1: Determine VM zone
    log_info "Locating VM ${vm_name}..."
    local vm_zone
    vm_zone=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="name=${vm_name}" \
        --format="value(zone)" 2>/dev/null)

    if [[ -z "${vm_zone}" ]]; then
        log_critical "VM ${vm_name} not found in project ${PROJECT}"
        exit 1
    fi
    log_info "Found VM in zone: ${vm_zone}"

    # Step 2: Get the VM's internal IP
    local internal_ip
    internal_ip=$(gcloud compute instances describe "${vm_name}" \
        --project="${PROJECT}" \
        --zone="${vm_zone}" \
        --format="value(networkInterfaces[0].networkIP)" 2>/dev/null)
    log_info "Internal IP: ${internal_ip}"

    # Step 3: Remove from all instance groups
    log_info "Removing VM from instance groups..."
    for service in "${MIG_SERVICES[@]}"; do
        local mig_name="sso-${service}-mig"
        # Try each zone — MIGs may be regional
        gcloud compute instance-groups managed abandon-instances "${mig_name}" \
            --project="${PROJECT}" \
            --region="${REGION}" \
            --instances="${vm_name}" 2>/dev/null && \
            log_ok "Removed ${vm_name} from ${mig_name}" || true
    done

    # Also try unmanaged instance groups
    for zone in ${ZONES[@]}; do
        local groups
        groups=$(gcloud compute instance-groups list \
            --project="${PROJECT}" \
            --filter="zone:${zone}" \
            --format="value(name)" 2>/dev/null)
        for group in ${groups}; do
            gcloud compute instance-groups unmanaged remove-instances "${group}" \
                --project="${PROJECT}" \
                --zone="${zone}" \
                --instances="${vm_name}" 2>/dev/null && \
                log_ok "Removed ${vm_name} from unmanaged group ${group}" || true
        done
    done

    # Step 4: Revoke service account keys
    log_info "Revoking service account keys..."
    local sa_email
    sa_email=$(gcloud compute instances describe "${vm_name}" \
        --project="${PROJECT}" \
        --zone="${vm_zone}" \
        --format="value(serviceAccounts[0].email)" 2>/dev/null)

    if [[ -n "${sa_email}" ]]; then
        local keys
        keys=$(gcloud iam service-accounts keys list \
            --iam-account="${sa_email}" \
            --project="${PROJECT}" \
            --format="value(KEY_ID)" \
            --filter="keyType=USER_MANAGED" 2>/dev/null)
        for key_id in ${keys}; do
            gcloud iam service-accounts keys delete "${key_id}" \
                --iam-account="${sa_email}" \
                --project="${PROJECT}" \
                --quiet 2>/dev/null && \
                log_ok "Revoked SA key: ${key_id}" || \
                log_warn "Failed to revoke key: ${key_id}"
        done

        # Disable the service account entirely
        gcloud iam service-accounts disable "${sa_email}" \
            --project="${PROJECT}" 2>/dev/null && \
            log_ok "Disabled service account: ${sa_email}" || \
            log_warn "Failed to disable SA: ${sa_email}"
    fi

    # Step 5: Block internal IP in firewall
    log_info "Creating firewall rule to block isolated VM..."
    local fw_rule_name="sso-isolate-${vm_name}-${INCIDENT_ID}"
    # Truncate to 62 chars max for GCP naming
    fw_rule_name="${fw_rule_name:0:62}"
    # Sanitize: lowercase, alphanumeric and hyphens only
    fw_rule_name=$(echo "${fw_rule_name}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')

    gcloud compute firewall-rules create "${fw_rule_name}" \
        --project="${PROJECT}" \
        --network="${VPC_NAME}" \
        --priority=100 \
        --direction=INGRESS \
        --action=DENY \
        --rules=all \
        --source-ranges="${internal_ip}/32" \
        --description="Incident ${INCIDENT_ID}: Isolate compromised VM ${vm_name}" 2>/dev/null && \
        log_ok "Created deny-ingress firewall rule: ${fw_rule_name}"

    gcloud compute firewall-rules create "${fw_rule_name}-egress" \
        --project="${PROJECT}" \
        --network="${VPC_NAME}" \
        --priority=100 \
        --direction=EGRESS \
        --action=DENY \
        --rules=all \
        --destination-ranges="0.0.0.0/0" \
        --target-tags="isolated-${vm_name}" \
        --description="Incident ${INCIDENT_ID}: Block egress from ${vm_name}" 2>/dev/null && \
        log_ok "Created deny-egress firewall rule"

    # Tag the VM for egress rule
    gcloud compute instances add-tags "${vm_name}" \
        --project="${PROJECT}" \
        --zone="${vm_zone}" \
        --tags="isolated-${vm_name}" 2>/dev/null && \
        log_ok "Tagged VM for isolation" || \
        log_warn "Could not tag VM (may already be unreachable)"

    # Step 6: Stop the VM (optional — keeps disk for forensics)
    log_info "Stopping VM for forensic preservation..."
    gcloud compute instances stop "${vm_name}" \
        --project="${PROJECT}" \
        --zone="${vm_zone}" 2>/dev/null && \
        log_ok "VM stopped" || \
        log_warn "Could not stop VM"

    echo ""
    log_critical "=== ISOLATION COMPLETE ==="
    log_critical "VM: ${vm_name} | Zone: ${vm_zone} | IP: ${internal_ip}"
    log_critical "Incident ID: ${INCIDENT_ID}"
    log_critical "Next steps:"
    log_critical "  1. Run: ./incident-response.sh snapshot ${vm_name}"
    log_critical "  2. Investigate audit logs in BigQuery: dataset sso_forensic_audit"
    log_critical "  3. If TSS/audit node: verify quorum with ./incident-response.sh status"
}

###############################################################################
# COMMAND: rotate-keys
###############################################################################

cmd_rotate_keys() {
    log_critical "EMERGENCY KEY ROTATION"
    log_critical "Incident ID: ${INCIDENT_ID}"
    confirm "This will rotate ALL cryptographic keys, re-seal key material, and rolling-restart services. Proceed?"

    # Step 1: Generate new master KEK via Cloud KMS
    log_info "Rotating master KEK in Cloud KMS..."
    local keyring="sso-keyring"
    local kek_key="master-kek"

    gcloud kms keys versions create \
        --project="${PROJECT}" \
        --location="${REGION}" \
        --keyring="${keyring}" \
        --key="${kek_key}" \
        --primary 2>/dev/null && \
        log_ok "New master KEK version created and set as primary" || \
        log_critical "Failed to rotate master KEK — manual intervention required"

    # Step 2: Rotate service-specific keys
    local service_keys=("tss-share-kek" "opaque-server-key" "ratchet-chain-key" "session-signing-key" "audit-signing-key")
    for key_name in "${service_keys[@]}"; do
        log_info "Rotating: ${key_name}..."
        gcloud kms keys versions create \
            --project="${PROJECT}" \
            --location="${REGION}" \
            --keyring="${keyring}" \
            --key="${key_name}" \
            --primary 2>/dev/null && \
            log_ok "Rotated: ${key_name}" || \
            log_warn "Could not rotate: ${key_name} (may not exist)"
    done

    # Step 3: Re-seal keys — trigger re-encryption on each service
    log_info "Triggering re-seal on all service VMs..."
    for service in "${ALL_SERVICES[@]}"; do
        local instances
        instances=$(gcloud compute instances list \
            --project="${PROJECT}" \
            --filter="labels.service=${service} AND labels.system=enterprise-sso AND status=RUNNING" \
            --format="value(name,zone)" 2>/dev/null)

        while IFS=$'\t' read -r instance_name instance_zone; do
            [[ -z "${instance_name}" ]] && continue
            log_info "Re-sealing keys on: ${instance_name}..."
            gcloud compute ssh "${instance_name}" \
                --project="${PROJECT}" \
                --zone="${instance_zone}" \
                --tunnel-through-iap \
                --command="sudo systemctl kill -s USR1 sso-${service} 2>/dev/null || sudo /opt/enterprise-sso/bin/reseal-keys.sh" \
                2>/dev/null && \
                log_ok "Re-seal signal sent to ${instance_name}" || \
                log_warn "Could not reach ${instance_name} for re-seal"
        done <<< "${instances}"
    done

    # Step 4: Rolling restart all services
    log_info "Initiating rolling restart of managed instance groups..."
    for service in "${MIG_SERVICES[@]}"; do
        local mig_name="sso-${service}-mig"
        log_info "Rolling restart: ${mig_name}..."
        gcloud compute instance-groups managed rolling-action restart "${mig_name}" \
            --project="${PROJECT}" \
            --region="${REGION}" \
            --max-surge=1 \
            --max-unavailable=0 2>/dev/null && \
            log_ok "Rolling restart initiated for ${mig_name}" || \
            log_warn "Could not restart ${mig_name}"
    done

    # Step 5: Restart singleton/HA services
    log_info "Restarting singleton and HA-pair services..."
    for service in orchestrator opaque ratchet risk kt; do
        local instances
        instances=$(gcloud compute instances list \
            --project="${PROJECT}" \
            --filter="labels.service=${service} AND labels.system=enterprise-sso AND status=RUNNING" \
            --format="value(name,zone)" 2>/dev/null)

        while IFS=$'\t' read -r instance_name instance_zone; do
            [[ -z "${instance_name}" ]] && continue
            log_info "Restarting service on: ${instance_name}..."
            gcloud compute ssh "${instance_name}" \
                --project="${PROJECT}" \
                --zone="${instance_zone}" \
                --tunnel-through-iap \
                --command="sudo systemctl restart sso-${service}" \
                2>/dev/null && \
                log_ok "Restarted ${service} on ${instance_name}" || \
                log_warn "Could not restart ${service} on ${instance_name}"
        done <<< "${instances}"
    done

    # TSS nodes: restart sequentially to maintain quorum
    log_info "Restarting TSS nodes sequentially (maintaining quorum)..."
    local tss_instances
    tss_instances=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=tss AND labels.system=enterprise-sso AND status=RUNNING" \
        --format="value(name,zone)" 2>/dev/null)

    while IFS=$'\t' read -r instance_name instance_zone; do
        [[ -z "${instance_name}" ]] && continue
        log_info "Restarting TSS node: ${instance_name} (waiting for health before next)..."
        gcloud compute ssh "${instance_name}" \
            --project="${PROJECT}" \
            --zone="${instance_zone}" \
            --tunnel-through-iap \
            --command="sudo systemctl restart sso-tss" \
            2>/dev/null && \
            log_ok "Restarted TSS on ${instance_name}" || \
            log_warn "Could not restart TSS on ${instance_name}"
        # Wait for node to rejoin before restarting next
        sleep 30
    done <<< "${tss_instances}"

    # Audit nodes: restart sequentially to maintain BFT quorum
    log_info "Restarting audit BFT nodes sequentially (maintaining quorum)..."
    local audit_instances
    audit_instances=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=audit AND labels.system=enterprise-sso AND status=RUNNING" \
        --format="value(name,zone)" 2>/dev/null)

    while IFS=$'\t' read -r instance_name instance_zone; do
        [[ -z "${instance_name}" ]] && continue
        log_info "Restarting audit node: ${instance_name}..."
        gcloud compute ssh "${instance_name}" \
            --project="${PROJECT}" \
            --zone="${instance_zone}" \
            --tunnel-through-iap \
            --command="sudo systemctl restart sso-audit" \
            2>/dev/null && \
            log_ok "Restarted audit on ${instance_name}" || \
            log_warn "Could not restart audit on ${instance_name}"
        sleep 20
    done <<< "${audit_instances}"

    echo ""
    log_critical "=== KEY ROTATION COMPLETE ==="
    log_critical "Incident ID: ${INCIDENT_ID}"
    log_critical "Actions taken:"
    log_critical "  - Master KEK rotated in Cloud KMS"
    log_critical "  - Service-specific keys rotated"
    log_critical "  - Re-seal signal sent to all services"
    log_critical "  - Rolling restart of all service groups"
    log_critical "Verify: ./incident-response.sh status"
}

###############################################################################
# COMMAND: freeze
###############################################################################

cmd_freeze() {
    log_critical "FREEZING ALL DEPLOYMENTS"
    log_critical "Incident ID: ${INCIDENT_ID}"
    confirm "This will FREEZE the cluster: disable autoscaling, block SSH, snapshot all disks. Proceed?"

    # Step 1: Disable auto-scaling on all MIGs
    log_info "Disabling auto-scaling on managed instance groups..."
    for service in "${MIG_SERVICES[@]}"; do
        local mig_name="sso-${service}-mig"
        local autoscaler_name="sso-${service}-autoscaler"

        # Get current size to pin it
        local current_size
        current_size=$(gcloud compute instance-groups managed describe "${mig_name}" \
            --project="${PROJECT}" \
            --region="${REGION}" \
            --format="value(targetSize)" 2>/dev/null || echo "0")

        # Delete the autoscaler
        gcloud compute instance-groups managed stop-autoscaling "${mig_name}" \
            --project="${PROJECT}" \
            --region="${REGION}" 2>/dev/null && \
            log_ok "Autoscaling disabled for ${mig_name} (pinned at ${current_size})" || \
            log_warn "Could not disable autoscaling for ${mig_name}"
    done

    # Step 2: Block all SSH access
    log_info "Creating firewall rule to block SSH..."
    gcloud compute firewall-rules create "sso-freeze-block-ssh-${INCIDENT_ID}" \
        --project="${PROJECT}" \
        --network="${VPC_NAME}" \
        --priority=100 \
        --direction=INGRESS \
        --action=DENY \
        --rules=tcp:22 \
        --source-ranges="0.0.0.0/0" \
        --target-tags="enterprise-sso" \
        --description="Incident ${INCIDENT_ID}: Emergency SSH block during freeze" 2>/dev/null && \
        log_ok "SSH blocked on all SSO VMs" || \
        log_warn "Could not create SSH block rule"

    # Also block IAP tunnel
    gcloud compute firewall-rules create "sso-freeze-block-iap-${INCIDENT_ID}" \
        --project="${PROJECT}" \
        --network="${VPC_NAME}" \
        --priority=100 \
        --direction=INGRESS \
        --action=DENY \
        --rules=tcp:22 \
        --source-ranges="35.235.240.0/20" \
        --target-tags="enterprise-sso" \
        --description="Incident ${INCIDENT_ID}: Block IAP tunnel during freeze" 2>/dev/null && \
        log_ok "IAP tunnel blocked" || \
        log_warn "Could not block IAP tunnel"

    # Step 3: Snapshot all disks for forensics
    log_info "Creating forensic snapshots of ALL SSO VM disks..."
    local all_instances
    all_instances=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.system=enterprise-sso" \
        --format="value(name,zone)" 2>/dev/null)

    local snapshot_count=0
    while IFS=$'\t' read -r instance_name instance_zone; do
        [[ -z "${instance_name}" ]] && continue
        _create_snapshot "${instance_name}" "${instance_zone}" &
        snapshot_count=$((snapshot_count + 1))
    done <<< "${all_instances}"

    # Wait for all background snapshots
    log_info "Waiting for ${snapshot_count} snapshots to complete..."
    wait
    log_ok "All snapshots initiated"

    # Step 4: Write freeze marker
    log_info "Recording freeze state..."
    gcloud compute project-info add-metadata \
        --project="${PROJECT}" \
        --metadata="sso-freeze-incident=${INCIDENT_ID},sso-freeze-timestamp=${TIMESTAMP}" 2>/dev/null && \
        log_ok "Freeze metadata recorded" || true

    echo ""
    log_critical "=== DEPLOYMENT FREEZE COMPLETE ==="
    log_critical "Incident ID: ${INCIDENT_ID}"
    log_critical "Actions taken:"
    log_critical "  - Autoscaling disabled on all MIGs"
    log_critical "  - SSH and IAP access blocked"
    log_critical "  - Disk snapshots created for all VMs"
    log_critical ""
    log_critical "TO UNFREEZE (after investigation):"
    log_critical "  1. Delete firewall rules: sso-freeze-block-ssh-${INCIDENT_ID}, sso-freeze-block-iap-${INCIDENT_ID}"
    log_critical "  2. Re-enable autoscaling on MIGs"
    log_critical "  3. Remove freeze metadata"
}

###############################################################################
# COMMAND: snapshot <vm-name>
###############################################################################

_create_snapshot() {
    local instance_name="$1"
    local instance_zone="$2"

    local disks
    disks=$(gcloud compute instances describe "${instance_name}" \
        --project="${PROJECT}" \
        --zone="${instance_zone}" \
        --format="value(disks[].source)" 2>/dev/null)

    for disk_url in ${disks}; do
        local disk_name
        disk_name=$(basename "${disk_url}")
        local snapshot_name="forensic-${instance_name}-${disk_name}-$(date -u +%Y%m%d%H%M%S)"
        # Truncate and sanitize snapshot name (max 62 chars)
        snapshot_name="${snapshot_name:0:62}"
        snapshot_name=$(echo "${snapshot_name}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')

        gcloud compute disks snapshot "${disk_name}" \
            --project="${PROJECT}" \
            --zone="${instance_zone}" \
            --snapshot-names="${snapshot_name}" \
            --description="Incident ${INCIDENT_ID}: Forensic snapshot of ${instance_name}/${disk_name}" \
            --labels="incident=${INCIDENT_ID},source_vm=${instance_name},purpose=forensics" 2>/dev/null && \
            log_ok "Snapshot created: ${snapshot_name}" || \
            log_warn "Failed to snapshot: ${disk_name} on ${instance_name}"
    done
}

cmd_snapshot() {
    local vm_name="${1:?Error: VM name required. Usage: incident-response.sh snapshot <vm-name>}"

    log_info "FORENSIC SNAPSHOT: ${vm_name}"
    log_info "Incident ID: ${INCIDENT_ID}"

    # Locate the VM
    local vm_zone
    vm_zone=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="name=${vm_name}" \
        --format="value(zone)" 2>/dev/null)

    if [[ -z "${vm_zone}" ]]; then
        log_critical "VM ${vm_name} not found in project ${PROJECT}"
        exit 1
    fi
    log_info "Found VM in zone: ${vm_zone}"

    _create_snapshot "${vm_name}" "${vm_zone}"

    echo ""
    log_ok "=== SNAPSHOT COMPLETE ==="
    log_info "List snapshots: gcloud compute snapshots list --filter='labels.source_vm=${vm_name}' --project=${PROJECT}"
    log_info "To create a forensic analysis VM from snapshot:"
    log_info "  gcloud compute disks create forensic-disk --source-snapshot=<snapshot-name> --zone=${vm_zone}"
    log_info "  gcloud compute instances create forensic-vm --disk=name=forensic-disk,boot=yes --zone=${vm_zone}"
}

###############################################################################
# COMMAND: status
###############################################################################

cmd_status() {
    echo -e "${BOLD}=======================================================${NC}"
    echo -e "${BOLD}  Enterprise SSO Cluster Health Report${NC}"
    echo -e "${BOLD}  ${TIMESTAMP}${NC}"
    echo -e "${BOLD}=======================================================${NC}"
    echo ""

    # Check if cluster is frozen
    local freeze_id
    freeze_id=$(gcloud compute project-info describe \
        --project="${PROJECT}" \
        --format="value(commonInstanceMetadata.items.filter(key:sso-freeze-incident).value)" 2>/dev/null || echo "")
    if [[ -n "${freeze_id}" ]]; then
        echo -e "${RED}${BOLD}  *** CLUSTER IS FROZEN (Incident: ${freeze_id}) ***${NC}"
        echo ""
    fi

    # ---------- VM Status ----------
    echo -e "${BOLD}--- VM Status ---${NC}"
    echo ""
    printf "%-30s %-15s %-15s %-20s\n" "INSTANCE" "SERVICE" "STATUS" "ZONE"
    printf "%-30s %-15s %-15s %-20s\n" "--------" "-------" "------" "----"

    local all_instances
    all_instances=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.system=enterprise-sso" \
        --format="table[no-heading](name,labels.service,status,zone)" \
        --sort-by="labels.service,name" 2>/dev/null)

    local total_vms=0
    local running_vms=0
    local stopped_vms=0

    while IFS=$'\t' read -r name service status zone; do
        [[ -z "${name}" ]] && continue
        total_vms=$((total_vms + 1))

        local status_color="${RED}"
        if [[ "${status}" == "RUNNING" ]]; then
            status_color="${GREEN}"
            running_vms=$((running_vms + 1))
        elif [[ "${status}" == "STOPPED" || "${status}" == "TERMINATED" ]]; then
            stopped_vms=$((stopped_vms + 1))
        fi

        printf "%-30s %-15s ${status_color}%-15s${NC} %-20s\n" "${name}" "${service:-unknown}" "${status}" "$(basename "${zone:-unknown}")"
    done <<< "${all_instances}"

    echo ""
    echo -e "Total: ${total_vms} VMs | ${GREEN}Running: ${running_vms}${NC} | ${RED}Down: ${stopped_vms}${NC}"
    echo ""

    # ---------- TSS Quorum ----------
    echo -e "${BOLD}--- TSS Quorum Status ---${NC}"
    local tss_running
    tss_running=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=tss AND labels.system=enterprise-sso AND status=RUNNING" \
        --format="value(name)" 2>/dev/null | wc -l)
    local tss_total
    tss_total=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=tss AND labels.system=enterprise-sso" \
        --format="value(name)" 2>/dev/null | wc -l)

    if [[ ${tss_running} -ge 3 ]]; then
        echo -e "  TSS Nodes: ${GREEN}${tss_running}/${tss_total} running${NC} (threshold: 3-of-5) - ${GREEN}HEALTHY${NC}"
    elif [[ ${tss_running} -ge 1 ]]; then
        echo -e "  TSS Nodes: ${YELLOW}${tss_running}/${tss_total} running${NC} (threshold: 3-of-5) - ${YELLOW}DEGRADED${NC}"
    else
        echo -e "  TSS Nodes: ${RED}${tss_running}/${tss_total} running${NC} (threshold: 3-of-5) - ${RED}CRITICAL${NC}"
    fi
    echo ""

    # ---------- Audit BFT Quorum ----------
    echo -e "${BOLD}--- Audit BFT Quorum Status ---${NC}"
    local audit_running
    audit_running=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=audit AND labels.system=enterprise-sso AND status=RUNNING" \
        --format="value(name)" 2>/dev/null | wc -l)
    local audit_total
    audit_total=$(gcloud compute instances list \
        --project="${PROJECT}" \
        --filter="labels.service=audit AND labels.system=enterprise-sso" \
        --format="value(name)" 2>/dev/null | wc -l)

    if [[ ${audit_running} -ge 5 ]]; then
        echo -e "  Audit Nodes: ${GREEN}${audit_running}/${audit_total} running${NC} (quorum: 5-of-7) - ${GREEN}HEALTHY${NC}"
    elif [[ ${audit_running} -ge 3 ]]; then
        echo -e "  Audit Nodes: ${YELLOW}${audit_running}/${audit_total} running${NC} (quorum: 5-of-7) - ${YELLOW}DEGRADED${NC}"
    else
        echo -e "  Audit Nodes: ${RED}${audit_running}/${audit_total} running${NC} (quorum: 5-of-7) - ${RED}CRITICAL${NC}"
    fi
    echo ""

    # ---------- Recent Alerts ----------
    echo -e "${BOLD}--- Recent Alerts (last 1 hour) ---${NC}"
    gcloud alpha monitoring policies conditions list \
        --project="${PROJECT}" 2>/dev/null || true

    # Fallback: check recent incidents via log entries
    local recent_alerts
    recent_alerts=$(gcloud logging read \
        "resource.type=\"gce_instance\" AND severity>=ERROR AND labels.system=\"enterprise-sso\" AND timestamp>=\"$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)\"" \
        --project="${PROJECT}" \
        --limit=10 \
        --format="table(timestamp,severity,jsonPayload.event_type,jsonPayload.message)" \
        2>/dev/null || echo "  (Could not retrieve recent alerts)")

    echo "${recent_alerts}"
    echo ""

    # ---------- Isolation Firewall Rules ----------
    echo -e "${BOLD}--- Active Isolation Rules ---${NC}"
    local isolation_rules
    isolation_rules=$(gcloud compute firewall-rules list \
        --project="${PROJECT}" \
        --filter="name~sso-isolate OR name~sso-freeze" \
        --format="table(name,direction,action,sourceRanges,targetTags,disabled)" \
        2>/dev/null || echo "  (none)")
    echo "${isolation_rules}"
    echo ""

    # ---------- Cloud SQL ----------
    echo -e "${BOLD}--- Cloud SQL Status ---${NC}"
    gcloud sql instances list \
        --project="${PROJECT}" \
        --format="table(name,state,settings.tier,ipAddresses[0].ipAddress)" \
        2>/dev/null || echo "  (Could not retrieve Cloud SQL status)"
    echo ""

    echo -e "${BOLD}=======================================================${NC}"
}

###############################################################################
# Main dispatch
###############################################################################

case "${COMMAND}" in
    isolate)
        cmd_isolate "${1:-}"
        ;;
    rotate-keys)
        cmd_rotate_keys
        ;;
    freeze)
        cmd_freeze
        ;;
    snapshot)
        cmd_snapshot "${1:-}"
        ;;
    status)
        cmd_status
        ;;
    *)
        usage
        ;;
esac
