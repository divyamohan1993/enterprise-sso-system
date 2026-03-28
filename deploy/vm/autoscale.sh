#!/usr/bin/env bash
set -euo pipefail
#
# MILNET SSO — VM Auto-Scaler
#
# Runs as a background process on the admin VM.
# Monitors CPU/memory load across all VMs and:
# - Scales UP: provisions new VM when avg CPU > 70% for 5 minutes
# - Scales DOWN: deprovisions VM when avg CPU < 20% for 15 minutes
# - Never scales below minimum (5 VMs / quorum requirements)
# - New VMs auto-join the cluster via MILNET_CLUSTER_PEERS
#
# Usage: ./autoscale.sh --project PROJECT --region REGION [--min-nodes 5] [--max-nodes 21]
#
# Run as daemon: nohup ./autoscale.sh --project P --region R &

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

PROJECT=""
REGION="asia-south1"
ZONE=""
MIN_NODES=5
MAX_NODES=21
CHECK_INTERVAL=60
SCALE_UP_THRESHOLD=70
SCALE_DOWN_THRESHOLD=20
SCALE_UP_DURATION=300       # 5 minutes sustained
SCALE_DOWN_DURATION=900     # 15 minutes sustained
LABEL_KEY="milnet-cluster"
MACHINE_TYPE="c2-standard-8"
BOOT_DISK_SIZE="100GB"
BOOT_DISK_TYPE="pd-ssd"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
VPC_NAME="milnet-vpc"
SUBNET_NAME="milnet-subnet"
PID_FILE="/var/run/milnet-autoscale.pid"
LOG_FILE="/var/log/milnet/autoscale.log"

# State tracking for sustained load
SCALE_UP_SINCE=0
SCALE_DOWN_SINCE=0
LAST_SCALE_ACTION=0
COOLDOWN=180  # 3 minute cooldown between scale actions

# ── Argument Parsing ─────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 --project PROJECT --region REGION [options]"
    echo ""
    echo "Required:"
    echo "  --project       GCP project ID"
    echo "  --region        GCP region"
    echo ""
    echo "Optional:"
    echo "  --min-nodes     Minimum VMs (default: 5, cannot be less)"
    echo "  --max-nodes     Maximum VMs (default: 21)"
    echo "  --interval      Check interval in seconds (default: 60)"
    echo "  --up-threshold  CPU% to trigger scale-up (default: 70)"
    echo "  --down-threshold CPU% to trigger scale-down (default: 20)"
    echo "  --zone          Override zone (default: \${region}-a)"
    echo "  --machine-type  VM machine type (default: c2-standard-8)"
    echo "  --help          Show this message"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)       PROJECT="$2"; shift 2 ;;
        --region)        REGION="$2"; shift 2 ;;
        --min-nodes)     MIN_NODES="$2"; shift 2 ;;
        --max-nodes)     MAX_NODES="$2"; shift 2 ;;
        --interval)      CHECK_INTERVAL="$2"; shift 2 ;;
        --up-threshold)  SCALE_UP_THRESHOLD="$2"; shift 2 ;;
        --down-threshold) SCALE_DOWN_THRESHOLD="$2"; shift 2 ;;
        --zone)          ZONE="$2"; shift 2 ;;
        --machine-type)  MACHINE_TYPE="$2"; shift 2 ;;
        --help|-h)       usage ;;
        *)               echo "ERROR: Unknown argument: $1"; usage ;;
    esac
done

if [[ -z "$PROJECT" ]]; then
    echo "ERROR: --project is required."
    usage
fi
if [[ -z "$REGION" ]]; then
    echo "ERROR: --region is required."
    usage
fi

if [[ -z "$ZONE" ]]; then
    ZONE="${REGION}-a"
fi

if [[ "$MIN_NODES" -lt 5 ]]; then
    echo "ERROR: Minimum nodes cannot be less than 5 (quorum requirement)."
    exit 1
fi

# ── Helper Functions ─────────────────────────────────────────────────────────

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

now_epoch() {
    date +%s
}

gcloud_ssh() {
    local vm="$1"
    shift
    gcloud compute ssh "$vm" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --tunnel-through-iap \
        --command="$*" \
        --quiet 2>/dev/null
}

# ── get_cluster_vms: List current MILNET VMs by label ────────────────────────

get_cluster_vms() {
    gcloud compute instances list \
        --project="$PROJECT" \
        --filter="labels.${LABEL_KEY}:* AND zone:${ZONE} AND status:RUNNING" \
        --format="value(name)" \
        --sort-by=name 2>/dev/null
}

get_cluster_vm_count() {
    get_cluster_vms | wc -l
}

get_vm_internal_ip() {
    local vm="$1"
    gcloud compute instances describe "$vm" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --format="value(networkInterfaces[0].networkIP)" 2>/dev/null
}

get_cluster_label_value() {
    # Get the label value from the first cluster VM
    local first_vm
    first_vm=$(get_cluster_vms | head -1)
    if [[ -n "$first_vm" ]]; then
        gcloud compute instances describe "$first_vm" \
            --project="$PROJECT" \
            --zone="$ZONE" \
            --format="value(labels.${LABEL_KEY})" 2>/dev/null
    fi
}

# ── monitor_load: Read CPU load from all VMs ─────────────────────────────────

monitor_load() {
    # Returns average CPU load percentage across all cluster VMs.
    # Uses /proc/loadavg (1-minute average) normalized by CPU count.
    local vms
    vms=$(get_cluster_vms)
    local total_load=0
    local vm_count=0

    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue

        # Get 1-minute loadavg and CPU count
        local load_info
        load_info=$(gcloud_ssh "$vm" \
            "awk '{print \$1}' /proc/loadavg && nproc" 2>/dev/null) || continue

        local loadavg
        local ncpus
        loadavg=$(echo "$load_info" | head -1)
        ncpus=$(echo "$load_info" | tail -1)

        if [[ -n "$loadavg" && -n "$ncpus" && "$ncpus" -gt 0 ]]; then
            # Convert loadavg to CPU percentage: (loadavg / ncpus) * 100
            local cpu_pct
            cpu_pct=$(awk "BEGIN {printf \"%.0f\", ($loadavg / $ncpus) * 100}")
            total_load=$((total_load + cpu_pct))
            vm_count=$((vm_count + 1))
        fi
    done <<< "$vms"

    if [[ "$vm_count" -eq 0 ]]; then
        echo "0"
        return
    fi

    echo $((total_load / vm_count))
}

# ── should_scale_up: Check if avg load > threshold for duration ──────────────

should_scale_up() {
    local avg_load="$1"
    local current_time
    current_time=$(now_epoch)
    local current_count
    current_count=$(get_cluster_vm_count)

    # Cannot scale above max
    if [[ "$current_count" -ge "$MAX_NODES" ]]; then
        SCALE_UP_SINCE=0
        return 1
    fi

    # Cooldown check
    if [[ $((current_time - LAST_SCALE_ACTION)) -lt "$COOLDOWN" ]]; then
        return 1
    fi

    if [[ "$avg_load" -gt "$SCALE_UP_THRESHOLD" ]]; then
        if [[ "$SCALE_UP_SINCE" -eq 0 ]]; then
            SCALE_UP_SINCE="$current_time"
            log "Scale-up condition detected (avg CPU: ${avg_load}%). Watching..."
            return 1
        fi

        local duration=$((current_time - SCALE_UP_SINCE))
        if [[ "$duration" -ge "$SCALE_UP_DURATION" ]]; then
            log "Scale-up condition sustained for ${duration}s (threshold: ${SCALE_UP_DURATION}s)"
            return 0
        fi
        return 1
    else
        # Load dropped below threshold, reset
        if [[ "$SCALE_UP_SINCE" -ne 0 ]]; then
            log "Scale-up condition cleared (avg CPU: ${avg_load}%)"
        fi
        SCALE_UP_SINCE=0
        return 1
    fi
}

# ── should_scale_down: Check if avg load < threshold for duration ────────────

should_scale_down() {
    local avg_load="$1"
    local current_time
    current_time=$(now_epoch)
    local current_count
    current_count=$(get_cluster_vm_count)

    # Cannot scale below min
    if [[ "$current_count" -le "$MIN_NODES" ]]; then
        SCALE_DOWN_SINCE=0
        return 1
    fi

    # Cooldown check
    if [[ $((current_time - LAST_SCALE_ACTION)) -lt "$COOLDOWN" ]]; then
        return 1
    fi

    if [[ "$avg_load" -lt "$SCALE_DOWN_THRESHOLD" ]]; then
        if [[ "$SCALE_DOWN_SINCE" -eq 0 ]]; then
            SCALE_DOWN_SINCE="$current_time"
            log "Scale-down condition detected (avg CPU: ${avg_load}%). Watching..."
            return 1
        fi

        local duration=$((current_time - SCALE_DOWN_SINCE))
        if [[ "$duration" -ge "$SCALE_DOWN_DURATION" ]]; then
            log "Scale-down condition sustained for ${duration}s (threshold: ${SCALE_DOWN_DURATION}s)"
            return 0
        fi
        return 1
    else
        if [[ "$SCALE_DOWN_SINCE" -ne 0 ]]; then
            log "Scale-down condition cleared (avg CPU: ${avg_load}%)"
        fi
        SCALE_DOWN_SINCE=0
        return 1
    fi
}

# ── scale_up: Provision a new VM and join it to the cluster ──────────────────

scale_up() {
    local current_count
    current_count=$(get_cluster_vm_count)
    local new_index=$((current_count + 1))
    local new_name="milnet-node-${new_index}"
    local label_value
    label_value=$(get_cluster_label_value)

    log "SCALE UP: Creating $new_name (node #${new_index})..."

    # Create the VM
    gcloud compute instances create "$new_name" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --network-interface="network=$VPC_NAME,subnet=$SUBNET_NAME,no-address" \
        --image-family="$IMAGE_FAMILY" \
        --image-project="$IMAGE_PROJECT" \
        --boot-disk-size="$BOOT_DISK_SIZE" \
        --boot-disk-type="$BOOT_DISK_TYPE" \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        --tags=milnet-node \
        --labels="${LABEL_KEY}=${label_value}" \
        --metadata=enable-oslogin=TRUE \
        --scopes=compute-ro,logging-write,monitoring-write

    # Wait for VM to be running
    local max_wait=180
    local elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
        local status
        status=$(gcloud compute instances describe "$new_name" \
            --project="$PROJECT" --zone="$ZONE" \
            --format="value(status)" 2>/dev/null || echo "PENDING")
        if [[ "$status" == "RUNNING" ]]; then
            break
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    local new_ip
    new_ip=$(get_vm_internal_ip "$new_name")
    log "  $new_name IP: $new_ip"

    # Install software (copy from an existing healthy node)
    local source_vm
    source_vm=$(get_cluster_vms | head -1)
    log "  Installing software from $source_vm..."

    gcloud_ssh "$new_name" "$(cat <<'INSTALL_SCRIPT'
set -euo pipefail

# Create milnet user and directories
if ! id milnet &>/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin milnet
fi
sudo mkdir -p /opt/milnet/bin /etc/milnet/env /etc/milnet/tls /etc/milnet/keys
sudo mkdir -p /var/lib/milnet/audit /var/lib/milnet/kt /var/lib/milnet/tss_nonce_state
sudo mkdir -p /var/log/milnet
sudo chown -R milnet:milnet /var/lib/milnet /var/log/milnet
sudo chown -R root:milnet /etc/milnet
sudo chmod 750 /etc/milnet/env /etc/milnet/tls /etc/milnet/keys

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential libssl-dev pkg-config ca-certificates tpm2-tools jq curl
INSTALL_SCRIPT
)"

    # Copy binaries from source VM
    for svc in gateway orchestrator opaque tss verifier ratchet risk audit kt admin; do
        gcloud_ssh "$source_vm" "sudo cat /opt/milnet/bin/$svc 2>/dev/null" | \
            gcloud_ssh "$new_name" "sudo tee /opt/milnet/bin/$svc > /dev/null && \
                sudo chmod 755 /opt/milnet/bin/$svc" 2>/dev/null || true
    done

    # Copy TLS CA cert and keys
    gcloud_ssh "$source_vm" "sudo cat /etc/milnet/tls/ca.crt" | \
        gcloud_ssh "$new_name" "sudo tee /etc/milnet/tls/ca.crt > /dev/null && \
            sudo chown root:milnet /etc/milnet/tls/ca.crt"

    # Copy sub-keys
    for keyfile in shard_hmac.hex receipt_signing.hex audit_hmac.hex \
                   session_enc.hex ratchet_seed.hex kt_hmac.hex; do
        gcloud_ssh "$source_vm" "sudo cat /etc/milnet/keys/$keyfile 2>/dev/null" | \
            gcloud_ssh "$new_name" "sudo tee /etc/milnet/keys/$keyfile > /dev/null && \
                sudo chown root:milnet /etc/milnet/keys/$keyfile && \
                sudo chmod 640 /etc/milnet/keys/$keyfile" 2>/dev/null || true
    done

    # Build updated CLUSTER_PEERS
    local all_ips=""
    local vms
    vms=$(get_cluster_vms)
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        local ip
        ip=$(get_vm_internal_ip "$vm")
        if [[ -n "$all_ips" ]]; then all_ips="${all_ips},"; fi
        all_ips="${all_ips}${ip}"
    done <<< "$vms"

    # Generate env file for new node
    local node_id
    node_id=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)

    # Get service addresses from the source VM env file
    local source_env
    source_env=$(gcloud_ssh "$source_vm" "sudo cat /etc/milnet/env/milnet.env 2>/dev/null" || echo "")

    # Extract existing addresses from source or use defaults
    local opaque_addr tss_addr verifier_addr ratchet_addr risk_addr audit_addr kt_addr
    opaque_addr=$(echo "$source_env" | grep "MILNET_OPAQUE_ADDR" | cut -d= -f2 || echo "")
    tss_addr=$(echo "$source_env" | grep "MILNET_TSS_ADDR" | cut -d= -f2 || echo "")
    verifier_addr=$(echo "$source_env" | grep "MILNET_VERIFIER_ADDR" | cut -d= -f2 || echo "")
    ratchet_addr=$(echo "$source_env" | grep "MILNET_RATCHET_ADDR" | cut -d= -f2 || echo "")
    risk_addr=$(echo "$source_env" | grep "MILNET_RISK_ADDR" | cut -d= -f2 || echo "")
    audit_addr=$(echo "$source_env" | grep "MILNET_AUDIT_ADDR" | cut -d= -f2 || echo "")
    kt_addr=$(echo "$source_env" | grep "MILNET_KT_ADDR" | cut -d= -f2 || echo "")

    gcloud_ssh "$new_name" "$(cat <<ENV_SCRIPT
sudo tee /etc/milnet/env/milnet.env > /dev/null <<'ENVFILE'
MILNET_PRODUCTION=1
MILNET_NODE_ID=${node_id}
MILNET_BIND_ADDR=${new_ip}
MILNET_CLUSTER_PEERS=${all_ips}
MILNET_OPAQUE_ADDR=${opaque_addr}
MILNET_TSS_ADDR=${tss_addr}
MILNET_VERIFIER_ADDR=${verifier_addr}
MILNET_RATCHET_ADDR=${ratchet_addr}
MILNET_RISK_ADDR=${risk_addr}
MILNET_AUDIT_ADDR=${audit_addr}
MILNET_KT_ADDR=${kt_addr}
MILNET_TLS_CERT=/etc/milnet/tls/server.crt
MILNET_TLS_KEY=/etc/milnet/tls/server.key
MILNET_CA_CERT=/etc/milnet/tls/ca.crt
MILNET_KEY_DIR=/etc/milnet/keys
MILNET_DATA_DIR=/var/lib/milnet
MILNET_LOG_DIR=/var/log/milnet
MILNET_RAFT_PORT=4647
ENVFILE
sudo chown root:milnet /etc/milnet/env/milnet.env
sudo chmod 640 /etc/milnet/env/milnet.env
ENV_SCRIPT
)"

    # Copy systemd units and start services
    # New scale-out nodes run as replicas (orchestrator only by default)
    gcloud_ssh "$source_vm" "sudo cat /etc/systemd/system/milnet-orchestrator.service" | \
        gcloud_ssh "$new_name" "sudo tee /etc/systemd/system/milnet-orchestrator.service > /dev/null && \
            sudo systemctl daemon-reload && \
            sudo systemctl enable milnet-orchestrator.service && \
            sudo systemctl start milnet-orchestrator.service"

    # Update CLUSTER_PEERS on all existing VMs
    log "  Updating CLUSTER_PEERS on all existing VMs..."
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        [[ "$vm" == "$new_name" ]] && continue
        gcloud_ssh "$vm" "sudo sed -i 's|^MILNET_CLUSTER_PEERS=.*|MILNET_CLUSTER_PEERS=${all_ips}|' /etc/milnet/env/milnet.env" &
    done <<< "$vms"
    wait

    LAST_SCALE_ACTION=$(now_epoch)
    SCALE_UP_SINCE=0
    log "SCALE UP: $new_name provisioned and joined cluster (total: $((current_count + 1)))"
}

# ── scale_down: Gracefully drain and remove a non-critical VM ────────────────

scale_down() {
    local current_count
    current_count=$(get_cluster_vm_count)

    if [[ "$current_count" -le "$MIN_NODES" ]]; then
        log "SCALE DOWN: Refused. Already at minimum ($MIN_NODES)."
        return 1
    fi

    # Find a non-critical VM to remove (highest numbered, not node-1 through node-5)
    local candidate=""
    local vms
    vms=$(get_cluster_vms | sort -t- -k3 -n -r)

    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue

        # Never remove the first 5 nodes (core cluster)
        local node_num
        node_num=$(echo "$vm" | grep -oP '\d+$' || echo "0")
        if [[ "$node_num" -le 5 ]]; then
            continue
        fi

        # Check if this VM is a Raft leader
        local is_leader
        is_leader=$(gcloud_ssh "$vm" \
            "curl -sf http://127.0.0.1:4647/cluster/role --max-time 3 2>/dev/null || echo unknown")
        if [[ "$is_leader" == *"leader"* ]]; then
            log "  Skipping $vm (is Raft leader)"
            continue
        fi

        # Check if this VM holds TSS signer shares
        local has_tss
        has_tss=$(gcloud_ssh "$vm" \
            "systemctl is-active milnet-tss-signer@*.service 2>/dev/null || echo inactive")
        if [[ "$has_tss" == "active" ]]; then
            log "  Skipping $vm (holds TSS signer shares)"
            continue
        fi

        candidate="$vm"
        break
    done <<< "$vms"

    if [[ -z "$candidate" ]]; then
        log "SCALE DOWN: No eligible candidate found (all nodes are critical)."
        return 1
    fi

    log "SCALE DOWN: Draining $candidate..."

    # Graceful drain: stop accepting new requests, finish in-flight
    gcloud_ssh "$candidate" "$(cat <<'DRAIN_SCRIPT'
set -euo pipefail

# Signal services to drain (send SIGTERM, which triggers graceful shutdown)
for unit in $(systemctl list-units --plain --no-legend 'milnet-*' | awk '{print $1}'); do
    sudo systemctl stop "$unit" 2>/dev/null || true
done

# Wait briefly for connections to drain
sleep 5

# Disable all milnet services
for unit in $(systemctl list-unit-files --plain --no-legend 'milnet-*' | awk '{print $1}'); do
    sudo systemctl disable "$unit" 2>/dev/null || true
done

echo "DRAINED"
DRAIN_SCRIPT
)"

    log "  $candidate drained. Deleting VM..."

    # Delete the VM
    gcloud compute instances delete "$candidate" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --quiet

    # Update CLUSTER_PEERS on remaining VMs
    local all_ips=""
    vms=$(get_cluster_vms)
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        local ip
        ip=$(get_vm_internal_ip "$vm")
        if [[ -n "$all_ips" ]]; then all_ips="${all_ips},"; fi
        all_ips="${all_ips}${ip}"
    done <<< "$vms"

    log "  Updating CLUSTER_PEERS on remaining VMs..."
    while IFS= read -r vm; do
        [[ -z "$vm" ]] && continue
        gcloud_ssh "$vm" "sudo sed -i 's|^MILNET_CLUSTER_PEERS=.*|MILNET_CLUSTER_PEERS=${all_ips}|' /etc/milnet/env/milnet.env" &
    done <<< "$vms"
    wait

    LAST_SCALE_ACTION=$(now_epoch)
    SCALE_DOWN_SINCE=0
    log "SCALE DOWN: $candidate removed (total: $((current_count - 1)))"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

# Write PID file
echo $$ > "$PID_FILE" 2>/dev/null || true

# Handle graceful shutdown
shutdown_requested=false
trap 'shutdown_requested=true; log "Shutdown requested..."' SIGTERM SIGINT

log "╔══════════════════════════════════════════════════════════════╗"
log "║  MILNET SSO — Auto-Scaler Started                           ║"
log "║  Project:   $PROJECT"
log "║  Region:    $REGION  Zone: $ZONE"
log "║  Min Nodes: $MIN_NODES  Max Nodes: $MAX_NODES"
log "║  Scale Up:  >${SCALE_UP_THRESHOLD}% CPU for ${SCALE_UP_DURATION}s"
log "║  Scale Down: <${SCALE_DOWN_THRESHOLD}% CPU for ${SCALE_DOWN_DURATION}s"
log "║  Check Interval: ${CHECK_INTERVAL}s"
log "║  PID: $$"
log "╚══════════════════════════════════════════════════════════════╝"

while [[ "$shutdown_requested" == "false" ]]; do
    # Collect load metrics
    avg_load=$(monitor_load)
    current_vms=$(get_cluster_vm_count)

    log "Check: avg_cpu=${avg_load}% vms=${current_vms} (min=$MIN_NODES max=$MAX_NODES)"

    # Evaluate scaling decisions
    if should_scale_up "$avg_load"; then
        log "Triggering scale-up (avg CPU: ${avg_load}%, VMs: ${current_vms})"
        scale_up || log "Scale-up failed"
    elif should_scale_down "$avg_load"; then
        log "Triggering scale-down (avg CPU: ${avg_load}%, VMs: ${current_vms})"
        scale_down || log "Scale-down failed"
    fi

    # Sleep with interruption support
    local_count=0
    while [[ "$local_count" -lt "$CHECK_INTERVAL" && "$shutdown_requested" == "false" ]]; do
        sleep 1
        local_count=$((local_count + 1))
    done
done

log "Auto-scaler stopped."
rm -f "$PID_FILE" 2>/dev/null || true
exit 0
