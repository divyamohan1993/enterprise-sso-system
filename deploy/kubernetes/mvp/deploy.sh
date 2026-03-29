#!/usr/bin/env bash
# MILNET SSO — MVP Deployment Script
# Deploys the full SSO system on a single-node k3s cluster.
# Intended for the C2 spot VM (c2-standard-8, Debian 12).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Step 1: Install k3s ─────────────────────────────────────────────────────
install_k3s() {
    # Helm and kubectl need this
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

    if command -v k3s &>/dev/null; then
        log "k3s already installed: $(k3s --version)"
        return
    fi
    log "Installing k3s..."
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik" sh -
    # Wait for k3s to be ready
    sleep 5
    sudo k3s kubectl wait --for=condition=Ready node --all --timeout=120s
    log "k3s installed and ready"
}

# ── Step 2: Install Docker ──────────────────────────────────────────────────
install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker already installed: $(docker --version)"
        return
    fi
    log "Installing Docker..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker.io
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER" || true
    log "Docker installed"
}

# ── Step 3: Install Helm ────────────────────────────────────────────────────
install_helm() {
    if command -v helm &>/dev/null; then
        log "Helm already installed: $(helm version --short)"
        return
    fi
    log "Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    log "Helm installed"
}

# ── Step 4: Build Docker images ─────────────────────────────────────────────
build_images() {
    log "Building Docker images (this will take a while on first run)..."
    cd "$REPO_ROOT"

    # Services that have binaries
    local services=(gateway orchestrator tss opaque verifier ratchet risk audit kt admin)

    # Use the MVP Dockerfile (no static linking, debian-slim runtime)
    local dockerfile="$SCRIPT_DIR/Dockerfile"

    # Check if images already exist
    local need_build=false
    for svc in "${services[@]}"; do
        if ! sudo docker image inspect "milnet/${svc}:dev" &>/dev/null; then
            need_build=true
            break
        fi
    done

    if [ "$need_build" = "false" ]; then
        log "All images already exist, skipping build"
    else
        for svc in "${services[@]}"; do
            if sudo docker image inspect "milnet/${svc}:dev" &>/dev/null; then
                log "  milnet/${svc}:dev already exists, skipping"
                continue
            fi
            log "Building milnet/${svc}:dev ..."
            sudo docker build \
                --build-arg SERVICE_NAME="${svc}" \
                -t "milnet/${svc}:dev" \
                -f "$dockerfile" \
                . 2>&1 | tail -30
            log "  -> milnet/${svc}:dev built"
        done
        # Clean build cache to save disk (keep final images)
        sudo docker builder prune -f 2>/dev/null || true
    fi

    log "Importing images into k3s containerd..."
    for svc in "${services[@]}"; do
        sudo docker save "milnet/${svc}:dev" | sudo k3s ctr images import -
        log "  -> milnet/${svc}:dev imported"
    done
}

# ── Step 5: Generate secrets ────────────────────────────────────────────────
generate_secrets() {
    log "Generating MVP secrets..."

    local DB_PASSWORD="milnet-mvp-db"
    local DB_URL="postgresql://milnet:${DB_PASSWORD}@postgres.milnet.svc.cluster.local:5432/milnet"
    local MASTER_KEK
    MASTER_KEK=$(openssl rand -hex 32)

    sudo k3s kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: milnet-database
  namespace: milnet
type: Opaque
stringData:
  POSTGRES_PASSWORD: "${DB_PASSWORD}"
  DATABASE_URL: "${DB_URL}"
---
apiVersion: v1
kind: Secret
metadata:
  name: milnet-master-kek
  namespace: milnet
type: Opaque
stringData:
  MILNET_MASTER_KEK: "${MASTER_KEK}"
EOF
    log "Secrets created (DB password: ${DB_PASSWORD})"
}

# ── Step 6: Deploy SSO services ─────────────────────────────────────────────
deploy_sso() {
    log "Deploying SSO services..."
    cd "$SCRIPT_DIR"

    # Namespace first
    sudo k3s kubectl apply -f namespace.yaml

    # Clean up evicted/failed pods from previous runs
    sudo k3s kubectl delete pods -n milnet --field-selector=status.phase=Failed 2>/dev/null || true

    # ConfigMap
    sudo k3s kubectl apply -f configmap.yaml

    # Secrets (must exist before workloads reference them)
    generate_secrets

    # Services (so DNS is available before pods start)
    sudo k3s kubectl apply -f services.yaml

    # PostgreSQL first — other services need it
    sudo k3s kubectl apply -f postgres.yaml
    log "Waiting for PostgreSQL to be ready..."
    sudo k3s kubectl wait --namespace=milnet --for=condition=Available deployment/postgres --timeout=120s || warn "PostgreSQL not ready yet, continuing..."

    # All workloads
    sudo k3s kubectl apply -f workloads.yaml

    # Index page — create configmap from HTML file, then deploy nginx
    sudo k3s kubectl create configmap index-html \
        --from-file=index.html="$SCRIPT_DIR/index.html" \
        --namespace=milnet \
        --dry-run=client -o yaml | sudo k3s kubectl apply -f -
    sudo k3s kubectl apply -f index-nginx.yaml

    log "All SSO services deployed"
}

# ── Step 7: Deploy Prometheus + Grafana ──────────────────────────────────────
deploy_monitoring() {
    log "Deploying Prometheus + Grafana via Helm..."

    # Add helm repo
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
    helm repo update

    # Install kube-prometheus-stack
    helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --create-namespace \
        --set grafana.adminPassword="milnet-mvp-2026" \
        --set grafana.service.type=NodePort \
        --set grafana.service.nodePort=30300 \
        --set prometheus.service.type=NodePort \
        --set prometheus.service.nodePort=30900 \
        --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
        --set alertmanager.enabled=false \
        --set grafana.persistence.enabled=false \
        --set "grafana.grafana\\.ini.server.root_url=http://localhost:30300" \
        --set nodeExporter.enabled=true \
        --set kubeStateMetrics.enabled=true \
        --timeout 5m \
        --wait || warn "Helm install timed out, may still be pulling images..."

    log "Monitoring stack deployed"
}

# ── Step 8: Print status ────────────────────────────────────────────────────
print_status() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  MILNET SSO — MVP Deployment Complete${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Get external IP
    local EXT_IP
    EXT_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || echo "UNKNOWN")

    echo -e "  External IP:  ${GREEN}${EXT_IP}${NC}"
    echo ""
    echo -e "  ${GREEN}Index Page:${NC}     http://${EXT_IP}:30000"
    echo -e "  ${GREEN}Grafana:${NC}        http://${EXT_IP}:30300   (admin / milnet-mvp-2026)"
    echo -e "  ${GREEN}Prometheus:${NC}     http://${EXT_IP}:30900"
    echo -e "  ${GREEN}Admin Panel:${NC}    http://${EXT_IP}:30080"
    echo -e "  ${GREEN}Gateway:${NC}        https://${EXT_IP}:30443"
    echo ""
    echo -e "  ${YELLOW}Pod Status:${NC}"
    sudo k3s kubectl get pods -n milnet -o wide 2>/dev/null || true
    echo ""
    sudo k3s kubectl get pods -n monitoring -o wide 2>/dev/null || true
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    log "MILNET SSO — MVP Deployment Starting..."
    echo ""

    install_k3s
    install_docker
    install_helm
    build_images
    deploy_sso
    deploy_monitoring
    print_status

    log "Done! Open http://<EXTERNAL_IP>:30000 for the dashboard."
}

main "$@"
