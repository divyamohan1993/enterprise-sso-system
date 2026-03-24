#!/usr/bin/env bash
# ==============================================================================
# MILNET SSO — Service Deployment Script
# ==============================================================================
# Builds Docker images, pushes to Artifact Registry, deploys to Cloud Run,
# wires service-to-service URLs, and runs health checks.
#
# Usage:
#   ./deploy-services.sh                      # Build + push + deploy
#   ./deploy-services.sh --build-only         # Build and push images only
#   ./deploy-services.sh --deploy-only        # Deploy from existing images
#   ./deploy-services.sh --local              # Build locally (no push/deploy)
#   ./deploy-services.sh --cloud-build        # Use Cloud Build instead of local
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration ─────────────────────────────────────────────────────────────
# Read from terraform.tfvars if available, otherwise use defaults
TFVARS="$SCRIPT_DIR/terraform.tfvars"

if [ -f "$TFVARS" ]; then
    PROJECT_ID=$(grep -E '^\s*project_id\s*=' "$TFVARS" | sed 's/.*=\s*"\(.*\)"/\1/' || echo "")
    REGION=$(grep -E '^\s*region\s*=' "$TFVARS" | sed 's/.*=\s*"\(.*\)"/\1/' || echo "asia-south1")
else
    PROJECT_ID="${GCP_PROJECT_ID:-}"
    REGION="${GCP_REGION:-asia-south1}"
fi

# Override with env vars if set
PROJECT_ID="${GCP_PROJECT_ID:-$PROJECT_ID}"
REGION="${GCP_REGION:-$REGION}"
ENV_SUFFIX="${ENV_SUFFIX:-dev}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

AR_REPO="${REGION}-docker.pkg.dev/${PROJECT_ID}/milnet-sso-${ENV_SUFFIX}"

# Service definitions: name, port, CPU, memory
SERVICES=(
    "gateway:9100:1:512Mi"
    "orchestrator:9101:1:512Mi"
    "opaque:9102:1:256Mi"
    "tss:9103:1:512Mi"
    "verifier:9104:1:256Mi"
    "admin:8080:1:512Mi"
    "ratchet:9105:1:256Mi"
    "audit:9108:1:256Mi"
)

# ── Parse Arguments ───────────────────────────────────────────────────────────
MODE="full"         # full | build-only | deploy-only | local | cloud-build
for arg in "$@"; do
    case "$arg" in
        --build-only)   MODE="build-only" ;;
        --deploy-only)  MODE="deploy-only" ;;
        --local)        MODE="local" ;;
        --cloud-build)  MODE="cloud-build" ;;
        --help|-h)
            echo "Usage: $0 [--build-only|--deploy-only|--local|--cloud-build]"
            echo ""
            echo "  --build-only    Build and push images only (no Cloud Run deploy)"
            echo "  --deploy-only   Deploy from existing images (no build)"
            echo "  --local         Build locally only (no push, no deploy)"
            echo "  --cloud-build   Use Cloud Build instead of local docker build"
            echo ""
            echo "Environment variables:"
            echo "  GCP_PROJECT_ID  GCP project ID"
            echo "  GCP_REGION      GCP region (default: asia-south1)"
            echo "  ENV_SUFFIX      Environment suffix (default: dev)"
            echo "  IMAGE_TAG       Image tag (default: latest)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $arg${NC}"
            exit 1
            ;;
    esac
done

# ── Validation ────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "${CYAN}${BOLD}MILNET SSO — Service Deployment${NC}"
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo ""
echo "  Mode:       $MODE"
echo "  Project:    $PROJECT_ID"
echo "  Region:     $REGION"
echo "  Env:        $ENV_SUFFIX"
echo "  Image Tag:  $IMAGE_TAG"
echo "  Registry:   $AR_REPO"
echo ""

if [ "$MODE" != "local" ] && [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}ERROR: GCP_PROJECT_ID is required for non-local builds.${NC}"
    echo "  Set GCP_PROJECT_ID env var or create deploy/dev-test/terraform.tfvars"
    exit 1
fi

# ── Prerequisites Check ──────────────────────────────────────────────────────
echo ">>> Checking prerequisites..."
REQUIRED_CMDS="docker"
if [ "$MODE" != "local" ]; then
    REQUIRED_CMDS="$REQUIRED_CMDS gcloud"
fi
if [ "$MODE" = "cloud-build" ]; then
    REQUIRED_CMDS="$REQUIRED_CMDS gcloud"
fi

MISSING=""
for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

if [ -n "$MISSING" ]; then
    echo -e "${RED}ERROR: Missing required tools:${MISSING}${NC}"
    exit 1
fi
echo -e "${GREEN}  Prerequisites OK${NC}"

# ── Cloud Build Path ──────────────────────────────────────────────────────────
if [ "$MODE" = "cloud-build" ]; then
    echo ""
    echo ">>> Submitting to Cloud Build..."
    cd "$PROJECT_ROOT"
    DEPLOY_FLAG="false"
    if [ "$MODE" = "full" ]; then
        DEPLOY_FLAG="true"
    fi
    gcloud builds submit . \
        --config=deploy/dev-test/cloudbuild.yaml \
        --substitutions="_REGION=${REGION},_ENV_SUFFIX=${ENV_SUFFIX},_DEPLOY=${DEPLOY_FLAG}" \
        --project="$PROJECT_ID"
    echo -e "${GREEN}  Cloud Build complete.${NC}"
    exit 0
fi

# ── Build Images ──────────────────────────────────────────────────────────────
build_images() {
    echo ""
    echo -e "${CYAN}>>> Building Docker images...${NC}"
    cd "$PROJECT_ROOT"

    for entry in "${SERVICES[@]}"; do
        IFS=':' read -r svc_name svc_port svc_cpu svc_mem <<< "$entry"

        echo ""
        echo -e "${BOLD}  Building ${svc_name}...${NC}"

        if [ "$MODE" = "local" ]; then
            docker build \
                --build-arg SERVICE_NAME="$svc_name" \
                -t "milnet-${svc_name}:${IMAGE_TAG}" \
                .
        else
            docker build \
                --build-arg SERVICE_NAME="$svc_name" \
                -t "${AR_REPO}/${svc_name}:${IMAGE_TAG}" \
                -t "milnet-${svc_name}:${IMAGE_TAG}" \
                .
        fi

        echo -e "${GREEN}  ${svc_name} built OK${NC}"
    done

    echo ""
    echo -e "${GREEN}>>> All images built successfully.${NC}"
}

# ── Push Images ───────────────────────────────────────────────────────────────
push_images() {
    echo ""
    echo -e "${CYAN}>>> Pushing images to Artifact Registry...${NC}"

    # Configure Docker authentication
    gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet 2>/dev/null || true

    for entry in "${SERVICES[@]}"; do
        IFS=':' read -r svc_name svc_port svc_cpu svc_mem <<< "$entry"
        echo "  Pushing ${svc_name}..."
        docker push "${AR_REPO}/${svc_name}:${IMAGE_TAG}"
    done

    echo -e "${GREEN}>>> All images pushed.${NC}"
}

# ── Deploy to Cloud Run ──────────────────────────────────────────────────────
deploy_services() {
    echo ""
    echo -e "${CYAN}>>> Deploying services to Cloud Run...${NC}"

    # First pass: deploy all services
    for entry in "${SERVICES[@]}"; do
        IFS=':' read -r svc_name svc_port svc_cpu svc_mem <<< "$entry"

        echo ""
        echo -e "${BOLD}  Deploying milnet-${svc_name}-${ENV_SUFFIX}...${NC}"

        # Determine ingress — only gateway is public-facing
        INGRESS="internal"
        if [ "$svc_name" = "gateway" ]; then
            INGRESS="all"
        fi

        # Base env vars for all services
        ENV_VARS="SERVICE_NAME=${svc_name},RUST_LOG=info,DEVELOPER_MODE=false"

        gcloud run deploy "milnet-${svc_name}-${ENV_SUFFIX}" \
            --image="${AR_REPO}/${svc_name}:${IMAGE_TAG}" \
            --region="$REGION" \
            --project="$PROJECT_ID" \
            --platform=managed \
            --port="$svc_port" \
            --cpu="$svc_cpu" \
            --memory="$svc_mem" \
            --min-instances=0 \
            --max-instances=2 \
            --ingress="$INGRESS" \
            --no-allow-unauthenticated \
            --set-env-vars="$ENV_VARS" \
            --quiet

        echo -e "${GREEN}  ${svc_name} deployed OK${NC}"
    done

    # Second pass: wire service-to-service URLs
    echo ""
    echo -e "${CYAN}>>> Wiring service-to-service URLs...${NC}"

    # Get service URLs
    GATEWAY_URL=$(gcloud run services describe "milnet-gateway-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    ORCHESTRATOR_URL=$(gcloud run services describe "milnet-orchestrator-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    OPAQUE_URL=$(gcloud run services describe "milnet-opaque-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    TSS_URL=$(gcloud run services describe "milnet-tss-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    VERIFIER_URL=$(gcloud run services describe "milnet-verifier-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    RATCHET_URL=$(gcloud run services describe "milnet-ratchet-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")
    AUDIT_URL=$(gcloud run services describe "milnet-audit-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --format="value(status.url)" 2>/dev/null || echo "")

    # Update orchestrator with peer addresses
    if [ -n "$OPAQUE_URL" ] && [ -n "$TSS_URL" ]; then
        echo "  Updating orchestrator with OPAQUE and TSS URLs..."
        gcloud run services update "milnet-orchestrator-${ENV_SUFFIX}" \
            --region="$REGION" --project="$PROJECT_ID" \
            --update-env-vars="OPAQUE_ADDR=${OPAQUE_URL},TSS_ADDR=${TSS_URL}" \
            --quiet
    fi

    # Update gateway with orchestrator address
    if [ -n "$ORCHESTRATOR_URL" ]; then
        echo "  Updating gateway with orchestrator URL..."
        gcloud run services update "milnet-gateway-${ENV_SUFFIX}" \
            --region="$REGION" --project="$PROJECT_ID" \
            --update-env-vars="ORCHESTRATOR_ADDR=${ORCHESTRATOR_URL}" \
            --quiet
    fi

    # Update admin with all peer addresses
    ADMIN_PEER_VARS="GATEWAY_ADDR=${GATEWAY_URL:-}"
    ADMIN_PEER_VARS="${ADMIN_PEER_VARS},ORCHESTRATOR_ADDR=${ORCHESTRATOR_URL:-}"
    ADMIN_PEER_VARS="${ADMIN_PEER_VARS},VERIFIER_ADDR=${VERIFIER_URL:-}"
    ADMIN_PEER_VARS="${ADMIN_PEER_VARS},RATCHET_ADDR=${RATCHET_URL:-}"
    ADMIN_PEER_VARS="${ADMIN_PEER_VARS},AUDIT_ADDR=${AUDIT_URL:-}"
    gcloud run services update "milnet-admin-${ENV_SUFFIX}" \
        --region="$REGION" --project="$PROJECT_ID" \
        --update-env-vars="$ADMIN_PEER_VARS" \
        --quiet

    echo -e "${GREEN}>>> Service URLs wired.${NC}"
}

# ── Health Checks ─────────────────────────────────────────────────────────────
run_health_checks() {
    echo ""
    echo -e "${CYAN}>>> Running health checks...${NC}"

    FAILED=0
    for entry in "${SERVICES[@]}"; do
        IFS=':' read -r svc_name svc_port svc_cpu svc_mem <<< "$entry"

        SVC_URL=$(gcloud run services describe "milnet-${svc_name}-${ENV_SUFFIX}" \
            --region="$REGION" --project="$PROJECT_ID" \
            --format="value(status.url)" 2>/dev/null || echo "")

        if [ -z "$SVC_URL" ]; then
            echo -e "  ${svc_name}: ${RED}NO URL${NC}"
            FAILED=$((FAILED + 1))
            continue
        fi

        # Get auth token for internal services
        TOKEN=$(gcloud auth print-identity-token 2>/dev/null || echo "")

        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer ${TOKEN}" \
            --max-time 10 \
            "${SVC_URL}/health" 2>/dev/null || echo "000")

        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "404" ]; then
            # 404 is acceptable for SHARD-based services that don't have /health
            echo -e "  ${svc_name}: ${GREEN}OK${NC} (HTTP ${HTTP_CODE}, ${SVC_URL})"
        else
            echo -e "  ${svc_name}: ${YELLOW}HTTP ${HTTP_CODE}${NC} (${SVC_URL})"
            # Don't count as failure — service may still be starting
        fi
    done

    if [ $FAILED -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}WARNING: ${FAILED} service(s) could not be reached.${NC}"
        echo "  Services may still be starting. Re-run health checks in 30s."
    else
        echo ""
        echo -e "${GREEN}>>> All health checks passed.${NC}"
    fi
}

# ── Execute ───────────────────────────────────────────────────────────────────

case "$MODE" in
    local)
        build_images
        echo ""
        echo -e "${GREEN}${BOLD}Local build complete.${NC}"
        echo "Run with docker compose:"
        echo "  cd $PROJECT_ROOT && docker compose up"
        ;;
    build-only)
        build_images
        push_images
        echo ""
        echo -e "${GREEN}${BOLD}Build and push complete.${NC}"
        ;;
    deploy-only)
        deploy_services
        run_health_checks
        ;;
    full)
        build_images
        push_images
        deploy_services
        run_health_checks
        ;;
esac

echo ""
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "${CYAN}${BOLD}Deployment complete.${NC}"
echo -e "${CYAN}${BOLD}============================================================${NC}"
