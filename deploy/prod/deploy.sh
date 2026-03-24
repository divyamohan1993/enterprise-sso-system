#!/usr/bin/env bash
# ============================================================================
# MILNET SSO — One-Click Production Deployment
# ============================================================================
# Usage: ./deploy.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo " MILNET SSO — Production Deployment"
echo " 3 isolated VMs, zero-trust architecture"
echo "============================================"
echo ""

# Preflight checks
if ! command -v terraform &>/dev/null; then
  echo "ERROR: terraform not found. Install from https://terraform.io"
  exit 1
fi

if ! command -v gcloud &>/dev/null; then
  echo "ERROR: gcloud not found. Install from https://cloud.google.com/sdk"
  exit 1
fi

if [ ! -f terraform.tfvars ]; then
  echo "ERROR: terraform.tfvars not found."
  echo "Copy terraform.tfvars.example to terraform.tfvars and fill in your values."
  exit 1
fi

echo "[1/4] Initializing Terraform..."
terraform init -input=false

echo ""
echo "[2/4] Planning deployment..."
terraform plan -input=false -out=tfplan

echo ""
echo "[3/4] Applying deployment..."
terraform apply -input=false -auto-approve tfplan
rm -f tfplan

echo ""
echo "[4/4] Waiting for VMs to initialize (60s)..."
sleep 60

echo ""
echo "============================================"
echo " DEPLOYMENT COMPLETE"
echo "============================================"
echo ""
terraform output -no-color

echo ""
echo "============================================"
echo " Service URLs"
echo "============================================"
GATEWAY_IP=$(terraform output -raw gateway_public_ip 2>/dev/null || echo "pending")
ADMIN_IP=$(terraform output -raw admin_api_url 2>/dev/null || echo "pending")
echo "  Gateway API:  http://${GATEWAY_IP}:9100"
echo "  Admin API:    ${ADMIN_IP}"
echo ""
echo "To destroy: terraform destroy -auto-approve"
echo "============================================"
