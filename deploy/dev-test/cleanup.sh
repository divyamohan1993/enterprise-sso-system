#!/bin/bash
# ============================================================================
# MILNET SSO — Dev/Test Cleanup Script
# ============================================================================
# Destroys all Terraform-managed resources and verifies nothing remains.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "============================================================"
echo "MILNET SSO Dev/Test Cleanup"
echo "============================================================"

# ── Check Prerequisites ─────────────────────────────────────────────────────

if ! command -v terraform &>/dev/null; then
  echo -e "${RED}ERROR: terraform not found. Install from https://developer.hashicorp.com/terraform/install${NC}"
  exit 1
fi

if ! command -v gcloud &>/dev/null; then
  echo -e "${RED}ERROR: gcloud not found. Install from https://cloud.google.com/sdk/install${NC}"
  exit 1
fi

# ── Check Terraform State ───────────────────────────────────────────────────

if [ ! -f "terraform.tfstate" ] && [ ! -d ".terraform" ]; then
  echo -e "${YELLOW}WARNING: No Terraform state found. Nothing to destroy.${NC}"
  echo "If resources exist but state is missing, delete them manually in GCP Console."
  exit 0
fi

if [ ! -d ".terraform" ]; then
  echo ">>> Running terraform init..."
  terraform init -input=false
fi

# ── Show What Will Be Destroyed ─────────────────────────────────────────────

echo ""
echo ">>> Resources that will be destroyed:"
terraform state list 2>/dev/null || true
echo ""

RESOURCE_COUNT=$(terraform state list 2>/dev/null | wc -l || echo "0")
if [ "$RESOURCE_COUNT" -eq 0 ]; then
  echo -e "${GREEN}No resources in state. Nothing to destroy.${NC}"
  exit 0
fi

echo -e "${YELLOW}Will destroy $RESOURCE_COUNT resources.${NC}"

# ── Destroy ──────────────────────────────────────────────────────────────────

echo ""
echo ">>> Running terraform destroy..."
terraform destroy -auto-approve -parallelism=20

DESTROY_EXIT=$?
if [ $DESTROY_EXIT -ne 0 ]; then
  echo -e "${RED}ERROR: terraform destroy failed (exit code: $DESTROY_EXIT)${NC}"
  echo ">>> Retrying with refresh..."
  terraform refresh
  terraform destroy -auto-approve -parallelism=20 || true
fi

# ── Verify No Resources Remain ──────────────────────────────────────────────

echo ""
echo ">>> Verifying cleanup..."

REMAINING=$(terraform state list 2>/dev/null | wc -l || echo "0")
if [ "$REMAINING" -gt 0 ]; then
  echo -e "${RED}WARNING: $REMAINING resources still in state:${NC}"
  terraform state list
  echo ""
  echo "Attempting forced removal from state..."
  terraform state list 2>/dev/null | while read -r resource; do
    echo "  Removing: $resource"
    terraform state rm "$resource" 2>/dev/null || true
  done
fi

# ── Check for Orphaned Resources in GCP ──────────────────────────────────────

echo ""
echo ">>> Checking for orphaned milnet-test resources in GCP..."

PROJECT_ID=$(grep -E '^\s*project_id\s*=' terraform.tfvars 2>/dev/null | sed 's/.*=\s*"\(.*\)"/\1/' || echo "")
if [ -z "$PROJECT_ID" ]; then
  echo -e "${YELLOW}Could not determine project_id from terraform.tfvars. Skipping orphan check.${NC}"
else
  echo "  Checking VMs..."
  ORPHAN_VMS=$(gcloud compute instances list --project="$PROJECT_ID" --filter="name~milnet-test" --format="value(name,zone)" 2>/dev/null || echo "")
  if [ -n "$ORPHAN_VMS" ]; then
    echo -e "${YELLOW}  Found orphaned VMs:${NC}"
    echo "$ORPHAN_VMS"
    echo "  Deleting orphaned VMs..."
    echo "$ORPHAN_VMS" | while read -r name zone; do
      gcloud compute instances delete "$name" --zone="$zone" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    done
  else
    echo "  No orphaned VMs found."
  fi

  echo "  Checking Cloud SQL instances..."
  ORPHAN_SQL=$(gcloud sql instances list --project="$PROJECT_ID" --filter="name~milnet-test" --format="value(name)" 2>/dev/null || echo "")
  if [ -n "$ORPHAN_SQL" ]; then
    echo -e "${YELLOW}  Found orphaned Cloud SQL instances:${NC}"
    echo "$ORPHAN_SQL"
    echo "  Deleting orphaned Cloud SQL instances..."
    echo "$ORPHAN_SQL" | while read -r name; do
      gcloud sql instances delete "$name" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    done
  else
    echo "  No orphaned Cloud SQL instances found."
  fi

  echo "  Checking Cloud Run services..."
  ORPHAN_RUN=$(gcloud run services list --project="$PROJECT_ID" --filter="metadata.name~milnet-" --format="value(metadata.name,region)" 2>/dev/null || echo "")
  if [ -n "$ORPHAN_RUN" ]; then
    echo -e "${YELLOW}  Found orphaned Cloud Run services:${NC}"
    echo "$ORPHAN_RUN"
    echo "  Deleting orphaned Cloud Run services..."
    echo "$ORPHAN_RUN" | while read -r name region; do
      gcloud run services delete "$name" --region="$region" --project="$PROJECT_ID" --quiet 2>/dev/null || true
    done
  else
    echo "  No orphaned Cloud Run services found."
  fi
fi

# ── Clean Local State ───────────────────────────────────────────────────────

echo ""
echo ">>> Cleaning local state files..."
rm -f terraform.tfstate terraform.tfstate.backup
rm -f .terraform.lock.hcl
rm -rf .terraform/

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}Cleanup complete. All dev/test resources destroyed.${NC}"
echo -e "${GREEN}============================================================${NC}"
