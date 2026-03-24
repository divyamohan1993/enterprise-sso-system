#!/bin/bash
# ============================================================================
# MILNET SSO — Dev/Test Deploy Script
# ============================================================================
# Authenticates, destroys previous resources, deploys fresh, tails test output.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}MILNET SSO — Dev/Test Deployment${NC}"
echo -e "${CYAN}============================================================${NC}"

# ── 1. Check Prerequisites ──────────────────────────────────────────────────

echo ""
echo ">>> [1/7] Checking prerequisites..."

MISSING=""
for cmd in gcloud terraform jq; do
  if ! command -v "$cmd" &>/dev/null; then
    MISSING="$MISSING $cmd"
  fi
done

if [ -n "$MISSING" ]; then
  echo -e "${RED}ERROR: Missing required tools:${MISSING}${NC}"
  echo "  gcloud:    https://cloud.google.com/sdk/install"
  echo "  terraform: https://developer.hashicorp.com/terraform/install"
  echo "  jq:        apt-get install jq"
  exit 1
fi

echo "  All prerequisites found."

# ── 2. Check GCP Authentication ─────────────────────────────────────────────

echo ""
echo ">>> [2/7] Checking GCP authentication..."

ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null || echo "")
if [ -z "$ACCOUNT" ]; then
  echo -e "${YELLOW}Not authenticated. Running gcloud auth login...${NC}"
  gcloud auth login
  gcloud auth application-default login
fi

ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
echo "  Authenticated as: $ACCOUNT"

# Verify application-default credentials exist
if ! gcloud auth application-default print-access-token &>/dev/null; then
  echo -e "${YELLOW}Application default credentials not set. Running gcloud auth application-default login...${NC}"
  gcloud auth application-default login
fi

# Read project ID from tfvars
if [ -f "terraform.tfvars" ]; then
  PROJECT_ID=$(grep -E '^\s*project_id\s*=' terraform.tfvars | sed 's/.*=\s*"\(.*\)"/\1/')
elif [ -f "terraform.tfvars.example" ]; then
  echo -e "${YELLOW}No terraform.tfvars found. Copy terraform.tfvars.example to terraform.tfvars and edit it.${NC}"
  exit 1
else
  echo -e "${RED}ERROR: No terraform.tfvars or terraform.tfvars.example found.${NC}"
  exit 1
fi

echo "  Project: $PROJECT_ID"
gcloud config set project "$PROJECT_ID" 2>/dev/null

# ── 3. Terraform Init ───────────────────────────────────────────────────────

echo ""
echo ">>> [3/7] Initializing Terraform..."
terraform init -input=false -upgrade

# ── 4. Destroy Previous Resources ───────────────────────────────────────────

echo ""
echo ">>> [4/7] Destroying previous deployment (clean slate)..."
if terraform state list &>/dev/null 2>&1 && [ "$(terraform state list 2>/dev/null | wc -l)" -gt 0 ]; then
  terraform destroy -auto-approve -parallelism=20
  echo -e "${GREEN}  Previous resources destroyed.${NC}"
else
  echo "  No previous resources found."
fi

# ── 5. Apply New Deployment ─────────────────────────────────────────────────

echo ""
echo ">>> [5/7] Deploying fresh infrastructure..."
terraform apply -auto-approve -parallelism=20

APPLY_EXIT=$?
if [ $APPLY_EXIT -ne 0 ]; then
  echo -e "${RED}ERROR: terraform apply failed (exit code: $APPLY_EXIT)${NC}"
  echo "Check the error messages above and fix terraform.tfvars if needed."
  exit $APPLY_EXIT
fi

echo -e "${GREEN}  Infrastructure deployed successfully.${NC}"

# ── 6. Wait for VM Ready ────────────────────────────────────────────────────

echo ""
echo ">>> [6/7] Waiting for test runner VM to be ready..."

VM_NAME=$(terraform output -raw test_runner_name)
VM_ZONE=$(terraform output -json | jq -r '.ssh_command.value' | grep -oP '(?<=--zone=)\S+')

echo "  VM:   $VM_NAME"
echo "  Zone: $VM_ZONE"

# Wait for the VM to be RUNNING
MAX_WAIT=120
WAITED=0
while true; do
  STATUS=$(gcloud compute instances describe "$VM_NAME" \
    --zone="$VM_ZONE" --project="$PROJECT_ID" \
    --format="value(status)" 2>/dev/null || echo "UNKNOWN")

  if [ "$STATUS" = "RUNNING" ]; then
    echo "  VM is RUNNING."
    break
  fi

  WAITED=$((WAITED + 5))
  if [ $WAITED -ge $MAX_WAIT ]; then
    echo -e "${RED}ERROR: VM did not reach RUNNING state within ${MAX_WAIT}s (status: $STATUS)${NC}"
    exit 1
  fi

  echo "  VM status: $STATUS (waiting... ${WAITED}s)"
  sleep 5
done

# Wait for startup script to begin (SSH may not be ready immediately)
echo "  Waiting for SSH to be available..."
sleep 15

# ── 7. Tail Test Output ─────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}>>> [7/7] Tailing test output (Ctrl+C to detach)...${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Poll metadata for test status while tailing logs
TAIL_PID=""
{
  while true; do
    TEST_STATUS=$(gcloud compute instances describe "$VM_NAME" \
      --zone="$VM_ZONE" --project="$PROJECT_ID" \
      --format="value(metadata.items[key=test-status].value)" 2>/dev/null || echo "unknown")

    case "$TEST_STATUS" in
      passed)
        echo ""
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        echo -e "${GREEN}============================================================${NC}"

        # Print summary from metadata
        PASSED=$(gcloud compute instances describe "$VM_NAME" --zone="$VM_ZONE" --project="$PROJECT_ID" --format="value(metadata.items[key=test-passed].value)" 2>/dev/null || echo "?")
        FAILED=$(gcloud compute instances describe "$VM_NAME" --zone="$VM_ZONE" --project="$PROJECT_ID" --format="value(metadata.items[key=test-failed].value)" 2>/dev/null || echo "?")
        IGNORED=$(gcloud compute instances describe "$VM_NAME" --zone="$VM_ZONE" --project="$PROJECT_ID" --format="value(metadata.items[key=test-ignored].value)" 2>/dev/null || echo "?")
        echo "  Passed:  $PASSED"
        echo "  Failed:  $FAILED"
        echo "  Ignored: $IGNORED"

        # Kill the tail process if running
        [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
        exit 0
        ;;
      failed|failed:*)
        echo ""
        echo -e "${RED}============================================================${NC}"
        echo -e "${RED}TESTS FAILED: $TEST_STATUS${NC}"
        echo -e "${RED}============================================================${NC}"
        echo ""
        echo "SSH in to debug:"
        terraform output -raw ssh_command
        echo ""

        [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null || true
        exit 1
        ;;
    esac

    sleep 15
  done
} &
STATUS_PID=$!

# Tail the startup log via SSH (with retries)
RETRIES=0
MAX_RETRIES=5
while [ $RETRIES -lt $MAX_RETRIES ]; do
  gcloud compute ssh "$VM_NAME" \
    --zone="$VM_ZONE" --project="$PROJECT_ID" \
    --command="sudo tail -f /var/log/milnet-test.log 2>/dev/null || sudo tail -f /var/log/syslog" \
    --ssh-flag="-o StrictHostKeyChecking=no" \
    --ssh-flag="-o ConnectTimeout=10" \
    2>/dev/null && break

  RETRIES=$((RETRIES + 1))
  echo "  SSH connection failed, retrying ($RETRIES/$MAX_RETRIES)..."
  sleep 10
done

# Wait for status polling to finish
wait "$STATUS_PID" 2>/dev/null
exit $?
