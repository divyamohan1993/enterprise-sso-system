#!/bin/bash
set -e

# ==============================================================================
# ENTERPRISE K8S DEPLOYMENT SCRIPT
# ==============================================================================
# 1. Checks for K8s Cluster (kubectl)
# 2. Generates Production Secrets
# 3. Applies Manifests
# 4. Verifies Rollout
# ==============================================================================

LOG_FILE="deploy_k8s.log"
exec > >(tee -a $LOG_FILE) 2>&1

echo "[INFO] Starting K8s Deployment at $(date)..."

# 1. Check Prereqs
if ! command -v kubectl &> /dev/null; then
    echo "[ERROR] kubectl not found. Please install or configure access to your cluster."
    exit 1
fi

# 2. Generate Secrets & Update Manifests
echo "[INFO] Generating Secure Secrets..."
DB_PASS=$(openssl rand -base64 24)
JWT_SECRET=$(openssl rand -hex 64)

# Create/Update Secret Manifest directly to avoid file I/O sed issues
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: sso-enterprise
---
apiVersion: v1
kind: Secret
metadata:
  name: sso-secrets
  namespace: sso-enterprise
type: Opaque
stringData:
  DB_PASS: "$DB_PASS"
  JWT_SECRET: "$JWT_SECRET"
  GOOGLE_CLIENT_ID: "placeholder_id"
  GOOGLE_CLIENT_SECRET: "placeholder_secret"
EOF

# 3. Apply Infrastructure
echo "[INFO] Applying Database StatefulSet..."
kubectl apply -f k8s/01-database.yaml

echo "[INFO] Waiting for Database Identity..."
kubectl rollout status statefulset/sso-db -n sso-enterprise --timeout=120s || echo "[WARN] DB taking time to provision PVC?"

# 4. Apply App
echo "[INFO] Applying Application Deployment..."
kubectl apply -f k8s/02-app.yaml
kubectl apply -f k8s/03-ingress.yaml

echo "[INFO] Waiting for App Rollout..."
kubectl rollout status deployment/sso-app -n sso-enterprise --timeout=60s

echo "----------------------------------------------------------------"
echo "[SUCCESS] K8s Deployment Completed."
echo "Namespace: sso-enterprise"
echo "Service: sso-service"
echo "URL: http://vmip.dmj.one (Ensure your Ingress Controller is active)"
echo "----------------------------------------------------------------"
