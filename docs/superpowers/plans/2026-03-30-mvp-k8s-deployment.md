# MVP K8s Deployment on C2 Spot VM

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the entire MILNET SSO system on a single c2-standard-8 VM using k3s, with Prometheus + Grafana monitoring and an nginx index page, to verify inter-service connectivity.

**Architecture:** Single-node k3s cluster. All services run as single-replica pods in dev mode (MILNET_DEV_MODE=1). Docker builds images locally, k3s imports them. Nginx reverse-proxies port 80 to an index page with links to all services.

**Tech Stack:** k3s, Docker, Helm (kube-prometheus-stack), nginx, PostgreSQL 16

---

### Task 1: Create MVP K8s Manifests

**Files:**
- Create: `deploy/kubernetes/mvp/namespace.yaml`
- Create: `deploy/kubernetes/mvp/configmap.yaml`
- Create: `deploy/kubernetes/mvp/secrets.yaml`
- Create: `deploy/kubernetes/mvp/postgres.yaml`
- Create: `deploy/kubernetes/mvp/services.yaml`
- Create: `deploy/kubernetes/mvp/gateway.yaml`
- Create: `deploy/kubernetes/mvp/orchestrator.yaml`
- Create: `deploy/kubernetes/mvp/tss.yaml`
- Create: `deploy/kubernetes/mvp/opaque.yaml`
- Create: `deploy/kubernetes/mvp/verifier.yaml`
- Create: `deploy/kubernetes/mvp/ratchet.yaml`
- Create: `deploy/kubernetes/mvp/risk.yaml`
- Create: `deploy/kubernetes/mvp/audit.yaml`
- Create: `deploy/kubernetes/mvp/kt.yaml`
- Create: `deploy/kubernetes/mvp/admin.yaml`
- Create: `deploy/kubernetes/mvp/monitoring.yaml`
- Create: `deploy/kubernetes/mvp/index-page.yaml`

Key differences from production manifests:
- All replicas: 1 (except TSS signers: 3 for 2-of-3 threshold)
- MILNET_DEV_MODE=1
- No pod anti-affinity (single node)
- Relaxed resource requests (100m CPU, 128Mi memory)
- Self-signed TLS certs generated at deploy time
- Random secrets generated at deploy time
- NodePort services for external access

### Task 2: Create Deploy Script

**Files:**
- Create: `deploy/kubernetes/mvp/deploy.sh`

Script will:
1. Install k3s if not present
2. Install Docker if not present
3. Install Helm if not present
4. Build all service images with Docker
5. Import images into k3s containerd
6. Generate self-signed TLS certs
7. Generate random secrets (KEK, TSS shares placeholder, DB password)
8. Apply all MVP manifests
9. Install kube-prometheus-stack via Helm
10. Wait for all pods to be ready
11. Print access URLs and credentials

### Task 3: Create Nginx Index Page

**Files:**
- Create: `deploy/kubernetes/mvp/index.html`

HTML page served on port 80 with:
- Links to SSO Gateway, Admin panel
- Links to Prometheus, Grafana
- Public credentials displayed on page
- Service health status indicators (JS polling)

### Task 4: Deploy and Verify

Run on C2 VM:
1. git pull
2. chmod +x deploy/kubernetes/mvp/deploy.sh
3. ./deploy/kubernetes/mvp/deploy.sh
4. Verify all pods running
5. Check inter-service connectivity
