# MILNET SSO — Replication Guide

Complete instructions to replicate the entire MILNET SSO deployment from scratch on Google Cloud Platform.

## GCP Resources and Costs

| Resource | SKU | Monthly Cost (est.) | Notes |
|---|---|---|---|
| Gateway VM | e2-small, SPOT, asia-south1-a | ~$5-8 | Preemptible; auto-deleted on eviction |
| Core VM | e2-small, SPOT, asia-south1-a | ~$5-8 | Runs admin, opaque, verifier, ratchet, audit |
| TSS VM | e2-small, SPOT, asia-south1-a | ~$5-8 | 3 FROST threshold instances |
| Cloud SQL | db-f1-micro, PostgreSQL 15 | ~$8 | 10 GB HDD, zonal, no backups |
| Cloud KMS HSM | 1 keyring, 2 keys (AES-256 + EC_SIGN_P256) | ~$1-3 | Pay per cryptographic operation |
| Artifact Registry | Docker repo, storage only | ~$0.10/GB | 8 service images, ~2-4 GB total |
| Cloud Build | Pay per build minute | ~$0-3 | Only during CI/CD builds |
| Networking | VPC, firewall rules, ephemeral IPs | ~$0-2 | Minimal; no load balancer |
| **Total** | | **~$25-40/month** | |

SPOT VM pricing fluctuates. Actual costs depend on region and preemption frequency.

## Prerequisites

1. A GCP project with billing enabled
2. `gcloud` CLI installed and authenticated
3. Rust toolchain (1.75+) with `x86_64-unknown-linux-gnu` target
4. Terraform >= 1.5 (optional, for automated infra)

```bash
# Install gcloud
curl https://sdk.cloud.google.com | bash
gcloud init

# Authenticate
gcloud auth login
gcloud auth application-default login
```

## Step 1: Set Up the GCP Project (~5 minutes)

```bash
export PROJECT_ID="your-project-id"
export REGION="asia-south1"
export ZONE="asia-south1-a"

gcloud config set project $PROJECT_ID
gcloud config set compute/region $REGION
gcloud config set compute/zone $ZONE

# Enable required APIs
gcloud services enable \
  compute.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  cloudkms.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  servicenetworking.googleapis.com
```

## Step 2: Create Service Accounts (~3 minutes)

Three service accounts enforce security separation: gateway sees nothing, core sees DB+KMS, TSS sees nothing.

```bash
# Gateway SA — logging only
gcloud iam service-accounts create milnet-gateway-sa \
  --display-name="MILNET Gateway (no secrets)"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:milnet-gateway-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

# Core SA — DB + KMS + Secret Manager
gcloud iam service-accounts create milnet-core-sa \
  --display-name="MILNET Core (DB + KMS)"
for ROLE in roles/cloudsql.client roles/cloudkms.cryptoKeyEncrypterDecrypter roles/secretmanager.secretAccessor roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:milnet-core-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="$ROLE"
done

# TSS SA — logging only
gcloud iam service-accounts create milnet-tss-sa \
  --display-name="MILNET TSS (threshold shares only)"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:milnet-tss-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"
```

## Step 3: Create VPC and Firewall Rules (~2 minutes)

```bash
# Create VPC
gcloud compute networks create milnet-vpc --subnet-mode=custom

# Create subnet
gcloud compute networks subnets create milnet-subnet \
  --network=milnet-vpc \
  --region=$REGION \
  --range=10.160.0.0/24 \
  --enable-private-ip-google-access

# Firewall: gateway port (public)
gcloud compute firewall-rules create milnet-fw-gateway \
  --network=milnet-vpc \
  --allow=tcp:9100 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=milnet-gateway

# Firewall: admin API (public)
gcloud compute firewall-rules create milnet-fw-core-admin \
  --network=milnet-vpc \
  --allow=tcp:8080 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=milnet-core

# Firewall: internal inter-service traffic
gcloud compute firewall-rules create milnet-fw-internal \
  --network=milnet-vpc \
  --allow=tcp:9101-9199 \
  --source-tags=milnet-gateway,milnet-core,milnet-tss \
  --target-tags=milnet-gateway,milnet-core,milnet-tss

# Firewall: SSH (restrict to IAP in production)
gcloud compute firewall-rules create milnet-fw-ssh \
  --network=milnet-vpc \
  --allow=tcp:22 \
  --source-ranges=35.235.240.0/20 \
  --target-tags=milnet-gateway,milnet-core,milnet-tss
```

## Step 4: Create Cloud SQL Instance (~10 minutes)

```bash
# Allocate private IP range for VPC peering
gcloud compute addresses create milnet-db-ip \
  --global \
  --purpose=VPC_PEERING \
  --addresses=10.161.0.0 \
  --prefix-length=20 \
  --network=milnet-vpc

# Create private services connection
gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=milnet-db-ip \
  --network=milnet-vpc

# Create the Cloud SQL instance
gcloud sql instances create milnet-sso-db \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=$REGION \
  --storage-type=HDD \
  --storage-size=10GB \
  --no-storage-auto-increase \
  --availability-type=zonal \
  --no-backup \
  --network=milnet-vpc \
  --no-assign-ip \
  --database-flags=max_connections=50

# Create database and user
DB_PASSWORD=$(openssl rand -base64 18)
gcloud sql databases create milnet_sso --instance=milnet-sso-db
gcloud sql users create milnet --instance=milnet-sso-db --password="$DB_PASSWORD"

echo "Database password: $DB_PASSWORD"
echo "Save this securely — you will need it for the VM startup scripts."
```

## Step 5: Create Cloud KMS HSM Keys (~2 minutes)

```bash
# Create keyring
gcloud kms keyrings create milnet-sso-keyring --location=$REGION

# Master KEK — AES-256, HSM protection, 90-day auto-rotation
gcloud kms keys create master-kek \
  --keyring=milnet-sso-keyring \
  --location=$REGION \
  --purpose=encryption \
  --default-algorithm=google-symmetric-encryption \
  --protection-level=hsm \
  --rotation-period=7776000s \
  --next-rotation-time=$(date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ)

# Token signing key — EC_SIGN_P256_SHA256, HSM
gcloud kms keys create token-signing-key \
  --keyring=milnet-sso-keyring \
  --location=$REGION \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-p256-sha256 \
  --protection-level=hsm
```

## Step 6: Create Artifact Registry (~1 minute)

```bash
gcloud artifacts repositories create milnet-sso-dev \
  --repository-format=docker \
  --location=$REGION \
  --description="MILNET SSO service images"

# Configure Docker auth
gcloud auth configure-docker ${REGION}-docker.pkg.dev
```

## Step 7: Build and Push Service Images (~15-25 minutes)

```bash
# Clone the repository
git clone https://github.com/divyamohan1993/enterprise-sso-system.git
cd enterprise-sso-system

# Build all 8 service binaries (release mode)
cargo build --release

# The services are:
#   gateway, orchestrator, opaque, tss, verifier, admin, ratchet, audit

AR_REPO="${REGION}-docker.pkg.dev/${PROJECT_ID}/milnet-sso-dev"

# Build and push Docker images for each service
for SERVICE in gateway orchestrator opaque tss verifier admin ratchet audit; do
  docker build -t ${AR_REPO}/${SERVICE}:latest --build-arg SERVICE=${SERVICE} .
  docker push ${AR_REPO}/${SERVICE}:latest
done
```

Alternatively, use the provided deploy script:

```bash
cd deploy/dev-test
./deploy-services.sh --build-only
```

## Step 8: Deploy the 3 VMs (~5 minutes)

```bash
# Get Cloud SQL private IP
DB_PRIVATE_IP=$(gcloud sql instances describe milnet-sso-db --format="value(ipAddresses[0].ipAddress)")

# ── Gateway VM ──
gcloud compute instances create milnet-gateway-vm \
  --zone=$ZONE \
  --machine-type=e2-small \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE \
  --no-restart-on-failure \
  --network-interface=subnet=milnet-subnet \
  --tags=milnet-gateway \
  --service-account=milnet-gateway-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-standard \
  --metadata=startup-script='#!/bin/bash
    # Install Rust, clone repo, build and run gateway + orchestrator
    apt-get update && apt-get install -y build-essential pkg-config libssl-dev
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    git clone https://github.com/divyamohan1993/enterprise-sso-system.git /opt/milnet
    cd /opt/milnet && cargo build --release -p gateway -p orchestrator
    # Start services via systemd (see deploy/dev-test/startup.sh for full script)
  '

# ── Core VM ──
gcloud compute instances create milnet-core-vm \
  --zone=$ZONE \
  --machine-type=e2-small \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE \
  --no-restart-on-failure \
  --network-interface=subnet=milnet-subnet \
  --tags=milnet-core \
  --service-account=milnet-core-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-standard \
  --metadata=db-host=$DB_PRIVATE_IP,db-password=$DB_PASSWORD,db-name=milnet_sso,db-user=milnet,startup-script='#!/bin/bash
    # Install Rust, clone repo, build and run core services
    apt-get update && apt-get install -y build-essential pkg-config libssl-dev
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    git clone https://github.com/divyamohan1993/enterprise-sso-system.git /opt/milnet
    cd /opt/milnet && cargo build --release -p opaque -p admin -p verifier -p ratchet -p audit
    # Configure DATABASE_URL from metadata, start services
  '

# ── TSS VM ──
gcloud compute instances create milnet-tss-vm \
  --zone=$ZONE \
  --machine-type=e2-small \
  --provisioning-model=SPOT \
  --instance-termination-action=DELETE \
  --no-restart-on-failure \
  --network-interface=subnet=milnet-subnet \
  --tags=milnet-tss \
  --service-account=milnet-tss-sa@${PROJECT_ID}.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-standard \
  --metadata=startup-script='#!/bin/bash
    # Install Rust, clone repo, build and run 3 TSS instances
    apt-get update && apt-get install -y build-essential pkg-config libssl-dev
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    git clone https://github.com/divyamohan1993/enterprise-sso-system.git /opt/milnet
    cd /opt/milnet && cargo build --release -p tss
    # Start 3 FROST instances on ports 9103, 9113, 9123
  '
```

For the full production-ready startup scripts with systemd units, environment wiring, and health checks, see `deploy/dev-test/startup.sh`.

## Step 9: Verify Deployment (~2 minutes)

```bash
# Get external IPs
GATEWAY_IP=$(gcloud compute instances describe milnet-gateway-vm --zone=$ZONE --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
CORE_IP=$(gcloud compute instances describe milnet-core-vm --zone=$ZONE --format="value(networkInterfaces[0].accessConfigs[0].natIP)")
TSS_IP=$(gcloud compute instances describe milnet-tss-vm --zone=$ZONE --format="value(networkInterfaces[0].accessConfigs[0].natIP)")

echo "Gateway:  $GATEWAY_IP:9100"
echo "Admin:    http://$CORE_IP:8080"
echo "TSS:      $TSS_IP (internal only)"

# Health check
curl -s http://$CORE_IP:8080/api/health | jq .

# Challenge page
curl -s http://$CORE_IP:8080/challenge | head -20
```

## Time Estimates Summary

| Step | Duration |
|---|---|
| 1. Project setup + API enablement | ~5 min |
| 2. Service accounts | ~3 min |
| 3. VPC + firewall | ~2 min |
| 4. Cloud SQL | ~10 min (instance creation is slow) |
| 5. Cloud KMS | ~2 min |
| 6. Artifact Registry | ~1 min |
| 7. Build + push images | ~15-25 min (Rust compile time) |
| 8. Deploy VMs | ~5 min |
| 9. Verify | ~2 min |
| **Total** | **~45-55 minutes** |

First-time Rust compilation on an e2-small takes 20-30 minutes. Subsequent builds with cached dependencies are much faster.

## Scaling Up: Sandbox to Production

| Dimension | Sandbox | Production |
|---|---|---|
| VMs | 3x e2-small SPOT | 3x e2-standard-4 (or larger), ON_DEMAND |
| Cloud SQL | db-f1-micro, HDD, no backups | db-custom-2-7680+, SSD, automated backups, HA (REGIONAL) |
| Cloud KMS | HSM (same) | HSM (same), add key versions for rotation |
| TSS nodes | 3 on 1 VM | 5 across 3+ separate VMs (or zones) |
| Networking | Plain TCP internal | mTLS between all services, private Google access |
| Load balancing | None (direct IP) | Cloud Load Balancer with managed TLS cert |
| Monitoring | Basic logging | Cloud Monitoring dashboards, alerting policies, uptime checks |
| VPC | Single subnet | Multi-region VPC, Cloud NAT, VPC Service Controls |
| Cost | ~$25-40/month | ~$200-500/month |

Production hardening checklist:
- Replace SPOT VMs with on-demand instances with automatic restart
- Enable Cloud SQL backups and point-in-time recovery
- Deploy TSS FROST nodes to separate VMs in different zones
- Add TLS termination (Cloud Load Balancer or nginx with Let's Encrypt)
- Use vTPM-enabled VMs (e.g., Shielded VMs) for platform attestation
- Rotate the master KEK via KMS key versioning
- Set up Cloud Monitoring alerts for CPU, memory, disk, and service health
- Enable VPC Flow Logs and Cloud Audit Logs
- Restrict SSH to IAP-only (remove `0.0.0.0/0` source range)

## Complete Teardown

Destroy all resources to stop billing. Order matters: delete VMs first, then SQL, then networking.

```bash
export PROJECT_ID="your-project-id"
export ZONE="asia-south1-a"
export REGION="asia-south1"

# 1. Delete VMs
gcloud compute instances delete milnet-gateway-vm milnet-core-vm milnet-tss-vm \
  --zone=$ZONE --project=$PROJECT_ID --quiet

# 2. Delete Cloud SQL
gcloud sql instances delete milnet-sso-db --project=$PROJECT_ID --quiet

# 3. Delete Artifact Registry (and all images)
gcloud artifacts repositories delete milnet-sso-dev \
  --location=$REGION --project=$PROJECT_ID --quiet

# 4. Delete firewall rules
gcloud compute firewall-rules delete \
  milnet-fw-gateway milnet-fw-core-admin milnet-fw-internal milnet-fw-ssh \
  --project=$PROJECT_ID --quiet

# 5. Delete VPC peering and subnet
gcloud compute addresses delete milnet-db-ip --global --project=$PROJECT_ID --quiet
gcloud compute networks subnets delete milnet-subnet \
  --region=$REGION --project=$PROJECT_ID --quiet
gcloud compute networks delete milnet-vpc --project=$PROJECT_ID --quiet

# 6. Delete service accounts
for SA in milnet-gateway-sa milnet-core-sa milnet-tss-sa; do
  gcloud iam service-accounts delete ${SA}@${PROJECT_ID}.iam.gserviceaccount.com \
    --project=$PROJECT_ID --quiet
done

# 7. Destroy KMS key versions (keyring and key names cannot be deleted)
KEYRING="milnet-sso-keyring"
for KEY in master-kek token-signing-key; do
  VERSIONS=$(gcloud kms keys versions list \
    --key=$KEY --keyring=$KEYRING --location=$REGION \
    --filter="state=ENABLED OR state=DISABLED" \
    --format="value(name)" --project=$PROJECT_ID)
  for V in $VERSIONS; do
    gcloud kms keys versions destroy "$V" --project=$PROJECT_ID --quiet
  done
done

echo "All resources destroyed. KMS keyring names persist (GCP limitation) but keys are destroyed."
```

## Using Terraform (Alternative)

The `deploy/dev-test/` directory contains a complete Terraform configuration that automates all of the above.

```bash
cd deploy/dev-test

# Copy and edit the variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set project_id, region, zone

# Deploy everything
./deploy.sh

# Or manually:
terraform init
terraform plan
terraform apply -auto-approve

# Tear down
terraform destroy -auto-approve
```

The Terraform config creates all resources with random suffixes to avoid name collisions, and uses `create_before_destroy = false` to ensure clean-slate deployments.
