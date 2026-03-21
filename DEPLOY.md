# MILNET SSO Deployment Guide

## One-Click Deployment (Terraform)

### Prerequisites
- Google Cloud SDK (`gcloud`) installed and authenticated
- Terraform >= 1.5 installed
- GCP project with Compute Engine API enabled

### Deploy

```bash
# 1. Clone the repository
git clone https://github.com/divyamohan1993/enterprise-sso-system.git
cd enterprise-sso-system

# 2. Initialize Terraform
cd terraform
terraform init

# 3. Deploy (one command)
terraform apply -auto-approve

# 4. Wait ~10 minutes for Rust compilation on VM
# Check progress:
gcloud compute ssh milnet-sso-server --zone=us-central1-a --command="tail -f /var/log/milnet-sso-setup.log"

# 5. Access
terraform output sso_url
```

### Destroy

```bash
terraform destroy -auto-approve
```

### Existing Deployment

There is an existing VM `milnet-sso-server` at `35.192.67.16` that is already running.
The Terraform configuration is designed for new deployments. Do NOT destroy the existing VM.

## Manual Deployment (without Terraform)

```bash
# Create VM
gcloud compute instances create milnet-sso-server \
  --zone=us-central1-a \
  --machine-type=e2-medium \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --tags=milnet-sso \
  --metadata-from-file=startup-script=terraform/startup.sh

# Create firewall rule
gcloud compute firewall-rules create milnet-sso-allow \
  --allow=tcp:8080,tcp:22 \
  --target-tags=milnet-sso
```

## Update Deployment (pull latest code)

```bash
gcloud compute ssh milnet-sso-server --zone=us-central1-a --command="\
  cd /opt/milnet-sso && \
  git pull origin master && \
  cargo build --release -p admin && \
  sudo cp target/release/admin /usr/local/bin/admin && \
  sudo systemctl restart milnet-sso"
```

## Architecture on GCloud

```
VM (e2-medium, Debian 12)
├── PostgreSQL 15 (local)
│   └── milnet_sso database (7 tables)
├── /usr/local/bin/admin (Rust binary)
├── /usr/local/share/milnet-sso/frontend/ (static HTML)
└── systemd milnet-sso.service (auto-restart)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| ADMIN_PORT | 8080 | HTTP port |
| DATABASE_URL | postgres://milnet:...@localhost/milnet_sso | PostgreSQL connection |
| RUST_LOG | info | Log level |
| ADMIN_API_KEY | (auto-generated) | Admin API bearer token |
| SHARD_HMAC_KEY | (dev key) | Inter-service HMAC key |
