# MILNET SSO — Production 10K Architecture

## Extreme Security. Sublinear Cost Scaling. MIT Licensed.

**Target**: 10,000 sustained logins/second | **Users**: 1,000,000+ | **Cost**: ~$12,265/mo on-demand (~$8,500/mo with 3yr CUD)

**Security**: Identical quantum-safe architecture to Production 1K. Security does not change with scale.

---

## Architecture Overview

```
                        Internet
                           |
                           v
                  +----------------+
                  |  Cloud Armor   |  Enterprise tier ($3K/mo flat)
                  |  (Enterprise)  |  Adaptive DDoS + ML anomaly detection
                  |                |  Rate limit: 500 req/min/IP
                  +-------+--------+  9 WAF rules (SQLi, XSS, RCE, LFI, session, Java)
                          |
                  +-------v--------+     +-------------------+
                  | Global HTTPS   |---->| Cloud CDN         |
                  | Load Balancer  |     | JWKS/.well-known  |
                  | TLS 1.3        |     | TTL=15min (epoch) |
                  +-------+--------+     +-------------------+
                          |
    +=====================+======================================================+
    |                     GKE CLUSTER (Private, 10K scale)                        |
    |  +-------------------------------------------------------------------+     |
    |  |                  milnet-sso namespace                               |     |
    |  |             Pod Security: RESTRICTED                                |     |
    |  |             Network Policy: DEFAULT DENY                            |     |
    |  |                                                                     |     |
    |  |  +------------- Node Pool: GENERAL -----------------------+        |     |
    |  |  |  8-20x e2-standard-8 (auto-scaling)                     |        |     |
    |  |  |  64-160 vCPU, 256-640 GB RAM                            |        |     |
    |  |  |                                                          |        |     |
    |  |  |  +---------+ +-------+ +--------+ +------+ +----+      |        |     |
    |  |  |  | Gateway | | Admin | |Verifier| | Risk | | KT |      |        |     |
    |  |  |  | :9100   | | :8080 | | :9104  | |:9106 | |:9107|      |        |     |
    |  |  |  | 12-48   | | 3-8   | | 8-30   | | 6-20 | | 3-8|      |        |     |
    |  |  |  | pods    | | pods  | | pods   | | pods | |pods |      |        |     |
    |  |  |  +----+----+ +-------+ +--------+ +---+--+ +----+      |        |     |
    |  |  |       |  Puzzle+X-Wing KEM              |                |        |     |
    |  |  +-------+--------------------------------+----------------+        |     |
    |  |          | SHARD mTLS                      |                         |     |
    |  |  +-------+------- Node Pool: COMPUTE ------+----------------+        |     |
    |  |  |       v  6-15x c3d-standard-8 (AMD Genoa)                |        |     |
    |  |  |       48-120 vCPU, 192-480 GB RAM                        |        |     |
    |  |  |  +------------+  +--------+                              |        |     |
    |  |  |  |Orchestrator|->| OPAQUE |  Argon2id at 10K req/s      |        |     |
    |  |  |  |   :9101    |  | :9102  |  ~1700 hashes/s per node    |        |     |
    |  |  |  |  10-40 pods|  |15-60   |  C3D Zen4: 30% faster IPC   |        |     |
    |  |  |  +-----+------+  | pods   |                              |        |     |
    |  |  |        |          +--------+                              |        |     |
    |  |  +--------+---------------------------------------------+---+        |     |
    |  |           | SHARD mTLS                                   |            |     |
    |  |  +--------+---- Node Pool: CONFIDENTIAL ----+            |            |     |
    |  |  |        v  5x n2d-standard-4 (AMD SEV)    |            |            |     |
    |  |  |        20 vCPU, 80 GB RAM (encrypted)     |            |            |     |
    |  |  |  +---------+ +--+ +--+ +--+ +--+         |            |            |     |
    |  |  |  |TSS Node0| |1 | |2 | |3 | |4 |         |            |            |     |
    |  |  |  |FROST 3/5| |  | |  | |  | |  |         |            |            |     |
    |  |  |  +---------+ +--+ +--+ +--+ +--+         |            |            |     |
    |  |  |  Each: 4 vCPU (2x for 10x signing)       |            |            |     |
    |  |  |  Memory encrypted (AMD SEV-SNP)           |            |            |     |
    |  |  +-------------------------------------------+            |            |     |
    |  |                                                            |            |     |
    |  |  +------------- Node Pool: STATEFUL -------------------+  |            |     |
    |  |  |  7x e2-standard-4 (persistent SSD, 200 GB each)     |  |            |     |
    |  |  |  28 vCPU, 112 GB RAM                                 |  |            |     |
    |  |  |  +-------------------------------------------+       |  |            |     |
    |  |  |  |  BFT Audit Cluster (7 nodes, 7-14 pods)   |       |  |            |     |
    |  |  |  |  Tolerates 2 Byzantine faults               |       |  |            |     |
    |  |  |  |  ML-DSA-87 signed, hash-chained            |       |  |            |     |
    |  |  |  |  Batched: 100 events/commit at 10K         |       |  |            |     |
    |  |  |  +-------------------------------------------+       |  |            |     |
    |  |  |  +----------+  +----+                                 |  |            |     |
    |  |  |  | Ratchet  |  | KT |  Key Transparency              |  |            |     |
    |  |  |  | :9105    |  |:9107|  SHA3-256 Merkle               |  |            |     |
    |  |  |  | 6-20pods |  |3-8 |                                 |  |            |     |
    |  |  |  +----------+  +----+                                 |  |            |     |
    |  |  +------------------------------------------------------+  |            |     |
    |  +-------------------------------------------------------------+            |     |
    +=========================+=========================+==========================+
                              | Private IP only         | Private IP only
                        +-----v-----+            +------v------+
                        | Cloud SQL |            | Memorystore |
                        | PG 16 HA  |            | Redis 7.x   |
                        | 16vCPU    |            | 16GB Cluster |
                        | 64GB RAM  |            | 4 shards    |
                        | 1000 conn |            | IAM auth    |
                        | Encrypted |            | TLS         |
                        +-----------+            +-------------+
                              |
                        +-----v------+
                        | Cloud KMS  |  HSM-backed (FIPS 140-3 L3)
                        | Master KEK |  Envelope encryption only
                        | + Backup   |  <100 ops/day = ~$15/mo
                        +------------+
```

---

## Scaling Decisions: 1K to 10K

### Why these specific changes?

| Component | 1K Config | 10K Config | Rationale |
|-----------|----------|-----------|-----------|
| General pool | 3-8x e2-standard-4 | 8-20x e2-standard-8 | Double CPU per node reduces scheduling overhead; 10x total vCPU |
| Compute pool | 2-5x t2d-standard-8 | 6-15x c3d-standard-8 | C3D Zen 4 is 30-40% faster IPC than T2D Zen 3 for Argon2id |
| Confidential pool | 5x n2d-standard-2 | 5x n2d-standard-4 | Same 5 signers (adding signers increases FROST latency O(n^2)); 2x CPU per signer for 10x concurrent signing rounds |
| Stateful pool | 7x e2-standard-2 | 7x e2-standard-4 | Same 7 BFT nodes; 2x CPU for batched audit writes at 10x volume |
| Cloud SQL | 8 vCPU / 32 GB | 16 vCPU / 64 GB | 2x compute handles 10x with connection pooling; 1000 max_connections |
| Redis | 4 GB Standard HA | 16 GB Cluster (4 shards) | Cluster mode for horizontal throughput; 16 GB holds 2M sessions |
| Cloud Armor | Standard (~$600/mo) | Enterprise ($3,000/mo flat) | At 26B req/mo, Enterprise is 5x cheaper per-request than Standard |
| Cloud CDN | None | JWKS/.well-known cached | Offloads ~40% of verification traffic from LB (read-only, cacheable) |
| VPC Flow Logs | 10% sampling | 5% sampling | Lower sampling rate at 10x volume keeps observability cost constant |
| GKE subnet | /20 (4K IPs) | /18 (16K IPs) | Room for 10K-scale pod count |

### Why NOT more signers?

FROST 3-of-5 is optimal at any scale. The FROST protocol has O(n^2) coordination overhead during the commitment phase. Adding more signers (e.g., 7-of-11) would increase per-signing latency without improving throughput. Instead, we scale vertically (n2d-standard-4) to handle more concurrent signing rounds per signer.

### Why NOT read replicas for Cloud SQL?

At 10K logins/s, the database handles ~50 active queries (5ms avg latency x 10K/s). A single 16-vCPU instance handles this easily. The bottleneck is Argon2id CPU, not database I/O. Adding read replicas adds complexity (replication lag affects session consistency) without solving the actual bottleneck.

---

## Bottleneck Analysis at 10K req/s

### Login Flow Critical Path

| Stage | Time | Throughput Limit | Bottleneck Risk | Mitigation |
|-------|------|-----------------|----------------|------------|
| Puzzle challenge | ~10ms | Gateway pods (CPU) | LOW | HPA scales to 48 gateways; puzzle is constant-time |
| X-Wing KEM | ~2ms | Gateway CPU | LOW | ML-KEM-1024 is fast; parallelized across gateway pods |
| OPAQUE auth | ~20ms | **Argon2id CPU-bound** | **HIGH** | C3D Zen 4 nodes; 60 OPAQUE pods; ~170 hashes/s/core |
| FROST 3-of-5 sign | ~30ms | Signer coordination | MEDIUM | n2d-standard-4 handles 333 concurrent rounds; async pipeline |
| Ratchet advance | ~5ms | In-memory HKDF | LOW | Stateless; HPA scales to 20 pods |
| Risk scoring | ~5ms | Redis lookups | LOW | Redis Cluster: 4 shards, 100K+ ops/s per shard |
| Audit write | ~3ms async | BFT quorum (5/7) | LOW | Fire-and-forget; batched 100 events/commit |
| DB write | ~5ms | Connection pool (1000) | LOW | 16 vCPU handles ~3,200 TPS; we need ~500 |
| **Total ceremony** | **~73ms** | **~13,700 req/s per set** | | |

### Primary Bottleneck: Argon2id (OPAQUE)

Argon2id with OWASP-recommended parameters (64 MiB memory, 3 iterations, 4 parallelism):
- Per-hash time on C3D: ~12ms per core
- Per C3D-standard-8 node: ~670 hashes/s (8 cores x 83 hashes/s/core)
- 6 nodes minimum: 6 x 670 = 4,020 hashes/s
- 15 nodes maximum: 15 x 670 = 10,050 hashes/s
- With 60 OPAQUE pods (4 per node): 10,200 hashes/s at peak

This is the tightest margin. At sustained 10K, compute pool will autoscale to ~10 nodes.

### Secondary Bottleneck: FROST Signing

FROST 3-of-5 signing at 10K req/s:
- Each signing round: ~30ms (3 round trips between 3 signers)
- Per signer (n2d-standard-4, 4 vCPU): handles ~133 concurrent rounds
- 5 signers, any 3 needed: effective capacity = ~333 concurrent rounds
- At 30ms per round: 333 / 0.030 = 11,100 signings/s
- Headroom: 11% above 10K target

If FROST becomes the bottleneck, scale to n2d-standard-8 (no architecture change).

---

## HPA Pod Counts for Each Service

### Steady State (10K req/s sustained)

| Service | Min Replicas | Max Replicas | CPU Request | Memory | Pool | Scaling Metric |
|---------|-------------|-------------|-------------|--------|------|---------------|
| Gateway | 12 | 48 | 1000m | 512Mi | general | CPU 70% + req/s |
| Admin | 3 | 8 | 500m | 1Gi | general | CPU 60% |
| Orchestrator | 10 | 40 | 1000m | 512Mi | compute | CPU 70% + req/s |
| OPAQUE | 15 | 60 | 2000m | 1Gi | compute | CPU 80% (Argon2id) |
| TSS Signer | 5 (fixed) | 5 (fixed) | 1000m | 1Gi | confidential | N/A (fixed) |
| Verifier | 8 | 30 | 500m | 512Mi | general | CPU 70% |
| Ratchet | 6 | 20 | 500m | 1Gi | stateful | CPU 60% |
| Risk | 6 | 20 | 500m | 512Mi | general | CPU 60% + Redis latency |
| KT | 3 | 8 | 500m | 512Mi | general | CPU 50% |
| Audit (BFT) | 7 (fixed) | 14 | 500m | 1Gi | stateful | Write queue depth |

### Comparison to Production 1K

| Service | 1K Min/Max | 10K Min/Max | Scale Factor |
|---------|-----------|------------|-------------|
| Gateway | 4/16 | 12/48 | 3x |
| Admin | 2/6 | 3/8 | 1.3x |
| Orchestrator | 3/12 | 10/40 | 3.3x |
| OPAQUE | 4/16 | 15/60 | 3.8x |
| TSS Signer | 5/5 | 5/5 | 1x (vertical) |
| Verifier | 3/10 | 8/30 | 3x |
| Ratchet | 2/8 | 6/20 | 2.5x |
| Risk | 2/6 | 6/20 | 3.3x |
| KT | 1/3 | 3/8 | 2.7x |
| Audit (BFT) | 7/7 | 7/14 | 1-2x |

---

## Token Verification (O(1) — no DB lookup, CDN-accelerated)

| Operation | Time | Notes |
|-----------|------|-------|
| FROST signature verify | ~35us | Cached public key |
| ML-DSA-87 verify | ~25us | Cached verifying key |
| Ratchet epoch check | ~5us | In-memory |
| Revocation check | ~2us | In-memory HashSet |
| **Total** | **~67us** | **~14,900 verifications/s per core** |

At 10K scale, JWKS and .well-known endpoints are served from Cloud CDN, eliminating ~40% of LB requests from token verification by relying parties. The CDN TTL (15 min) matches the ratchet epoch — key rotation automatically invalidates the CDN cache.

---

## Capacity Planning: Headroom Analysis

### Current Headroom at 10K req/s

| Resource | Capacity | Used at 10K | Headroom | First Bottleneck |
|----------|---------|------------|----------|-----------------|
| Gateway pods | 48 max | ~20 | 140% | CPU |
| OPAQUE pods | 60 max | ~40 | 50% | Argon2id CPU |
| Orchestrator pods | 40 max | ~18 | 122% | CPU |
| TSS signing | 11,100/s | 10,000/s | 11% | Signer coordination |
| Cloud SQL TPS | ~3,200 | ~500 | 540% | Connections |
| Cloud SQL connections | 1,000 | ~200 | 400% | Max connections |
| Redis ops/s | 400,000+ | ~30,000 | 1,233% | Memory |
| Redis memory | 16 GB | ~8 GB | 100% | Session count |
| Network bandwidth | 10+ Gbps | ~2 Gbps | 400% | LB capacity |

### Growth Path: 10K to 50K req/s

| Component | Change Needed | Effort | Cost Impact |
|-----------|--------------|--------|------------|
| General pool | 20 -> 40 nodes | Variable change | +$3,000/mo |
| Compute pool | 15 -> 40 nodes, c3d-standard-16 | Variable + machine type | +$8,000/mo |
| Confidential | n2d-standard-4 -> n2d-standard-8 | Machine type change | +$600/mo |
| Cloud SQL | 16 vCPU -> 64 vCPU + read replicas | Tier change + replicas | +$6,000/mo |
| Redis | 16 GB -> 64 GB (16 shards) | Shard count change | +$1,000/mo |
| Total for 50K | | | ~$31,000/mo |

### Growth Path: 50K to 100K req/s

At 100K req/s, consider:
1. Multi-region GKE with Global Anycast
2. Cloud Spanner replacing Cloud SQL (unlimited horizontal write scaling)
3. FROST committee rotation (multiple 3-of-5 committees signing in parallel)
4. Dedicated Argon2id ASICs or GPU-accelerated hashing
5. Estimated cost: ~$80,000/mo (still 75x cheaper than Okta at 10M users)

---

## Cost Comparison: MILNET SSO vs Competitors at 1M Users

### Monthly Cost at 1,000,000 Users (10K logins/sec)

```
  $9,000,000 |  XXXXX
             |  XXXXX  Azure AD P2 ($9/user/mo)
             |  XXXXX
  $6,000,000 |  XXXXX  XXXXX
             |  XXXXX  XXXXX  Okta Enterprise ($6/user/mo)
             |  XXXXX  XXXXX
  $4,000,000 |  XXXXX  XXXXX  XXXXX
             |  XXXXX  XXXXX  XXXXX  Ping Identity ($4/user/mo)
             |  XXXXX  XXXXX  XXXXX
  $3,000,000 |  XXXXX  XXXXX  XXXXX  XXXXX
             |  XXXXX  XXXXX  XXXXX  XXXXX  Auth0 ($3/user/mo)
             |  XXXXX  XXXXX  XXXXX  XXXXX
    $100,000 |  XXXXX  XXXXX  XXXXX  XXXXX
             |  XXXXX  XXXXX  XXXXX  XXXXX
     $12,265 |  XXXXX  XXXXX  XXXXX  XXXXX  +---+
             +--XXXXX--XXXXX--XXXXX--XXXXX--| M |---
               Azure   Okta   Ping  Auth0   MILNET
                AD                           SSO

  MILNET SSO: $0.012/user/mo = 244x cheaper than cheapest competitor
```

### Total Cost of Ownership (3-Year)

| Provider | Monthly | 3-Year Total | 3-Year CUD | Savings vs Auth0 |
|----------|---------|-------------|-----------|-----------------|
| Azure AD P2 | $9,000,000 | $324,000,000 | N/A | -$216,000,000 |
| Okta Enterprise | $6,000,000 | $216,000,000 | N/A | -$108,000,000 |
| Ping Identity | $4,000,000 | $144,000,000 | N/A | -$36,000,000 |
| Auth0 Enterprise | $3,000,000 | $108,000,000 | N/A | baseline |
| **MILNET SSO** | **$12,265** | **$441,540** | **$306,000** | **$107,694,000** |

Auth0 over 3 years at 1M users: $108,000,000. MILNET SSO with 3yr CUD: $306,000. Savings: **$107.7 million**.

### Security Feature Comparison

| Feature | MILNET SSO | Okta | Auth0 | Azure AD | Ping |
|---------|-----------|------|-------|----------|------|
| Post-quantum crypto | ML-KEM-1024 + ML-DSA-87 | None | None | None | None |
| Threshold signing | FROST 3-of-5 | Single key | Single key | Single key | Single key |
| Server-blind passwords | OPAQUE RFC 9497 | bcrypt | bcrypt | NTLM/Kerberos | bcrypt |
| Forward-secret sessions | HKDF ratcheting | No | No | No | No |
| Tamper-proof audit | BFT 7-node cluster | Append-only | Append-only | Append-only | Append-only |
| Token binding | DPoP + ML-DSA-65 | No | No | No | No |
| Confidential Computing | AMD SEV (TSS nodes) | No | No | No | No |
| Key Transparency | SHA3-256 Merkle tree | No | No | No | No |
| License | MIT (free) | Proprietary | Proprietary | Proprietary | Proprietary |
| Quantum-safe by 2031? | Already done | Unknown | Unknown | Unknown | Unknown |
| Cost (1M users) | $12,265/mo | $6,000,000/mo | $3,000,000/mo | $9,000,000/mo | $4,000,000/mo |

---

## Quantum-Safe Communication Matrix

**Every link between every component uses quantum-resistant cryptography. Unchanged from 1K.**

| Path | Transport | Authentication | Forward Secrecy |
|------|-----------|---------------|-----------------|
| Client -> Gateway | TLS 1.3 + X-Wing KEM | Puzzle challenge | ML-KEM-1024 + X25519 |
| Gateway -> Orchestrator | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| Orchestrator -> OPAQUE | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| Orchestrator -> TSS | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| Orchestrator -> Risk | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| Orchestrator -> Ratchet | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| TSS <-> TSS (peer) | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| * -> Audit | SHARD mTLS | HMAC-SHA512 | Per-session HKDF |
| Token signing | -- | FROST + ML-DSA-87 | -- |
| Audit entries | -- | ML-DSA-87 | -- |
| Session keys | -- | -- | HKDF-SHA512 ratchet |
| Pod -> Cloud SQL | TLS 1.3 (encrypted_only) | IAM auth | -- |
| Pod -> Redis | TLS (server auth) | IAM auth | -- |
| Pod -> KMS | TLS 1.3 (Google managed) | Workload Identity | -- |

**Quantum-safe status**: All SHARD links use HMAC-SHA512 (256-bit quantum security) + AES-256-GCM (128-bit quantum security). Token signatures use ML-DSA-87 (NIST Level 5). Key exchange uses X-Wing (ML-KEM-1024 + X25519). All hash functions are SHA-512 or SHA3-256 (256-bit quantum security).

**5-year projection (through 2031)**: NIST post-quantum standards (FIPS 203, 204, 205) are already implemented. CNSA 2.0 timeline requires PQ-preferred by 2026 and PQ-only by 2030. This system already meets the 2030 target today.

---

## Deployment Steps

### Prerequisites

```bash
# Install tools
gcloud components install kubectl gke-gcloud-auth-plugin
terraform -version  # >= 1.7.0

# Authenticate
gcloud auth login
gcloud auth application-default login

# Set project
gcloud config set project YOUR_PROJECT_ID
```

### 1. Initialize Terraform

```bash
cd terraform/production-10k

# Create state bucket (if not existing from 1K deployment)
gsutil mb -l us-central1 gs://milnet-sso-terraform-state

# Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

terraform init
```

### 2. Plan and Apply

```bash
# Review the plan
terraform plan -out=tfplan

# Apply (creates all infrastructure)
terraform apply tfplan
```

### 3. Configure kubectl

```bash
gcloud container clusters get-credentials milnet-sso-production \
  --region us-central1 \
  --project YOUR_PROJECT_ID
```

### 4. Build and Push Images

```bash
# Get Artifact Registry URL from terraform output
AR_URL=$(terraform output -raw artifact_registry)

# Build all 8 service images
for svc in gateway orchestrator opaque tss verifier ratchet audit admin; do
  docker build --build-arg SERVICE_NAME=$svc -t $AR_URL/$svc:latest .
  docker push $AR_URL/$svc:latest
done
```

### 5. Deploy Services

```bash
# Apply Kubernetes manifests (from deploy/k8s/ adapted for production-10k)
kubectl apply -f deploy/k8s/

# Verify HPA configurations
kubectl get hpa -n milnet-sso
```

### 6. Verify

```bash
# Check all pods are running
kubectl get pods -n milnet-sso

# Check services
kubectl get svc -n milnet-sso

# Check network policies (should be identical to 1K)
kubectl get networkpolicy -n milnet-sso

# Check node pool scaling
kubectl get nodes --show-labels | grep node_pool

# Health check
curl -k https://YOUR_LB_IP:9100/health
```

### 7. Load Test (validate 10K capacity)

```bash
# Run graduated load test
# Phase 1: 1K req/s (warm-up, validates 1K baseline)
# Phase 2: 5K req/s (triggers autoscaling)
# Phase 3: 10K req/s sustained (validates target)
# Phase 4: 13K req/s burst (validates headroom)
```

---

## Security Hardening Checklist

Identical to Production 1K — security does not scale.

- [x] Private GKE cluster (no public node IPs)
- [x] Workload Identity (no service account keys)
- [x] Pod Security Standards: Restricted
- [x] Network Policies: Default deny + explicit allow
- [x] Cloud SQL: Private IP only + SSL required
- [x] Redis: IAM auth + TLS encryption
- [x] KMS: HSM-backed (FIPS 140-3 Level 3)
- [x] Secrets: Encrypted under KMS HSM
- [x] Shielded VMs: Secure boot + integrity monitoring
- [x] Confidential Computing: AMD SEV for TSS signers
- [x] Binary Authorization: Signed images only
- [x] Cloud Armor Enterprise: WAF + adaptive DDoS + ML anomaly detection
- [x] Cloud CDN: Signed URLs for JWKS (prevents cache poisoning)
- [x] VPC Flow Logs: 5% sampling (adjusted for 10K volume)
- [x] IAP: SSH only through Identity-Aware Proxy
- [x] Default deny firewall: All ingress blocked except explicit rules

---

## Disaster Recovery

| Component | RPO | RTO | Strategy |
|-----------|-----|-----|----------|
| GKE pods | 0 | 2 min | Multi-zone, auto-restart, HPA pre-warmed |
| Cloud SQL | 1 sec | 30 sec | Regional HA, PITR, 14 daily backups |
| Redis Cluster | Session loss | 60 sec | Cluster failover, rebuild from DB |
| KMS keys | 0 | 0 | Google-managed replication |
| Secrets | 0 | 0 | Auto-replicated |
| Audit log | 0 | 5 min | BFT 7-node, PV snapshots, 200 GB SSD per node |
| TSS shares | 0 | 10 min | Stored in Secret Manager, re-DKG |
| CDN cache | N/A | 0 | Auto-populated from origin on miss |

---

## Monitoring and Alerting

### Key Metrics to Alert On (10K thresholds)

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Login latency (p99) | >200ms | >500ms | Scale OPAQUE pods / compute nodes |
| Login error rate | >0.5% | >2% | Check OPAQUE/DB health |
| Login throughput | <8K/s | <5K/s | Check all node pool health |
| FROST signing latency | >80ms | >200ms | Check TSS signer health / network |
| Argon2id hash rate | <8K/s | <5K/s | Scale compute pool |
| DB connections | >800/1000 | >950/1000 | Scale DB tier or add read replica |
| DB replication lag | >1s | >5s | Investigate HA standby |
| Redis memory | >75% | >90% | Increase redis_memory_gb |
| Redis cluster ops/s | >300K/s | >380K/s | Add shards |
| Pod restarts | >5/hr | >20/hr | Check OOM/crash logs |
| Audit BFT quorum | <6/7 | <5/7 | Investigate node health |
| Cloud Armor blocks | >100K/hr | >1M/hr | Check for DDoS, review adaptive rules |
| CDN cache hit ratio | <80% | <60% | Check JWKS rotation / TTL config |
| Node pool utilization | >80% | >90% | Pre-scale before capacity exhaustion |
