# MILNET SSO — Hyper-Distributed Isolated VM Architecture

## Classification: ARCHITECT-LEVEL REFERENCE — FINAL TOPOLOGY

> **Design Axiom**: Full compromise of any N-1 VMs reveals ZERO plaintext.
> Attacker must simultaneously compromise ALL threshold participants,
> ALL database shards, AND the HSM — within a single ratchet epoch (30s) —
> or every key, certificate, port, and challenge mutates and the attack
> surface resets to zero.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [VM Inventory & Roles](#2-vm-inventory--roles)
3. [Network Topology](#3-network-topology)
4. [GCP Security Services Integration](#4-gcp-security-services-integration)
5. [Inter-VM Quantum-Safe Communication](#5-inter-vm-quantum-safe-communication)
6. [Auto-Mutation & Moving Target Defense](#6-auto-mutation--moving-target-defense)
7. [Threshold Distribution & No Single Point of Failure](#7-threshold-distribution--no-single-point-of-failure)
8. [Data Protection — Unbreakable Even with 1M Qubit QC](#8-data-protection--unbreakable-even-with-1m-qubit-qc)
9. [Autoscaling & Load Architecture](#9-autoscaling--load-architecture)
10. [Boot Chain & Attestation](#10-boot-chain--attestation)
11. [Failure Domains & Blast Radius](#11-failure-domains--blast-radius)
12. [Key Lifecycle & Rotation Schedule](#12-key-lifecycle--rotation-schedule)
13. [Deployment — Direct on VM, No Docker](#13-deployment--direct-on-vm-no-docker)
14. [Monitoring, Audit & Forensics](#14-monitoring-audit--forensics)
15. [Complete Firewall Matrix](#15-complete-firewall-matrix)
16. [Disaster Recovery & Self-Healing](#16-disaster-recovery--self-healing)
17. [Cost Estimation](#17-cost-estimation)

---

## 1. Design Principles

### 1.1 Zero Trust, Zero Shared Fate

Every VM is an **independent security domain**. No VM trusts any other VM implicitly.
Every message is authenticated, encrypted, and bound to a quantum-safe session.
Compromise of VM-A gives the attacker ZERO advantage in attacking VM-B.

### 1.2 Threshold Everything

- **Signing**: FROST 3-of-5 across 5 isolated TSS VMs (compromise 2 = nothing)
- **OPAQUE**: 2-of-3 threshold across 3 isolated OPAQUE VMs (compromise 1 = nothing)
- **Database**: 3-way sharded with secret-sharing (compromise 2 = nothing)
- **Audit**: 7-node BFT across 7 isolated VMs (tolerate 2 Byzantine = nothing)
- **Master KEK**: Shamir 3-of-5 split across Cloud HSM + 4 vTPM-sealed VMs

### 1.3 Auto-Mutation (Moving Target Defense)

Every cryptographic channel, port assignment, challenge nonce, and session key
**automatically rotates** on a schedule. An attacker who discovers a key, port,
or protocol detail has a **maximum exploitation window of 30 seconds** before
everything mutates and their knowledge becomes worthless.

### 1.4 Quantum-Safe at Every Layer

All inter-VM communication uses **X-Wing hybrid KEM** (X25519 + ML-KEM-1024)
with **ML-DSA-87** authentication. Even a 1-million-qubit quantum computer
running Shor's algorithm cannot break ML-KEM-1024 or ML-DSA-87.
Classical X25519 provides defense-in-depth against lattice breakthroughs.

### 1.5 No Docker, No Containers, No Abstraction Layers

Every service runs as a **native systemd unit** directly on the VM kernel.
This eliminates container escape attacks, Docker daemon vulnerabilities,
overlay filesystem overhead, and gives direct access to vTPM, HSM PKCS#11
interfaces, hardware entropy (RDRAND/RDSEED), and kernel security modules.

---

## 2. VM Inventory & Roles

### Overview: 21 VMs Across 8 Isolated Security Zones

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        GCP PROJECT: milnet-sso                              │
│                        REGION: asia-south1 (Mumbai)                         │
│                                                                             │
│  ┌─── ZONE 1: DMZ ──────────────────────────────────────────────────────┐   │
│  │  VM-01: BASTION-GATEWAY (C2 Spot MIG, autoscale 1→50)               │   │
│  │         ★ ONLY VM WITH PUBLIC IP ★                                   │   │
│  │         Services: gateway + admin (public endpoints only)            │   │
│  │         Secrets held: ZERO (stateless puzzle + proxy)                │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 2: CEREMONY ─────────────────────────────────────────────────┐  │
│  │  VM-02: ORCHESTRATOR-A     VM-03: ORCHESTRATOR-B                     │  │
│  │         Active/Standby ceremony state machines                       │  │
│  │         Secrets held: ZERO (stateless coordinator)                   │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 3: AUTH CORE ────────────────────────────────────────────────┐  │
│  │  VM-04: OPAQUE-SHARD-1   VM-05: OPAQUE-SHARD-2   VM-06: OPAQUE-3   │  │
│  │         2-of-3 threshold OPAQUE (each holds 1 Shamir share)          │  │
│  │         Compromise 1 = ZERO knowledge of any password                │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 4: SIGNING ──────────────────────────────────────────────────┐  │
│  │  VM-07  VM-08  VM-09  VM-10  VM-11   (5 TSS VMs)                    │  │
│  │  FROST 3-of-5 threshold signing — each holds 1 key share            │  │
│  │  Compromise 2 = ZERO ability to forge signatures                    │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 5: VERIFICATION ─────────────────────────────────────────────┐  │
│  │  VM-12: VERIFIER-A         VM-13: VERIFIER-B                         │  │
│  │         Stateless O(1) token verification (public keys only)         │  │
│  │  VM-14: RATCHET-A          VM-15: RATCHET-B                          │  │
│  │         Forward-secret session ratcheting (HA pair)                   │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 6: AUDIT (BFT) ──────────────────────────────────────────────┐ │
│  │  VM-16  VM-17  VM-18  VM-19  VM-20  (+ 2 more = 7 BFT nodes)        │ │
│  │  Spread across 3 availability zones (a, b, c)                        │ │
│  │  Tolerates 2 Byzantine failures, quorum = 5                          │ │
│  │  VM-16,17 in asia-south1-a | VM-18,19 in -b | VM-20+ in -c          │ │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 7: DATA ─────────────────────────────────────────────────────┐  │
│  │  VM-DB-1: PostgreSQL Primary    (asia-south1-a)                      │  │
│  │  VM-DB-2: PostgreSQL Sync Rep   (asia-south1-b)                      │  │
│  │  VM-DB-3: PostgreSQL Async Rep  (asia-south1-c)                      │  │
│  │  All use CMEK (Cloud KMS) + field-level envelope encryption          │  │
│  │  + Confidential Computing (AMD SEV-SNP memory encryption)            │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── ZONE 8: INTELLIGENCE ─────────────────────────────────────────────┐  │
│  │  VM-21: RISK + KT + WITNESS                                          │  │
│  │         Risk scoring, Key Transparency Merkle tree,                   │  │
│  │         External witness checkpoint publication                       │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── CLOUD SERVICES (No VMs — GCP Managed) ────────────────────────────┐  │
│  │  Cloud HSM (FIPS 140-2 L3)  |  Cloud KMS (CMEK)                      │  │
│  │  Cloud Armor (WAF + DDoS)   |  Secret Manager                        │  │
│  │  VPC Service Controls        |  Binary Authorization                   │  │
│  │  Cloud Audit Logs            |  Access Transparency                    │  │
│  │  Packet Mirroring            |  Cloud NAT (updates only)               │  │
│  │  Organization Policy         |  Security Command Center                │  │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 VM-01: BASTION-GATEWAY (DMZ)

| Property | Value |
|----------|-------|
| **Machine Type** | c2-standard-4 (Spot, autoscaling MIG) |
| **vCPUs** | 4 (burst to 50 instances) |
| **RAM** | 16 GB |
| **Disk** | 20 GB SSD (read-only root, dm-verity) |
| **Public IP** | YES — the ONLY VM with external IP |
| **OS** | Debian 12 (Shielded VM, Secure Boot, vTPM, UEFI) |
| **Services** | `gateway` (TCP 443), `admin` (TCP 8443) |
| **Secrets Held** | **ZERO** — stateless puzzle generator + encrypted proxy |
| **Scaling** | MIG: min=1, max=50, target CPU=60% |
| **Cloud Armor** | WAF policy with OWASP rules, rate limiting, geo-blocking |

**Why C2 Spot**: C2 instances provide sustained high-frequency CPU for
hash puzzle generation/verification. Spot pricing reduces cost 60-91%.
The MIG auto-replaces preempted instances within 30 seconds.

**Why zero secrets**: If this VM is fully compromised, the attacker gets
NOTHING — no keys, no passwords, no tokens. They see only encrypted
X-Wing tunnels to internal VMs they cannot reach.

### 2.2 VM-02, VM-03: ORCHESTRATOR (Ceremony Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-medium |
| **vCPUs** | 2 |
| **RAM** | 4 GB |
| **Disk** | 10 GB SSD |
| **Public IP** | NO |
| **Services** | `orchestrator` |
| **Secrets Held** | **ZERO** — stateless ceremony coordinator |
| **HA** | Active/standby with health-check failover |

**Why two**: Eliminates SPOF. If VM-02 dies, VM-03 takes over in <5s.
Orchestrator holds NO keys — it only routes messages between OPAQUE and TSS.

### 2.3 VM-04, VM-05, VM-06: OPAQUE SHARDS (Auth Core Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-medium |
| **vCPUs** | 2 |
| **RAM** | 4 GB |
| **Disk** | 30 GB SSD (encrypted, CMEK) |
| **Public IP** | NO |
| **Services** | `opaque` (threshold mode) |
| **Secrets Held** | 1 Shamir share of OPAQUE ServerSetup per VM |
| **Threshold** | 2-of-3 — need any 2 shards to authenticate |
| **Confidential VM** | YES — AMD SEV-SNP memory encryption |

**Why 3 VMs with 2-of-3**: Attacker compromising 1 OPAQUE VM gets ONE
Shamir share — mathematically useless without a second share.
Even with a 1M-qubit quantum computer, Shamir secret sharing over
a finite field is information-theoretically secure (not computationally
secure — TRULY unbreakable regardless of computing power).

### 2.4 VM-07 through VM-11: TSS SIGNING NODES (Signing Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-small |
| **vCPUs** | 2 |
| **RAM** | 2 GB |
| **Disk** | 10 GB SSD |
| **Public IP** | NO |
| **Services** | `tss` (one FROST share per VM) |
| **Secrets Held** | 1 FROST key share per VM |
| **Threshold** | 3-of-5 — need any 3 to sign a token |
| **Confidential VM** | YES — AMD SEV-SNP |

**Why 5 separate VMs**: Each VM holds exactly ONE FROST Ristretto255
key share. An attacker must compromise 3 of 5 VMs simultaneously.
With 2 compromised shares, they have ZERO ability to forge signatures.
The FROST scheme is information-theoretically secure below threshold.

**Cross-zone placement**:
- VM-07, VM-08: asia-south1-a
- VM-09, VM-10: asia-south1-b
- VM-11: asia-south1-c

This ensures a single availability zone failure cannot breach threshold.

### 2.5 VM-12, VM-13: VERIFIER (Verification Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-small |
| **vCPUs** | 2 |
| **RAM** | 2 GB |
| **Disk** | 10 GB SSD |
| **Public IP** | NO |
| **Services** | `verifier` |
| **Secrets Held** | Public verification keys ONLY (no private material) |
| **HA** | Active/active behind internal LB |

**Why safe**: Even full compromise reveals only PUBLIC keys.
Attacker gains zero advantage.

### 2.6 VM-14, VM-15: RATCHET (Verification Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-medium |
| **vCPUs** | 2 |
| **RAM** | 4 GB |
| **Disk** | 10 GB SSD |
| **Public IP** | NO |
| **Services** | `ratchet` |
| **Secrets Held** | Ephemeral session chain keys (forward-secret) |
| **HA** | Active/standby with state replication |
| **Confidential VM** | YES — AMD SEV-SNP |

**Why Confidential VM**: Ratchet chain keys exist in RAM. AMD SEV-SNP
encrypts all VM memory with a per-VM key managed by the AMD Secure
Processor. Even a hypervisor-level compromise cannot read the keys.

**Forward secrecy**: Even if compromised NOW, all PAST sessions remain
secure because old chain keys were cryptographically erased (zeroized +
munlocked). Attacker gets only current epoch's key, which mutates in ≤30s.

### 2.7 VM-16 through VM-20 (+2): AUDIT BFT NODES (Audit Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-small |
| **vCPUs** | 2 |
| **RAM** | 2 GB |
| **Disk** | 100 GB SSD (append-only audit logs) |
| **Public IP** | NO |
| **Services** | `audit` (BFT consensus) |
| **BFT** | 7 nodes, quorum=5, tolerates 2 Byzantine |
| **Placement** | 3 zones × 2-3 nodes each |

**Why 7 nodes across 3 zones**: Byzantine Fault Tolerance requires 3f+1
nodes to tolerate f failures. With 7 nodes (f=2), an attacker must
compromise 3+ audit nodes to inject false entries — and even then,
the hash chain + ML-DSA-87 signatures make tampering detectable.

### 2.8 VM-DB-1, VM-DB-2, VM-DB-3: DATABASE (Data Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-medium (primary), e2-small (replicas) |
| **vCPUs** | 2 |
| **RAM** | 4 GB (primary), 2 GB (replicas) |
| **Disk** | 100 GB SSD (CMEK encrypted) |
| **Public IP** | NO |
| **Services** | PostgreSQL 16 (native, no Cloud SQL) |
| **Replication** | Synchronous to DB-2, Async to DB-3 |
| **Encryption** | CMEK (Cloud KMS) + field-level AES-256-GCM envelope |
| **Confidential VM** | YES — AMD SEV-SNP |

**Triple protection**:
1. **Disk encryption**: CMEK via Cloud KMS (quantum-safe AES-256)
2. **Field encryption**: Application-level AES-256-GCM per sensitive field
3. **Memory encryption**: AMD SEV-SNP (prevents hypervisor snooping)

**Why NOT Cloud SQL**: Direct VM gives us vTPM attestation, Confidential
Computing, custom kernel hardening, dm-verity, and PKCS#11 HSM integration
that Cloud SQL does not support.

### 2.9 VM-21: RISK + KT + WITNESS (Intelligence Zone)

| Property | Value |
|----------|-------|
| **Machine Type** | e2-small |
| **vCPUs** | 2 |
| **RAM** | 2 GB |
| **Disk** | 20 GB SSD |
| **Public IP** | NO |
| **Services** | `risk`, `kt` (Key Transparency), witness checkpoints |
| **Secrets Held** | ML-DSA-87 witness signing key (vTPM-sealed) |

---

## 3. Network Topology

### 3.1 VPC Architecture

```
VPC: milnet-sso-vpc (MTU 1460, no auto-subnets)
│
├── Subnet: dmz-subnet          10.0.1.0/28   (14 hosts)  ← Gateway MIG
├── Subnet: ceremony-subnet     10.0.2.0/28   (14 hosts)  ← Orchestrators
├── Subnet: authcore-subnet     10.0.3.0/28   (14 hosts)  ← OPAQUE shards
├── Subnet: signing-subnet      10.0.4.0/28   (14 hosts)  ← TSS nodes
├── Subnet: verify-subnet       10.0.5.0/28   (14 hosts)  ← Verifier + Ratchet
├── Subnet: audit-subnet        10.0.6.0/28   (14 hosts)  ← BFT audit nodes
├── Subnet: data-subnet         10.0.7.0/28   (14 hosts)  ← PostgreSQL cluster
└── Subnet: intel-subnet        10.0.8.0/28   (14 hosts)  ← Risk + KT + Witness
```

### 3.2 Firewall Rules — Default DENY ALL

```
PRIORITY 0:    DENY ALL ingress   (default)
PRIORITY 0:    DENY ALL egress    (default — no internet except Cloud NAT for apt)
PRIORITY 100:  ALLOW IAP SSH      (Identity-Aware Proxy only — no direct SSH)
PRIORITY 200:  ALLOW health-check (GCP LB health check source ranges)
PRIORITY 1000: ALLOW specific inter-zone traffic (see §15 matrix)
```

**No VM can reach any other VM** unless explicitly permitted in the
firewall matrix. Even within the same subnet, inter-VM traffic is
denied by default and only allowed for specific service ports.

### 3.3 No Public IPs (Except Gateway)

```
Organization Policy: constraints/compute.vmExternalIpAccess
  → DENY for all VMs except VM-01 instance template

All internal VMs access GCP APIs via Private Google Access.
Software updates via Cloud NAT (restricted egress to apt repos only).
SSH access via Identity-Aware Proxy (IAP) tunnel only.
```

### 3.4 VPC Service Controls Perimeter

```
Access Policy: milnet-sso-perimeter
  Protected Services:
    - compute.googleapis.com
    - secretmanager.googleapis.com
    - cloudkms.googleapis.com
    - storage.googleapis.com
    - logging.googleapis.com

  Access Levels:
    - Corporate VPN CIDR only
    - Device attestation required (BeyondCorp)

  Ingress Rules: NONE (no external API access)
  Egress Rules: NONE (no data exfiltration possible)
```

---

## 4. GCP Security Services Integration

### 4.1 Shielded VMs (ALL VMs)

Every VM runs as a **Shielded VM** with:

| Feature | Setting |
|---------|---------|
| **Secure Boot** | ENABLED — UEFI Secure Boot with custom DB keys |
| **vTPM** | ENABLED — Virtual TPM 2.0 for measured boot + key sealing |
| **Integrity Monitoring** | ENABLED — Alerts on boot sequence deviation |
| **Measured Boot** | PCR 0-7 baseline recorded and verified |

### 4.2 Confidential Computing (Sensitive VMs)

VMs holding secrets use **Confidential VM** (AMD SEV-SNP):

| VM | Confidential | Why |
|----|-------------|-----|
| OPAQUE shards (04-06) | YES | Shamir shares in RAM |
| TSS nodes (07-11) | YES | FROST key shares in RAM |
| Ratchet (14-15) | YES | Ephemeral chain keys in RAM |
| Database (DB-1,2,3) | YES | Query processing on sensitive data |
| All others | NO | No sensitive material in RAM |

**AMD SEV-SNP** encrypts all VM memory with a unique key managed by
the AMD Secure Processor (SP). The hypervisor, host OS, and even Google
engineers with physical access CANNOT read VM memory.

### 4.3 Cloud HSM (FIPS 140-2 Level 3)

```
Cloud KMS KeyRing: milnet-sso-keyring (asia-south1)
│
├── Key: master-kek
│   Protection: HSM (FIPS 140-2 L3)
│   Algorithm: AES-256-GCM (quantum-safe symmetric)
│   Purpose: ENCRYPT_DECRYPT
│   Rotation: 90 days automatic
│   Access: Only OPAQUE VMs + Admin VM via IAM
│
├── Key: audit-signing-key
│   Protection: HSM
│   Algorithm: EC_SIGN_P384_SHA384 (classical, HSM-backed)
│   Purpose: ASYMMETRIC_SIGN
│   Note: Backup for ML-DSA-87 software signing
│
├── Key: cmek-disk-key
│   Protection: HSM
│   Algorithm: AES-256-GCM
│   Purpose: ENCRYPT_DECRYPT (CMEK for all VM disks)
│   Rotation: 365 days automatic
│
└── Key: secret-manager-kek
    Protection: HSM
    Algorithm: AES-256-GCM
    Purpose: ENCRYPT_DECRYPT (wraps Secret Manager secrets)
```

### 4.4 Secret Manager

```
Secrets stored (all encrypted by Cloud HSM):
  milnet-opaque-share-1     → Accessible by VM-04 SA only
  milnet-opaque-share-2     → Accessible by VM-05 SA only
  milnet-opaque-share-3     → Accessible by VM-06 SA only
  milnet-frost-share-1..5   → Accessible by VM-07..11 SAs respectively
  milnet-receipt-signing-key → Accessible by OPAQUE VMs only
  milnet-db-password         → Accessible by DB VMs + OPAQUE/Admin VMs
  milnet-shard-hmac-key      → Accessible by all service VMs
  milnet-witness-signing-key → Accessible by VM-21 SA only
```

**Each secret is accessible by exactly ONE service account.**
No service account can read another service's secrets.

### 4.5 Binary Authorization

```
Policy: milnet-sso-binary-auth
  Default Rule: DENY
  Cluster Admission Rules:
    - Require attestation by: milnet-build-attestor
    - Attestor uses: Cloud KMS asymmetric key for signing
    - Only binaries built by Cloud Build with SHA-512 manifest pass

  Enforcement: Every binary on every VM is attested before execution.
  Unattested binaries are blocked by kernel-level enforcement (dm-verity).
```

### 4.6 Cloud Armor (WAF + DDoS — Gateway Only)

```
Security Policy: milnet-gateway-armor
│
├── Priority 100:  Allow GCP health check IPs
├── Priority 500:  Geo-block (allow only IN, US, allied nations)
├── Priority 1000: OWASP ModSecurity CRS 3.3 (SQLi, XSS, LFI, RFI, RCE)
├── Priority 2000: Request size limit (1 MiB max)
├── Priority 3000: Global rate limit (100 req/min per IP)
├── Priority 3100: Auth endpoint rate limit (20 req/min per IP)
├── Priority 4000: Adaptive protection (ML-based anomaly detection)
├── Priority 5000: Bot detection (known scanner UA blocking)
└── Priority 9999: Default DENY
```

### 4.7 Organization Policies

```
Enforced Organization Policies:
  compute.vmExternalIpAccess          → Deny (except Gateway template)
  compute.requireShieldedVm          → Require
  compute.vmCanIpForward             → Deny
  iam.disableServiceAccountKeyCreation → Deny (use Workload Identity)
  storage.uniformBucketLevelAccess    → Require
  compute.restrictLoadBalancerCreationForTypes → Internal only
  compute.disableSerialPortAccess     → Deny
  compute.disableNestedVirtualization → Deny
  compute.setNewProjectDefaultToZonalDNSOnly → Require
```

### 4.8 Access Transparency & Audit

```
Cloud Audit Logs:
  Admin Activity:    ENABLED (immutable, 400-day retention)
  Data Access:       ENABLED (all services, 400-day retention)
  System Events:     ENABLED
  Policy Denied:     ENABLED

Access Transparency:
  ENABLED — logs all Google engineer access to customer data
  → Alerts on any Google admin access to milnet VMs

Security Command Center (Premium):
  ENABLED — vulnerability scanning, threat detection
  → Web Security Scanner on gateway
  → Container Threat Detection (n/a — no containers)
  → Event Threat Detection (anomalous IAM, data exfil)
```

---

## 5. Inter-VM Quantum-Safe Communication

### 5.1 The SHARD-QS Protocol (Quantum-Safe SHARD)

Every inter-VM channel uses a **triple-layered** encryption stack:

```
Layer 1: GCP VPC Wire Encryption (AES-256-GCM, automatic)
         ↓ protects against physical tap on Google's network fabric

Layer 2: mTLS 1.3 (X25519 ECDHE + AES-256-GCM)
         ↓ protects against compromised VPC / ARP spoofing

Layer 3: X-Wing Application-Level KEM (X25519 + ML-KEM-1024)
         + ML-DSA-87 Mutual Authentication
         + HKDF-SHA512 Session Key Derivation
         + AEGIS-256 / AES-256-GCM Payload Encryption
         + HMAC-SHA512 Message Authentication
         ↓ protects against quantum computer attacks on TLS
```

**Why three layers**:
- Layer 1 is transparent (Google manages it) — we don't trust it alone
- Layer 2 uses classical crypto (X25519) — vulnerable to future QC
- Layer 3 uses hybrid post-quantum — survives 1M-qubit attacks

Even if an attacker breaks ALL of Layer 1 and Layer 2, Layer 3's
ML-KEM-1024 component remains secure against known quantum algorithms.

### 5.2 Session Establishment (Per-Connection)

```
VM-A → VM-B Connection Setup:

1. VM-A generates ephemeral X-Wing keypair (X25519 + ML-KEM-1024)
2. VM-A signs its public key with ML-DSA-87 (proving identity)
3. VM-A sends: [signed_pubkey, vTPM_attestation_quote, timestamp]
4. VM-B verifies:
   a. ML-DSA-87 signature (quantum-safe identity proof)
   b. vTPM attestation quote (platform integrity proof)
   c. Timestamp within ±2 seconds (freshness)
   d. Source IP in firewall allowlist (network-level binding)
5. VM-B encapsulates shared secret using VM-A's X-Wing public key
6. VM-B signs its ciphertext with its own ML-DSA-87 key
7. Both derive session key: HKDF-SHA512(shared_secret, "MILNET-SHARD-QS-v1")
8. All subsequent messages encrypted with AEGIS-256 using session key
9. Session key ratchets every 30 seconds via HKDF-SHA512 chain
```

### 5.3 Message Wire Format

```
┌─────────┬────────┬──────────┬───────────────┬────────────┬──────────┐
│ Length   │ SeqNum │ Epoch    │ Ciphertext    │ HMAC-512   │ PQ-Sig   │
│ (4B BE) │ (8B)   │ (8B)     │ (variable)    │ (64B)      │ (4627B)  │
└─────────┴────────┴──────────┴───────────────┴────────────┴──────────┘

- Length: Total frame length (big-endian u32)
- SeqNum: Monotonic sequence counter (replay protection)
- Epoch: Ratchet epoch (key rotation binding)
- Ciphertext: AEGIS-256 encrypted payload
- HMAC-512: HMAC-SHA512 over (SeqNum || Epoch || Ciphertext)
- PQ-Sig: ML-DSA-87 signature over entire frame (quantum-safe auth)
```

### 5.4 Why This Survives 1M-Qubit Quantum Computer

| Attack | Defense | Quantum Resistance |
|--------|---------|-------------------|
| Break X25519 (Shor's) | ML-KEM-1024 still protects session | ✅ NIST Level 5 |
| Break ML-KEM-1024 (unknown lattice attack) | X25519 still protects session | ✅ Classical defense |
| Break BOTH simultaneously | Information-theoretically impossible with hybrid combiner | ✅ Dual protection |
| Record-now-decrypt-later | 30-second epoch ratcheting: old keys are erased | ✅ Forward secrecy |
| Forge signatures (Shor's on ECDSA) | ML-DSA-87 (lattice-based, quantum-safe) | ✅ NIST Level 5 |
| Break ML-DSA-87 (unknown lattice attack) | SLH-DSA fallback (hash-based, no lattice assumptions) | ✅ Zero math assumptions |

**SLH-DSA (FIPS 205)** is the ultimate fallback. It relies ONLY on
the security of SHA-256 hash functions — no number theory, no lattices,
no elliptic curves. Even a hypothetical quantum computer that breaks
ALL structured mathematical assumptions cannot break SLH-DSA as long
as SHA-256's preimage resistance holds.

---

## 6. Auto-Mutation & Moving Target Defense

### 6.1 What Mutates and When

| Asset | Mutation Interval | Mechanism |
|-------|-------------------|-----------|
| Session encryption keys | 30 seconds | HKDF-SHA512 ratchet chain |
| Inter-VM session keys | 30 seconds | SHARD-QS epoch advancement |
| mTLS certificates | 24 hours | Auto-generated, vTPM-bound |
| FROST key shares | 7 days | Proactive share refresh (new DKG) |
| Master KEK | 90 days | Cloud HSM automatic rotation |
| OPAQUE ServerSetup | 30 days | Threshold re-setup ceremony |
| ML-DSA-87 signing keys | 90 days | New keygen + KT Merkle publication |
| Hash puzzle difficulty | Adaptive | Increases under DDoS load |
| Service listening ports | 6 hours | Port-knocking + firewall update |
| Challenge nonces | Per-request | Cryptographic random, single-use |
| vTPM attestation quotes | 1 hour | Re-attestation with fresh nonce |
| Firewall rules | 1 hour | Rule shuffling (permitted IPs rotate) |
| Binary attestation | On deploy | SHA-512 manifest verification |

### 6.2 How Mutation Invalidates Attacks

**Scenario**: Attacker compromises VM-07 (TSS node) and extracts FROST share #1.

```
T+0s:    Attacker has Share #1 (needs 2 more shares)
T+10m:   Attacker compromises VM-08, gets Share #2
T+15m:   Attacker attempts to compromise VM-09...
T+168h:  FROST proactive share refresh fires
         → ALL 5 shares are regenerated via new DKG
         → Old shares (including stolen #1 and #2) are WORTHLESS
         → Attacker must start over from scratch
         → New shares have ZERO mathematical relationship to old ones
```

**Scenario**: Attacker records encrypted traffic for quantum decryption later.

```
T+0:     Attacker captures encrypted frames from wire
T+30s:   Session key ratchets — new HKDF-SHA512 derived key
T+60s:   Another ratchet — key #1 is permanently erased (zeroized)
T+∞:     Attacker runs quantum computer on captured traffic
         → Each 30-second window has a DIFFERENT key
         → Must break X-Wing hybrid KEM for EACH window separately
         → ML-KEM-1024 resists Shor's algorithm
         → Even if ML-KEM-1024 breaks, forward secrecy means
            past keys are ERASED and cannot be recovered
```

### 6.3 Port Mutation (Moving Target Defense)

Every 6 hours, the system runs a coordinated port rotation:

```
1. ORCHESTRATOR generates new random port assignments:
   - Each service gets a new random port in range 10000-60000
   - Port assignment signed with ML-DSA-87 to prevent injection

2. New firewall rules are pushed via Compute Engine API:
   - Old port rules are deleted
   - New port rules are created
   - Transition window: 30 seconds (both old and new accepted)

3. Each service receives new port config via Secret Manager update:
   - Service binds to new port
   - Old port is closed

4. All inter-VM connections re-establish on new ports:
   - Fresh X-Wing KEM handshake
   - Fresh vTPM attestation
   - Fresh ML-DSA-87 mutual authentication
```

**Effect**: An attacker who discovered the port layout has a maximum
6-hour window. After rotation, all port knowledge is invalidated.
Combined with the 30-second key ratcheting, the attacker must:
- Discover the new ports (6h window)
- Break X-Wing KEM (quantum-resistant)
- Break ML-DSA-87 auth (quantum-resistant)
- All within 30 seconds before the next ratchet

### 6.4 Certificate Mutation

```
Every 24 hours:
  1. Each VM generates a new ephemeral mTLS certificate
  2. Certificate is bound to vTPM (TPM2_CreateKey with PCR policy)
  3. Certificate fingerprint is published to all peers via Secret Manager
  4. Old certificate is revoked and destroyed
  5. All connections re-establish with new certificates

This means:
  - Stolen certificates expire in ≤24 hours
  - Certificate private keys are sealed to vTPM (cannot be extracted)
  - Even physical theft of the disk cannot extract the private key
    because it's sealed to the TPM's PCR state (Secure Boot chain)
```

---

## 7. Threshold Distribution & No Single Point of Failure

### 7.1 Every Critical Operation Requires Multiple VMs

```
┌─────────────────────────────────────────────────────────────────────┐
│ OPERATION              │ VMs REQUIRED  │ SPOF? │ COMPROMISE NEEDED │
├────────────────────────┼───────────────┼───────┼───────────────────┤
│ Authenticate user      │ 2-of-3 OPAQUE │  NO   │ 2 OPAQUE VMs     │
│ Sign token             │ 3-of-5 TSS    │  NO   │ 3 TSS VMs        │
│ Write audit entry      │ 5-of-7 BFT    │  NO   │ 3 audit VMs      │
│ Read database          │ Any 1-of-3 DB │  NO   │ 1 DB + KEK       │
│ Write database         │ Primary + sync │  NO   │ 2 DB VMs + KEK   │
│ Verify token           │ Any 1-of-2    │  NO   │ Public keys only  │
│ Advance ratchet        │ Any 1-of-2    │  NO   │ Forward-secret    │
│ Reconstruct master KEK │ 3-of-5 Shamir │  NO   │ 3 VMs + HSM      │
│ Route ceremony         │ Any 1-of-2    │  NO   │ No secrets held   │
│ Accept request         │ Any 1-of-N MIG│  NO   │ No secrets held   │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Master KEK: Shamir 5-of-5 → 3-of-5 Reconstruction

The Master KEK (Key Encryption Key) is NEVER stored in one place:

```
Master KEK (256-bit AES key)
  ↓ Shamir Secret Sharing (3-of-5 threshold)
  ↓
  Share 1 → Cloud HSM (FIPS 140-2 L3, Google-managed hardware)
  Share 2 → VM-04 vTPM (OPAQUE-SHARD-1, sealed to PCR state)
  Share 3 → VM-05 vTPM (OPAQUE-SHARD-2, sealed to PCR state)
  Share 4 → VM-14 vTPM (RATCHET-A, sealed to PCR state)
  Share 5 → Offline cold storage (USB HSM in physical safe)
```

**To reconstruct**: Need any 3 of 5 shares. This means:
- Cloud HSM alone = useless
- Compromising 2 VMs = useless
- Physical theft of USB = useless
- Must breach Cloud HSM + 2 VMs simultaneously

### 7.3 Failure Tolerance Per Zone

```
Zone 1 (DMZ):        MIG auto-heals. 50 instances available. ZERO SPOF.
Zone 2 (Ceremony):   2 orchestrators. Lose 1 = continue. ZERO SPOF.
Zone 3 (Auth Core):  3 OPAQUE shards. Lose 1 = continue (2-of-3). ZERO SPOF.
Zone 4 (Signing):    5 TSS nodes. Lose 2 = continue (3-of-5). ZERO SPOF.
Zone 5 (Verify):     2 verifiers + 2 ratchets. Lose 1 each = continue. ZERO SPOF.
Zone 6 (Audit):      7 BFT nodes. Lose 2 = continue (5-of-7). ZERO SPOF.
Zone 7 (Data):       3 DB nodes. Lose 1 = continue (sync rep). ZERO SPOF.
Zone 8 (Intel):      1 VM (acceptable — risk scoring is advisory, not blocking).
```

### 7.4 No Chain of Failure

Each zone operates **independently**. A cascading failure in one zone
CANNOT propagate to another zone because:

1. **No shared credentials**: Each VM has its own service account, its own
   vTPM-sealed keys, its own mTLS certificate. Compromising VM-A's
   credentials gives ZERO access to VM-B.

2. **No shared storage**: Each zone has its own disk. Database VMs use
   their own encrypted volumes. Audit VMs use their own append-only logs.

3. **No shared network path**: Firewall rules ensure each zone can only
   talk to its designated peers. OPAQUE VMs cannot reach audit VMs directly.

4. **Circuit breakers**: Every inter-VM connection has exponential backoff
   and circuit breaker patterns. If a downstream VM fails, the upstream
   VM degrades gracefully rather than cascading.

5. **Independent health monitoring**: Each VM reports health independently
   to GCP health checks. A sick VM is replaced without affecting others.

---

## 8. Data Protection — Unbreakable Even with 1M Qubit QC

### 8.1 Layers of Encryption on Stored Data

```
Data at Rest Protection Stack:

Layer 1: GCP Default Encryption (AES-256, Google-managed)
         → Automatic, transparent disk encryption

Layer 2: CMEK (Customer-Managed Encryption Key via Cloud HSM)
         → AES-256-GCM, key material in FIPS 140-2 L3 HSM
         → Key never leaves HSM boundary

Layer 3: dm-verity (Kernel-Level)
         → Read-only root filesystem with hash tree verification
         → Any modification to any file is detected and blocked

Layer 4: Application Envelope Encryption (per-field)
         → Each sensitive database field encrypted individually
         → AES-256-GCM with unique nonce per ciphertext
         → DEK wrapped by KEK (which is Shamir-split)
         → AAD: "MILNET-AAD-v1:<table>:<column>:<row_id>"

Layer 5: AMD SEV-SNP Memory Encryption (in-transit through RAM)
         → Prevents hypervisor/physical access to processing data
```

### 8.2 Why 1M-Qubit Quantum Computer Cannot Decrypt

| Attack Vector | Defense | Quantum Impact |
|---------------|---------|----------------|
| Break AES-256 (Grover's) | Grover's reduces AES-256 to 128-bit security | 128-bit still requires 2^128 operations — more than atoms in universe |
| Break RSA/ECC (Shor's) | No RSA/ECC used for data encryption — only AES-256 | N/A — Shor's doesn't apply to symmetric ciphers |
| Break ML-KEM-1024 (lattice attack) | Data at rest uses AES-256-GCM, not lattice crypto | N/A — lattice attacks don't help with AES |
| Brute-force KEK | KEK is 256-bit AES, Shamir-split across 5 locations | Even with Grover's: 2^128 operations, physically impossible |
| Steal HSM key | FIPS 140-2 L3 HSM: tamper-evident, zeroizes on breach | Physical attack destroys key material |
| Record encrypted traffic | Forward secrecy: keys erased every 30 seconds | Must break EACH epoch's hybrid KEM separately |

### 8.3 Information-Theoretic Security (Beyond Computation)

Some protections are **information-theoretically secure** — they cannot
be broken regardless of computational power, including quantum:

1. **Shamir Secret Sharing** (Master KEK split): With k-1 shares,
   the secret is uniformly distributed over all possible values.
   No algorithm, classical or quantum, can determine the secret.

2. **FROST Threshold Signatures** (below threshold): With t-1 shares,
   the signing key is information-theoretically hidden.

3. **One-Time Pad effect of ratcheting**: Each ratchet epoch uses
   HKDF-SHA512 to derive a fresh key from the previous key + entropy.
   Once the previous key is zeroized, the derivation is irreversible
   regardless of computing power.

4. **OPAQUE server-blindness**: The server never sees the password.
   Even full database + memory dump reveals only OPRF evaluations,
   which are computationally and information-theoretically unlinkable
   to the original password.

---

## 9. Autoscaling & Load Architecture

### 9.1 Gateway MIG (Managed Instance Group)

```
Resource: google_compute_instance_group_manager.gateway_mig

Instance Template:
  Machine Type: c2-standard-4 (Spot)
  Preemptibility: SPOT (with STOP action)
  Boot Disk: 20 GB SSD, Shielded VM
  Startup Script: Download attested binary, start gateway service

Autoscaler:
  Min Replicas: 1    (idle: 10 logins/month)
  Max Replicas: 50   (peak: 10,000 logins/second)
  Target CPU: 60%
  Cool Down: 60 seconds
  Scale-In Control: 10 minutes (prevent flapping)

Health Check:
  Protocol: TCP
  Port: 443
  Check Interval: 10s
  Unhealthy Threshold: 3
  Auto-healing: Replace unhealthy within 60s

External Load Balancer:
  Protocol: TCP (pass-through, no SSL termination at LB)
  Backend: gateway_mig
  Health Check: TCP 443
  Session Affinity: CLIENT_IP (sticky for puzzle solving)
  Cloud Armor: milnet-gateway-armor policy
```

**Why TCP pass-through** (not HTTPS LB): The gateway implements its own
X-Wing KEM handshake at the application layer. SSL termination at the
LB would break the end-to-end quantum-safe encryption.

### 9.2 Capacity Planning

```
10 logins/month (idle):
  Gateway: 1x c2-standard-4 Spot ($25/month)
  All internal VMs: e2-small/medium (~$150/month total)
  Total: ~$200/month

100 logins/hour (normal):
  Gateway: 1x c2-standard-4 Spot
  No scaling needed — single instance handles this easily
  Total: ~$200/month

1,000 logins/minute (busy):
  Gateway: 3-5x c2-standard-4 Spot (~$75-125/month)
  Internal VMs: May need orchestrator scaling
  Total: ~$300/month

10,000 logins/second (extreme DDoS/peak):
  Gateway: 30-50x c2-standard-4 Spot (~$750-1250/month)
  Puzzle difficulty auto-increases to throttle
  Cloud Armor rate limiting kicks in
  Internal VMs: 5 TSS nodes handle signing (FROST is fast)
  Total: ~$1500/month during peak
```

### 9.3 Internal Service Scaling

Internal services do NOT auto-scale — they are right-sized for peak:

```
OPAQUE (3 VMs): Each handles ~3,000 OPAQUE ops/sec
  → 3 VMs in 2-of-3 mode = ~6,000 ops/sec sustained
  → Exceeds 10,000 login/sec (OPAQUE is lighter than TLS handshake)

TSS (5 VMs): FROST signing ≈ 1ms per signature
  → 5 VMs × 1,000 sigs/sec = 5,000 sigs/sec
  → Need 3-of-5 = effective ~1,600 sigs/sec per quorum
  → For 10K/sec: batch signing (aggregate multiple logins)

Verifier (2 VMs): O(1) signature verification ≈ 0.1ms
  → 2 VMs × 10,000 verifications/sec = 20,000/sec
  → Far exceeds requirements

Database (3 VMs): PostgreSQL handles ~5,000 queries/sec per node
  → Read replicas absorb verification queries
  → Writes go to primary only (auth operations)
```

---

## 10. Boot Chain & Attestation

### 10.1 Secure Boot Chain (Every VM)

```
UEFI Firmware (Google Titan chip)
  → Measured to PCR 0
  ↓
UEFI Secure Boot (custom DB keys)
  → Verified bootloader signature
  → Measured to PCR 4
  ↓
Linux Kernel (hardened, custom config)
  → KASLR, SMEP, SMAP, PTI enabled
  → Measured to PCR 7
  ↓
dm-verity Root Filesystem
  → Hash tree verification of every block
  → Read-only root (tmpfs for /tmp, /var)
  ↓
systemd → milnet-pre.service
  → Binary attestation (SHA-512 of all service binaries)
  → Config attestation (BLAKE3 of all config files)
  → vTPM PCR extension with service identity
  ↓
milnet-{service}.service
  → Platform integrity checks at startup
  → FIPS KAT (Known Answer Tests)
  → CNSA 2.0 compliance verification
  → vTPM quote generation for peer attestation
```

### 10.2 Remote Attestation Between VMs

Before any VM accepts a connection from another VM, it verifies:

```
1. vTPM Attestation Quote:
   - PCR 0: Firmware hash matches expected
   - PCR 4: Bootloader hash matches expected
   - PCR 7: Secure Boot policy matches expected
   - PCR 14: Service-specific measurement matches expected
   - Quote signature verified against Google's EK CA

2. Binary Attestation:
   - SHA-512 hash of running binary matches signed manifest
   - Manifest signed by build attestor (Cloud KMS key)

3. Config Attestation:
   - BLAKE3 hash of config files matches expected baseline

4. Identity Verification:
   - ML-DSA-87 signature proves VM identity
   - Service account matches expected role

Only if ALL FOUR checks pass does the VM accept the connection.
```

### 10.3 Continuous Attestation (Runtime)

```
Every 60 minutes:
  1. Each VM re-generates vTPM attestation quote
  2. Quote is sent to all connected peers
  3. Peers re-verify the attestation
  4. If verification fails:
     a. Connection is immediately terminated
     b. Alert sent to SIEM
     c. VM is marked unhealthy in GCP health check
     d. MIG replaces the VM (if in a MIG)
     e. Incident response procedure triggered
```

---

## 11. Failure Domains & Blast Radius

### 11.1 Blast Radius Matrix

```
IF COMPROMISED:        ATTACKER GAINS:                BLAST RADIUS:
─────────────────────────────────────────────────────────────────────
VM-01 (Gateway)        Nothing (zero secrets)          NONE
VM-02 (Orchestrator)   Nothing (zero secrets)          NONE
VM-04 (OPAQUE-1)       1 Shamir share (useless alone)  NONE
VM-07 (TSS-1)          1 FROST share (useless alone)   NONE
VM-12 (Verifier)       Public keys (already public)    NONE
VM-14 (Ratchet)        Current epoch key (30s window)  1 epoch
VM-16 (Audit-1)        Read audit entries              Read-only
VM-DB-1 (Database)     Encrypted field ciphertexts     NONE*
VM-21 (Risk+KT)        Risk scores + Merkle tree       Read-only
Cloud HSM              1 Shamir share of KEK           NONE
Google employee        Access Transparency log          NONE

* Database compromise yields only AES-256-GCM ciphertexts.
  Decryption requires the KEK, which is Shamir-split.
  KEK reconstruction requires 3-of-5 shares from different VMs.
```

### 11.2 Combined Attack Scenarios

```
SCENARIO 1: Compromise Gateway + Orchestrator (2 VMs)
  Result: See encrypted traffic. No keys to decrypt. ZERO data breach.

SCENARIO 2: Compromise 2 OPAQUE shards (2 of 3 VMs)
  Result: CAN reconstruct OPAQUE ServerSetup
  Mitigation: OPAQUE is server-blind — ServerSetup alone cannot
              recover ANY password. Still need victim to authenticate.
  Actual Risk: LOW (can impersonate server, but DPoP binding prevents
               token theft, and ratchet detects cloning)

SCENARIO 3: Compromise 2 TSS nodes (2 of 5 VMs)
  Result: 2 FROST shares (need 3). ZERO signing ability. SAFE.

SCENARIO 4: Compromise 3 TSS nodes (3 of 5 VMs) — THRESHOLD BREACH
  Result: CAN forge token signatures
  Mitigation: ML-DSA-87 wrapper also required (separate key on
              separate VM). Forged FROST sig fails PQ verification.
  Actual Risk: Must ALSO compromise ML-DSA-87 key holder.

SCENARIO 5: Compromise Database + 2 OPAQUE shards + Cloud HSM (4 targets)
  Result: CAN reconstruct KEK, CAN decrypt database fields
  Mitigation: This is a CATASTROPHIC breach. Recovery procedure:
    1. Automatic detection via audit BFT divergence
    2. Emergency key rotation (all 5 FROST shares regenerated)
    3. Master KEK re-split with new Shamir shares
    4. Database re-encrypted with new DEKs
    5. All sessions invalidated
    6. Incident response team notified within 30 seconds

SCENARIO 6: Compromise ALL 21 VMs + Cloud HSM + physical USB simultaneously
  Result: Full system compromise
  Mitigation: This requires:
    - Breaching GCP's physical security (Titan chip, biometric access)
    - Breaching AMD SEV-SNP (no known attacks)
    - Breaching Cloud HSM (FIPS 140-2 L3 tamper-evident)
    - Breaching 21 independent OS instances simultaneously
    - All within 30 seconds (before ratchet mutation)
    - Probability: effectively zero for any nation-state actor
```

---

## 12. Key Lifecycle & Rotation Schedule

### 12.1 Complete Rotation Schedule

```
┌─────────────────────────┬───────────┬─────────────────────────────────┐
│ KEY/CREDENTIAL          │ ROTATION  │ MECHANISM                       │
├─────────────────────────┼───────────┼─────────────────────────────────┤
│ Session encryption keys │ 30 sec    │ HKDF-SHA512 ratchet             │
│ Inter-VM session keys   │ 30 sec    │ SHARD-QS epoch ratchet          │
│ Challenge nonces        │ Per-req   │ CSPRNG (multi-source entropy)   │
│ DPoP proofs             │ Per-req   │ Fresh ML-DSA-87 signature       │
│ Service ports           │ 6 hours   │ Coordinated port rotation       │
│ mTLS certificates       │ 24 hours  │ vTPM-bound cert regeneration    │
│ vTPM attestation quotes │ 1 hour    │ Fresh quote with new nonce      │
│ Hash puzzle seed        │ 1 hour    │ New CSPRNG seed                 │
│ FROST key shares        │ 7 days    │ Proactive share refresh (DKG)   │
│ OPAQUE ServerSetup      │ 30 days   │ Threshold re-setup ceremony     │
│ ML-DSA-87 signing keys  │ 90 days   │ New keygen + KT publication     │
│ Master KEK              │ 90 days   │ Cloud HSM automatic rotation    │
│ CMEK disk keys          │ 365 days  │ Cloud KMS automatic rotation    │
│ SLH-DSA signing keys    │ 365 days  │ New keygen (stateless = safe)   │
│ Firewall rules refresh  │ 1 hour    │ Port/IP rule shuffling          │
│ Binary attestation      │ On deploy │ SHA-512 manifest re-signing     │
└─────────────────────────┴───────────┴─────────────────────────────────┘
```

### 12.2 Zero-Downtime Key Rotation Protocol

```
For FROST share refresh (weekly):

1. COORDINATOR (Orchestrator) announces rotation epoch
2. All 5 TSS nodes generate new Feldman VSS commitments
3. Each node sends shares to all other nodes (point-to-point SHARD-QS)
4. Each node verifies received shares against commitments
5. Each node computes new aggregate share
6. GROUP public key REMAINS THE SAME (verifiers need no update)
7. All old shares are zeroized (memset + munlock)
8. New shares are sealed to vTPM

Duration: < 5 seconds. Zero downtime. No service interruption.
Verification: Existing tokens remain valid (same group public key).
```

---

## 13. Deployment — Direct on VM, No Docker

### 13.1 Per-VM Deployment

Each VM runs services as native systemd units:

```
/opt/milnet/bin/
  ├── gateway          (VM-01 only, 0555 root:milnet)
  ├── admin            (VM-01 only, 0555 root:milnet)
  ├── orchestrator     (VM-02,03 only)
  ├── opaque           (VM-04,05,06 only)
  ├── tss              (VM-07-11 only)
  ├── verifier         (VM-12,13 only)
  ├── ratchet          (VM-14,15 only)
  ├── audit            (VM-16-20+ only)
  ├── risk             (VM-21 only)
  └── kt               (VM-21 only)

/etc/milnet/
  ├── {service}.env     (per-service config, 0400 root:milnet)
  └── shard-hmac.key    (SHARD IPC key, 0400 root:milnet)

/var/lib/milnet/
  └── {service}/        (per-service data dir, 0700 milnet:milnet)
```

### 13.2 systemd Hardening (Per Service)

```ini
[Service]
User=milnet
Group=milnet
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
SeccompProfile=strict
ReadOnlyPaths=/
ReadWritePaths=/var/lib/milnet/{service}
```

### 13.3 Kernel Hardening (sysctl)

```
# Memory protections
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 3
kernel.unprivileged_bpf_disabled = 1
vm.mmap_min_addr = 65536

# Network hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# Filesystem protections
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
```

---

## 14. Monitoring, Audit & Forensics

### 14.1 Application-Level Audit (BFT — 7 Nodes)

```
Audit Flow:

Every security event → ML-DSA-87 signed → SHA-512 hash-chained
  → Replicated to 7 BFT nodes (quorum 5)
  → Witness checkpoint every 300 seconds (ML-DSA-87 signed tree head)
  → Cross-referenced with KT Merkle tree root
  → Shipped to Cloud Logging (secondary copy)
  → SIEM webhook for real-time alerting

23 Event Types Tracked:
  AuthSuccess, AuthFailure, MfaEnabled, CredentialRegistered,
  CredentialRevoked, ActionLevel3, ActionLevel4, KeyRotation,
  ShareRefresh, SystemDegraded, SystemRecovered, DuressDetected,
  RecoveryCodeUsed, RecoveryCodeGenerated, UserDeleted,
  AdminRbacDenied, AdminRbacGranted, CrossDomainDecision,
  AdminCeremonyRequired, DpopReplayDetected, ...
```

### 14.2 GCP-Level Monitoring

```
Cloud Monitoring Alerts:
  - CPU > 80% sustained 5 minutes → Scale up
  - Memory > 90% → Alert + investigate
  - Disk > 80% → Alert + archive old audit logs
  - Health check failure → Auto-heal (MIG) or alert
  - Unusual API calls → Security Command Center alert
  - IAM policy changes → Immediate alert to SOC
  - VPC flow log anomalies → Packet Mirroring capture

VPC Flow Logs:
  ENABLED on ALL subnets
  Sampling: 100% (no sampling for security)
  Aggregation: 5 seconds
  Retention: 400 days
  → Shipped to BigQuery for forensic analysis

Packet Mirroring:
  Collector in audit-subnet
  Mirrors: ALL inter-zone traffic
  → Full PCAP for post-incident forensics
  → Encrypted at rest with CMEK
```

### 14.3 Intrusion Detection

```
Automated Detection:
  1. Ratchet heartbeat failure → Session terminated + alert
  2. DPoP replay detected → Token revoked + alert + IP blocked
  3. Receipt chain break → Ceremony aborted + alert
  4. Audit hash chain divergence → Byzantine node identified + alert
  5. Binary attestation mismatch → VM quarantined + alert
  6. vTPM PCR drift → VM isolated + forensic snapshot + alert
  7. Impossible travel (geo-velocity) → Session terminated + alert
  8. Failed auth burst (>5 in 60s) → Account locked + alert
  9. Cross-zone traffic violation → Connection killed + alert
  10. Abnormal process execution → VM isolated + alert
```

---

## 15. Complete Firewall Matrix

### 15.1 Inter-Zone Allowed Traffic

```
SOURCE              → DESTINATION           PORT    PROTOCOL  PURPOSE
────────────────────────────────────────────────────────────────────────
dmz-subnet          → ceremony-subnet        *       TCP/SHARD Gateway→Orchestrator
ceremony-subnet     → authcore-subnet        *       TCP/SHARD Orch→OPAQUE
ceremony-subnet     → signing-subnet         *       TCP/SHARD Orch→TSS
ceremony-subnet     → intel-subnet           *       TCP/SHARD Orch→Risk
ceremony-subnet     → verify-subnet          *       TCP/SHARD Orch→Ratchet
signing-subnet      → signing-subnet         *       TCP/SHARD TSS↔TSS (FROST)
signing-subnet      → audit-subnet           *       TCP/SHARD TSS→Audit
verify-subnet       → signing-subnet         *       TCP/SHARD Verifier→TSS
verify-subnet       → verify-subnet          *       TCP/SHARD Verifier↔Ratchet
intel-subnet        → audit-subnet           *       TCP/SHARD KT→Audit
intel-subnet        → verify-subnet          *       TCP/SHARD Risk→Ratchet
authcore-subnet     → data-subnet            5432    TCP/PG    OPAQUE→PostgreSQL
dmz-subnet          → data-subnet            5432    TCP/PG    Admin→PostgreSQL
audit-subnet        → audit-subnet           *       TCP/SHARD Audit↔Audit (BFT)
ALL subnets         → audit-subnet           *       TCP/SHARD *→Audit (log)
────────────────────────────────────────────────────────────────────────
ALL OTHER TRAFFIC: DENIED (default deny ingress + egress)

* Ports are randomized every 6 hours (Moving Target Defense)
  Firewall rules updated atomically via Compute Engine API
```

### 15.2 External Traffic

```
EXTERNAL → dmz-subnet:
  Source: 0.0.0.0/0
  Ports: 443 (SSO endpoint), 8443 (admin panel)
  Via: External TCP Load Balancer + Cloud Armor WAF

ALL OTHER EXTERNAL TRAFFIC: DENIED

Egress (outbound internet):
  Cloud NAT for apt updates ONLY
  Restricted to: deb.debian.org, security.debian.org
  ALL other egress: DENIED
```

---

## 16. Disaster Recovery & Self-Healing

### 16.1 Auto-Healing

```
MIG-based (Gateway):
  Health check failure → Auto-replace instance within 60 seconds
  Spot preemption → Auto-replace within 30 seconds

Non-MIG VMs:
  Monitored by Cloud Monitoring
  Alert → Manual intervention via runbook
  Database failover: Automatic promotion of sync replica

BFT Audit:
  Node failure → Remaining 6 nodes continue (quorum 5)
  Node recovery → Automatic state catch-up from peers
  Chain divergence → Identified and quarantined automatically
```

### 16.2 Backup Strategy

```
Database:
  Continuous WAL archiving to Cloud Storage (CMEK encrypted)
  Daily full backup (pg_basebackup) to separate region
  RPO: 0 seconds (synchronous replication)
  RTO: 5 minutes (replica promotion)

Audit Logs:
  7 BFT copies + Cloud Logging + Cloud Storage archive
  Retention: 7 years (compliance minimum)

Key Material:
  FROST shares: vTPM-sealed (survives disk wipe, not VM delete)
  Master KEK shares: 5 locations (including offline cold storage)
  OPAQUE ServerSetup: Encrypted backup in Secret Manager

Configuration:
  All configs in version control (Infrastructure as Code)
  Terraform state in Cloud Storage with versioning + CMEK
```

### 16.3 Emergency Recovery Procedure

```
DEFCON 1 — Full System Compromise Detected:

1. T+0s:   Audit BFT divergence triggers automatic alert
2. T+5s:   All inter-VM connections terminated (kill switch)
3. T+10s:  All sessions invalidated (ratchet chain reset)
4. T+15s:  All tokens revoked (revocation list flushed)
5. T+30s:  Gateway switches to maintenance mode (503)
6. T+60s:  Forensic snapshot of all VMs (disk + memory)
7. T+120s: FROST proactive share refresh (new DKG)
8. T+180s: New mTLS certificates generated (all VMs)
9. T+300s: Master KEK re-split (new Shamir shares)
10. T+600s: Database re-encrypted with new DEKs
11. T+900s: System restored with all-new key material
12. T+∞:    Post-incident forensic analysis from snapshots

Total recovery time: ~15 minutes
Data loss: ZERO (synchronous replication + WAL archiving)
Key exposure: ZERO (all old keys destroyed, new keys generated)
```

---

## 17. Cost Estimation

### 17.1 Monthly Cost (asia-south1, Spot where available)

```
VM COSTS:
┌────────────────────────────┬──────────┬─────────┬──────────────┐
│ VM                         │ Type     │ Spot?   │ $/month (est)│
├────────────────────────────┼──────────┼─────────┼──────────────┤
│ VM-01 Gateway (MIG min=1)  │ c2-std-4 │ YES     │ $25-40       │
│ VM-02,03 Orchestrator ×2   │ e2-medium│ NO      │ $50          │
│ VM-04,05,06 OPAQUE ×3      │ e2-medium│ NO      │ $75          │
│ VM-07-11 TSS ×5            │ e2-small │ NO      │ $85          │
│ VM-12,13 Verifier ×2       │ e2-small │ NO      │ $34          │
│ VM-14,15 Ratchet ×2        │ e2-medium│ NO      │ $50          │
│ VM-16-20+ Audit ×7         │ e2-small │ NO      │ $119         │
│ VM-DB-1,2,3 Database ×3    │ e2-medium│ NO      │ $75          │
│ VM-21 Risk+KT              │ e2-small │ NO      │ $17          │
├────────────────────────────┼──────────┼─────────┼──────────────┤
│ SUBTOTAL VMs               │          │         │ ~$570        │
└────────────────────────────┴──────────┴─────────┴──────────────┘

GCP SERVICES:
┌────────────────────────────┬──────────────┐
│ Service                    │ $/month (est)│
├────────────────────────────┼──────────────┤
│ Cloud HSM (2 keys)         │ $2.40        │
│ Cloud KMS (CMEK, 3 keys)   │ $3.60        │
│ Secret Manager (15 secrets)│ $0.90        │
│ Cloud Armor (1 policy)     │ $5.00        │
│ Cloud NAT (1 gateway)      │ $32.00       │
│ External LB (1 forwarding) │ $18.00       │
│ VPC Flow Logs              │ $15.00       │
│ Cloud Logging (retention)  │ $10.00       │
│ Cloud Monitoring           │ $0.00 (free) │
│ Packet Mirroring           │ $10.00       │
│ Confidential VM premium    │ ~$30.00      │
│ Disk (SSD, ~500GB total)   │ $85.00       │
├────────────────────────────┼──────────────┤
│ SUBTOTAL Services          │ ~$212        │
└────────────────────────────┴──────────────┘

TOTAL ESTIMATED: ~$782/month (idle)
                 ~$1,500/month (peak with autoscaling)
```

---

## Architecture Diagram — Complete Data Flow

```
                    ┌──────────────────────────────────────┐
                    │          INTERNET                      │
                    └──────────────┬───────────────────────┘
                                  │
                    ┌─────────────▼─────────────────┐
                    │     Cloud Armor WAF            │
                    │  (OWASP, Rate Limit, Geo-block)│
                    └─────────────┬─────────────────┘
                                  │
                    ┌─────────────▼─────────────────┐
                    │   External TCP Load Balancer    │
                    │   (pass-through, no TLS term)   │
                    └─────────────┬─────────────────┘
                                  │
              ════════════════════╪══════════════════════════
              ║   ZONE 1: DMZ    ║
              ║  ┌───────────────▼───────────────────┐     ║
              ║  │  VM-01: BASTION-GATEWAY            │     ║
              ║  │  (C2 Spot MIG, 1→50 instances)     │     ║
              ║  │                                     │     ║
              ║  │  1. Hash Puzzle Challenge           │     ║
              ║  │  2. X-Wing KEM Handshake            │     ║
              ║  │  3. AES-256-GCM Frame Encryption    │     ║
              ║  │  4. Forward to Orchestrator         │     ║
              ║  │                                     │     ║
              ║  │  SECRETS: ██ ZERO ██                │     ║
              ║  │  Admin Panel: :8443                 │     ║
              ║  └───────────────┬───────────────────┘     ║
              ════════════════════╪══════════════════════════
                                  │ SHARD-QS (X-Wing + ML-DSA-87)
              ════════════════════╪══════════════════════════
              ║ ZONE 2: CEREMONY ║
              ║  ┌───────────────▼───────────────────┐     ║
              ║  │  VM-02/03: ORCHESTRATOR (HA pair)  │     ║
              ║  │                                     │     ║
              ║  │  Ceremony State Machine:            │     ║
              ║  │  PendingOpaque → PendingTss →       │     ║
              ║  │  Complete                           │     ║
              ║  │                                     │     ║
              ║  │  SECRETS: ██ ZERO ██                │     ║
              ║  └──┬──────────┬──────────┬──────────┘     ║
              ═══════╪══════════╪══════════╪═════════════════
                     │          │          │
         ┌───────────┘          │          └───────────┐
         │ SHARD-QS             │ SHARD-QS             │ SHARD-QS
         ▼                      ▼                      ▼
  ═══════════════════  ═══════════════════  ═══════════════════
  ║ ZONE 3: AUTH    ║  ║ ZONE 4: SIGNING ║  ║ ZONE 8: INTEL ║
  ║                 ║  ║                 ║  ║               ║
  ║ VM-04 OPAQUE-1  ║  ║ VM-07 TSS-1    ║  ║ VM-21         ║
  ║ VM-05 OPAQUE-2  ║  ║ VM-08 TSS-2    ║  ║ Risk Engine   ║
  ║ VM-06 OPAQUE-3  ║  ║ VM-09 TSS-3    ║  ║ KT Merkle     ║
  ║                 ║  ║ VM-10 TSS-4    ║  ║ Witness        ║
  ║ 2-of-3 Shamir   ║  ║ VM-11 TSS-5    ║  ║               ║
  ║ (server-blind)  ║  ║                 ║  ═══════════════════
  ║                 ║  ║ 3-of-5 FROST    ║
  ═══════════════════  ║ + ML-DSA-87     ║
         │              ═══════════════════
         │                      │
         │                      │ SHARD-QS
         │              ═══════════════════
         │              ║ ZONE 5: VERIFY ║
         │              ║                ║
         │              ║ VM-12,13       ║
         │              ║ Verifier (HA)  ║
         │              ║ (public keys)  ║
         │              ║                ║
         │              ║ VM-14,15       ║
         │              ║ Ratchet (HA)   ║
         │              ║ (fwd-secret)   ║
         │              ═══════════════════
         │
         │ PostgreSQL (TLS + SCRAM-SHA-256)
         ▼
  ═══════════════════          ═══════════════════
  ║ ZONE 7: DATA   ║          ║ ZONE 6: AUDIT  ║
  ║                ║          ║                 ║
  ║ VM-DB-1 Primary║          ║ VM-16..20+      ║
  ║ VM-DB-2 Sync   ║          ║ 7 BFT nodes     ║
  ║ VM-DB-3 Async  ║          ║ (quorum = 5)    ║
  ║                ║          ║                 ║
  ║ CMEK + Envelope║          ║ Hash-chained    ║
  ║ + AMD SEV-SNP  ║          ║ ML-DSA-87 signed║
  ═══════════════════          ═══════════════════
```

---

## Summary — Why This Architecture Is Unbreakable

### The Attacker's Dilemma

To achieve ANY meaningful breach, an attacker must SIMULTANEOUSLY:

1. **Bypass Cloud Armor** (WAF + DDoS + rate limiting + geo-blocking)
2. **Solve hash puzzles** at scale (CPU-intensive, adaptive difficulty)
3. **Break X-Wing KEM** (X25519 + ML-KEM-1024 — quantum-resistant)
4. **Forge ML-DSA-87 signatures** (CNSA 2.0 Level 5 — quantum-resistant)
5. **Compromise 3+ TSS VMs** across different availability zones
   (each with Shielded VM + vTPM + Confidential Computing + unique SA)
6. **Compromise 2+ OPAQUE VMs** (each with AMD SEV-SNP memory encryption)
7. **Reconstruct Master KEK** from 3-of-5 Shamir shares
   (distributed across Cloud HSM + vTPMs + offline cold storage)
8. **Do all of the above within 30 seconds** before the ratchet mutates
   every key, port, and session in the system

**Each individual step is believed to be infeasible.**
**Requiring ALL steps simultaneously makes it physically impossible.**

### Security Guarantees

| Property | Guarantee | Basis |
|----------|-----------|-------|
| Password confidentiality | UNCONDITIONAL | OPAQUE server-blindness (information-theoretic) |
| Signing key confidentiality | UNCONDITIONAL below threshold | FROST/Shamir (information-theoretic) |
| Forward secrecy | 30-second granularity | HKDF-SHA512 ratchet + key erasure |
| Quantum resistance | NIST Level 5 (AES-256 equivalent) | ML-KEM-1024 + ML-DSA-87 |
| Lattice-independent fallback | Hash-based only | SLH-DSA (FIPS 205) — no math assumptions |
| Audit integrity | Byzantine fault tolerant | 7-node BFT (tolerates 2 traitors) |
| Data-at-rest protection | 5 layers of encryption | GCP + CMEK + dm-verity + envelope + SEV-SNP |
| No single point of failure | Every component is redundant | Threshold + replication + HA pairs |
| Auto-mutation | 30s keys, 6h ports, 24h certs, 7d shares | Moving Target Defense |
| Physical access resistance | Hardware-backed | vTPM + Cloud HSM + AMD SEV-SNP + Secure Boot |

### Longevity (5+ Years)

This architecture remains secure for 5+ years because:

1. **ML-KEM-1024 and ML-DSA-87** are NIST-standardized (2024) with
   decades of cryptanalysis behind the lattice problems they rely on.
2. **SLH-DSA** relies only on hash function security — the most
   conservative, most battle-tested assumption in cryptography.
3. **AES-256** provides 128-bit security even against Grover's algorithm.
4. **Information-theoretic protections** (Shamir, FROST thresholds)
   are mathematically proven secure regardless of computational advances.
5. **Auto-mutation** ensures that even if a breakthrough occurs,
   the window of exploitation is measured in seconds, not years.
6. **Hybrid approach** means BOTH classical AND post-quantum must
   break simultaneously — hedging against unknown breakthroughs.

---

*Document Version: 1.0*
*Classification: INTERNAL — ARCHITECTURE REFERENCE*
*Author: MILNET SSO Architecture Team*
*Date: 2026-03-26*
