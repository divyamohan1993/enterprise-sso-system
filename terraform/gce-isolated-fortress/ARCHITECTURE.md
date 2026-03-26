# MILNET SSO — Isolated Fortress Architecture

## Design Principle: Compromise One VM = Learn Nothing

Every VM is completely isolated. They communicate ONLY through quantum-resistant
encrypted SHARD channels over a private VPC with no internet access. Keys auto-rotate
every 30 seconds. If an attacker compromises one VM, the keys they stole become
invalid within 30 seconds and the entire cluster detects the anomaly and rotates
all shared material — forcing the attacker to start from scratch on every VM
simultaneously.

## VM Layout (13 VMs across 5 zones)

```
                    INTERNET
                       │
                  ┌────▼────┐
                  │ Cloud    │ ← Cloud Armor DDoS + WAF
                  │ Armor    │   Rate limit, geo-block, OWASP rules
                  └────┬────┘
                       │
              ╔════════▼════════╗
     Zone A   ║  VM-GATEWAY     ║  ONLY public IP in entire cluster
              ║  10.10.1.10     ║  Hash puzzle + X-Wing KEM + TLS 1.3
              ║  Port 9100+8080 ║  Admin panel + SSO entry point
              ╚════════╤════════╝
                       │ SHARD mTLS (ML-KEM-1024 + X25519)
           ┌───────────┼───────────┐
           │           │           │
    ╔══════▼══════╗ ╔══▼═══════╗ ╔▼════════════╗
    ║ VM-ORCH-1   ║ ║VM-ORCH-2 ║ ║VM-RISK      ║
    ║ 10.10.2.10  ║ ║10.10.2.11║ ║10.10.5.10   ║
    ║ Zone A      ║ ║Zone B    ║ ║Zone C        ║
    ╚══════╤══════╝ ╚══╤═══════╝ ╚╤════════════╝
           │           │           │
     ┌─────┴───┬───────┴──┬───────┘
     │         │          │
╔════▼═══╗╔═══▼════╗╔════▼═════╗
║VM-OPAQ ║║VM-OPAQ ║║VM-OPAQ   ║  2-of-3 threshold OPAQUE
║  -1    ║║  -2    ║║  -3      ║  Each holds 1 OPRF share
║Zone A  ║║Zone B  ║║Zone C    ║  No single server = no passwords
╚════════╝╚════════╝╚══════════╝

╔════════╗╔════════╗╔════════╗╔════════╗╔════════╗
║VM-TSS-1║║VM-TSS-2║║VM-TSS-3║║VM-TSS-4║║VM-TSS-5║  3-of-5 FROST
║Zone A  ║║Zone B  ║║Zone C  ║║Zone D  ║║Zone E  ║  Each holds 1 key share
║10.10.3 ║║10.10.3 ║║10.10.3 ║║10.10.3 ║║10.10.3 ║  No single VM = no token forgery
╚════════╝╚════════╝╚════════╝╚════════╝╚════════╝

╔══════════╗ ╔══════════╗ ╔═══════════╗ ╔═════════╗
║VM-VERIFY ║ ║VM-RATCHET║ ║VM-AUDIT   ║ ║VM-KT    ║
║10.10.4.10║ ║10.10.6.10║ ║10.10.7.10 ║ ║10.10.8.10║
║Zone A    ║ ║Zone B    ║ ║Zone C     ║ ║Zone A    ║
╚══════════╝ ╚══════════╝ ╚═══════════╝ ╚═════════╝

╔═══════════════════════════════════════════════════╗
║  Cloud SQL (HA) — Private IP only, no public      ║
║  CMEK encrypted (Cloud KMS), automated backups    ║
║  10.10.100.0/24 (peered, not routable externally) ║
╚═══════════════════════════════════════════════════╝
```

## Isolation Model

### Network Isolation (Defense Layer 1)
- **Each service gets its own /28 subnet** — no shared L2 broadcast domain
- **Default deny ALL** — ingress and egress
- **Per-pair firewall rules** — only the exact ports/IPs in the communication matrix
- **No internet for internal VMs** — no Cloud NAT, no default route
- **Private Google Access** only for Cloud KMS/HSM API calls
- **VPC Service Controls** perimeter — prevents data exfiltration even with stolen credentials
- **Packet Mirroring** → Cloud IDS for deep packet inspection

### Cryptographic Isolation (Defense Layer 2)
- **SHARD mTLS** — every inter-VM message is:
  - Encrypted: AEGIS-256 (or AES-256-GCM in FIPS mode)
  - Authenticated: HMAC-SHA512 with per-pair keys
  - Replay-protected: monotonic sequence + timestamp ±2s
  - Module-identity-bound: sender verified against communication matrix
- **X-Wing hybrid KEM** (ML-KEM-1024 + X25519) for key exchange — quantum resistant
- **Mandatory key fingerprint pinning** — MITM impossible even if CA compromised

### Auto-Mutation (Defense Layer 3) — "Compromise = Start Over"
- **Ratchet epoch: 30 seconds** — stolen session keys expire in 30s
- **SHARD key rotation: 1 hour** — inter-VM HMAC keys rotate hourly
- **FROST key refresh on anomaly** — if health check detects VM compromise,
  remaining VMs run a new DKG ceremony excluding the compromised node
- **Automatic credential revocation** — compromised VM's service account is
  disabled via Cloud IAM within seconds
- **Secret rotation via Secret Manager** — all secrets have 24h TTL with auto-rotation

### Hardware Isolation (Defense Layer 4)
- **Confidential VMs (AMD SEV-SNP)** — memory encrypted at hardware level
  Even GCP operators cannot read VM memory
- **Shielded VMs** — Secure Boot + vTPM + Integrity Monitoring
  Boot chain verified; runtime integrity checked every 60s
- **Sole-tenant nodes** (optional) — no other customers on the same physical host
- **Cloud HSM** — master keys never leave FIPS 140-2 Level 3 hardware

## GCP Services Used

| Service | Purpose | Why |
|---------|---------|-----|
| **Compute Engine** | Isolated VMs per service | Full control over OS, no shared runtime |
| **VPC** | Private network, no internet | Network-level isolation |
| **Cloud Armor** | DDoS + WAF on gateway | Layer 7 protection before traffic hits our code |
| **Cloud HSM** | Hardware key storage | Master keys never in software |
| **Cloud KMS** | CMEK for all encryption | Envelope encryption key hierarchy |
| **Secret Manager** | Secrets with auto-rotation | No secrets in env vars or disk |
| **Cloud SQL (HA)** | Database with private IP | Managed HA, automated backups, CMEK |
| **Cloud IDS** | Intrusion detection | Detect lateral movement |
| **VPC Service Controls** | Data exfiltration prevention | Even stolen SA keys can't export data |
| **Cloud Audit Logs** | Forensic trail | Every API call logged, tamper-evident |
| **Binary Authorization** | Supply chain security | Only signed binaries deploy |
| **OS Login** | SSH via IAM, no SSH keys | No key sprawl, centralized access control |
| **IAP (Identity-Aware Proxy)** | Admin access without public IP | Zero-trust admin access |
| **Cloud Monitoring** | Anomaly detection | Triggers key rotation on anomalies |
| **Packet Mirroring** | Deep packet inspection | Feed to Cloud IDS |
| **Organization Policies** | Enforce constraints | Block public IPs, external sharing |

## Attack Scenarios

### Scenario 1: Attacker compromises VM-TSS-1
- Gets 1 of 5 FROST shares (needs 3 to forge tokens)
- Within 60 seconds, health monitor detects anomaly
- Remaining 4 TSS VMs run new DKG excluding TSS-1
- TSS-1's share is now invalid for the new group key
- Attacker must simultaneously compromise 2 more VMs before rotation completes

### Scenario 2: Attacker compromises VM-OPAQUE-1
- Gets 1 of 3 OPRF shares (needs 2 to evaluate passwords)
- Cannot offline-attack any passwords with 1 share
- Anomaly detection triggers OPRF seed re-split excluding OPAQUE-1
- OPAQUE-1's share is invalidated

### Scenario 3: Attacker intercepts network traffic
- All traffic is SHARD-encrypted (AEGIS-256 + HMAC-SHA512)
- Key exchange used X-Wing (ML-KEM-1024 + X25519) — quantum resistant
- Key fingerprints are pinned — MITM impossible
- Even with a quantum computer, past sessions are unrecoverable (forward secrecy via ratchet)

### Scenario 4: Attacker compromises GCP credentials
- VPC Service Controls prevent data export outside perimeter
- Cloud HSM keys cannot be extracted (hardware barrier)
- Binary Authorization prevents deploying modified binaries
- Cloud Audit Logs alert on anomalous API calls
- Organization policies block creating public IPs or firewall holes

### Scenario 5: Attacker compromises VM-GATEWAY (the only public VM)
- Gateway holds ZERO secrets (no signing keys, no DB credentials, no OPRF shares)
- It only terminates TLS and forwards puzzled+KEM requests to orchestrator
- All it can see is encrypted SHARD payloads
- Ratchet epoch means any observed tokens expire in 30 seconds
