# MILNET SSO System -- VM Layout

## Recommended 5-VM Distribution

```
VM-1 (gateway + admin):      gateway, admin
VM-2 (auth-primary):         orchestrator, opaque-1, tss-coordinator
VM-3 (auth-replica-1):       orchestrator, opaque-2, tss-signer-1, tss-signer-2
VM-4 (auth-replica-2):       orchestrator, opaque-3, tss-signer-3, tss-signer-4
VM-5 (verification + audit): verifier, ratchet, risk, audit, kt, tss-signer-5
```

## Why This Distribution Maximizes Fault Tolerance

### Single-VM failure analysis

| VM Lost | Services Lost | Impact |
|---------|--------------|--------|
| VM-1 | gateway, admin | No auth traffic enters. Other services unaffected. Admin unavailable. Recovery: route traffic to standby gateway. |
| VM-2 | orchestrator-0, opaque-1, tss-coordinator | Raft elects new orchestrator leader (2 of 3 survive). OPAQUE still has 2-of-3. TSS coordinator failover via Raft on remaining coordinators (if co-located) or signers continue with cached coordinator state. |
| VM-3 | orchestrator-1, opaque-2, tss-signer-1, tss-signer-2 | Raft still has majority (2 of 3). OPAQUE still has 2-of-3. FROST loses 2 signers but retains 3 of 5 -- threshold met. |
| VM-4 | orchestrator-2, opaque-3, tss-signer-3, tss-signer-4 | Raft still has majority (2 of 3). OPAQUE drops to 1-of-3 -- **threshold NOT met** (need 2). FROST retains 3 of 5 -- threshold met. |
| VM-5 | verifier, ratchet, risk, audit, kt, tss-signer-5 | Verification pipeline down. FROST retains 4 of 5 -- threshold met. Audit BFT degrades but continues if other audit instances exist. |

### Key observations

1. **No single VM failure causes total system outage.** The worst case (VM-4
   or VM-5) degrades specific subsystems but does not expose key material.

2. **OPAQUE 2-of-3 tolerates any single VM failure except VM-4.** To improve
   this, consider adding a 6th VM and redistributing OPAQUE shares so no two
   VMs hold the "last surviving" pair. In the 5-VM layout, VM-2+VM-3 or
   VM-2+VM-4 always satisfy the threshold.

3. **FROST 3-of-5 tolerates any single VM failure.** The worst case loses 2
   signers (VM-3 or VM-4), leaving exactly 3 -- the threshold.

4. **Raft 3-node quorum tolerates any single VM failure.** All three
   orchestrator instances are on separate VMs (VM-2, VM-3, VM-4).

5. **Gateway isolation.** The public-facing gateway is on its own VM (VM-1),
   physically separated from all cryptographic services. A gateway compromise
   does not expose OPAQUE shares, TSS shares, or the master KEK.

## Port Allocation

| Service | Listen Port | Health Port | Protocol |
|---------|------------|-------------|----------|
| gateway | 9100 | 10100 | PQ-TLS (public) |
| orchestrator | 9101 | 10101 | mTLS (SHARD) |
| opaque | 9102 | 10102 | mTLS (SHARD) |
| tss-coordinator | 9103 | 10103 | mTLS (SHARD) |
| verifier | 9104 | 10104 | mTLS (SHARD) |
| ratchet | 9105 | 10105 | mTLS (SHARD) |
| risk | 9106 | 10106 | mTLS (SHARD) |
| audit | 9108 | 10108 | mTLS (SHARD) |
| kt | 9109 | 10109 | mTLS (SHARD) |
| tss-signer-1 | 9110 | 10110 | mTLS (SHARD) |
| tss-signer-2 | 9111 | 10111 | mTLS (SHARD) |
| tss-signer-3 | 9112 | 10112 | mTLS (SHARD) |
| tss-signer-4 | 9113 | 10113 | mTLS (SHARD) |
| tss-signer-5 | 9114 | 10114 | mTLS (SHARD) |
| admin | 8080 | 9080 | TLS (internal) |
| raft (orch) | 9090 | -- | mTLS (SHARD) |
| raft (tss-coord) | 9190 | -- | mTLS (SHARD) |

## Scaling to 7+ VMs

For higher availability, redistribute services:

```
VM-1: gateway
VM-2: orchestrator, tss-coordinator
VM-3: orchestrator, opaque-1, tss-signer-1
VM-4: orchestrator, opaque-2, tss-signer-2
VM-5: opaque-3, tss-signer-3
VM-6: verifier, ratchet, risk, tss-signer-4
VM-7: audit, kt, tss-signer-5, admin
```

This layout ensures every threshold system (OPAQUE 2-of-3, FROST 3-of-5,
Raft 2-of-3) can tolerate any **two** simultaneous VM failures.
