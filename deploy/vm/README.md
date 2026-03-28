# MILNET SSO System -- VM Deployment Guide

## Overview

This directory contains systemd unit files, environment templates, and provisioning
scripts for deploying the MILNET SSO system across bare-metal or VM infrastructure.

## Minimum Requirements

**5 VMs required.** This minimum is dictated by the system's cryptographic
fault-tolerance requirements:

1. **FROST 3-of-5 threshold signing** requires 5 distinct signer processes. Placing
   all 5 on a single host defeats the purpose -- a host failure would lose all shares.
   With 5 VMs, a single VM loss loses at most 2 signers, preserving the 3-of-5 quorum.

2. **Raft consensus** (orchestrator, tss-coordinator) needs a 3-node majority. With
   services spread across VMs, losing any single VM preserves the Raft quorum.

3. **OPAQUE 2-of-3** threshold shares must reside on separate hosts so that
   compromising one host yields at most one share.

4. **BFT audit** (7 nodes, f=2) needs at least 5 honest nodes. The 7 audit processes
   can be distributed across all VMs with at most 2 per VM.

## VM Sizing Recommendations

| VM Role | vCPUs | RAM | Disk | Notes |
|---------|-------|-----|------|-------|
| VM-1 (gateway + admin) | 4 | 8 GB | 50 GB SSD | TLS termination, public-facing |
| VM-2 (auth-primary) | 8 | 16 GB | 100 GB SSD | Orchestrator + OPAQUE + TSS coordinator |
| VM-3 (auth-replica-1) | 8 | 16 GB | 100 GB SSD | Orchestrator + OPAQUE + TSS signers |
| VM-4 (auth-replica-2) | 8 | 16 GB | 100 GB SSD | Orchestrator + OPAQUE + TSS signers |
| VM-5 (verification) | 8 | 16 GB | 200 GB SSD | Verifier + ratchet + risk + audit + KT |

All VMs should use encrypted disks and be deployed in the same region but across
different availability zones (or physical racks for bare-metal).

## Network Topology

```
                    Internet
                       |
                  [ Firewall ]
                       |
              +--------+--------+
              |   VM-1 (DMZ)    |
              |  gateway:9100   |
              |  admin:8080     |
              +--------+--------+
                       |
          Private Network (10.0.0.0/24)
       +-------+-------+-------+-------+
       |       |       |       |       |
    +--+--+ +--+--+ +--+--+ +--+--+ +--+--+
    | VM-1| | VM-2| | VM-3| | VM-4| | VM-5|
    +-----+ +-----+ +-----+ +-----+ +-----+
     :9100   :9101   :9101   :9101   :9104
     :8080   :9102   :9102   :9102   :9105
             :9103   :9110   :9112   :9106
                     :9111   :9113   :9108
                                     :9109
                                     :9114
```

Ports shown are the service listen ports per VM. All inter-service traffic
uses mTLS via the SHARD transport layer.

## Deployment Steps

1. Build the release binary: `cargo build --release`
2. Edit env files in `deploy/vm/env/` with production values
3. Run `./deploy/vm/provision.sh VM1_IP VM2_IP VM3_IP VM4_IP VM5_IP`
4. Verify health: `curl -k https://VM1_IP:10100/healthz`

## Firewall Rules

Only VM-1 (gateway) should be exposed to the internet on port 9100 (443).
All other VMs communicate exclusively on the private network. Block all
external access to ports 9101-9114 and 8080.

## Recovery

Use `deploy/vm/heal.sh TARGET_IP SERVICE_NAME` to replace a corrupted binary
and restart the affected service.
