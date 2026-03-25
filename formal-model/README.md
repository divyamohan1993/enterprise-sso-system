# MILNET SSO TLA+ Formal Model

## Overview

This TLA+ specification formally models all critical protocols of the MILNET SSO system:

- **Tier 1 (Sovereign)** -- FIDO2 + risk scoring ceremony
- **Tier 2 (Command)** -- OPAQUE + TSS threshold signing
- **Tier 3 (Sensor)** -- Attestation-based authentication
- **Tier 4 (Emergency)** -- 7-of-13 Shamir + out-of-band verification
- **FROST DKG** -- Distributed key generation (no single party learns the secret)
- **OPAQUE** -- Server-blind password authentication
- **Ratchet** -- Forward secrecy (compromise of current key does not reveal past)
- **Cross-Domain Guard** -- Bell-LaPadula information flow (no write-down, no read-up)
- **Token Lifecycle** -- Issuance, validation, revocation, expiry
- **Key Rotation** -- Atomic key rotation without service interruption

## What the Model Verifies

### Safety Properties (Invariants)

| Property | Description |
|----------|-------------|
| **TypeOK** | All state variables have correct types and values |
| **NoUnauthToken** | Every verified token traces back to a completed ceremony |
| **ThresholdIntegrity** | If fewer than 3 TSS nodes compromised, no forged tokens exist |
| **SessionUniqueness** | No two ceremonies share a session ID |
| **DKGSecretSafety** | No single DKG participant learns the group secret |
| **OPAQUEPasswordBlindness** | Server never sees the plaintext password |
| **RatchetForwardSecrecy** | Current epoch key is never in the history of past epochs |
| **RevokedTokenNeverVerified** | Revoked tokens are never in the verified set |
| **KeyRotationSafety** | Old key not decommissioned while live tokens depend on it |
| **Tier4ShareThreshold** | Tier 4 ceremony requires at least 7-of-13 Shamir shares |
| **Tier1Completeness** | Tier 1 ceremony requires FIDO2 + acceptable risk score |
| **Tier3AttestationRequired** | Tier 3 ceremony requires valid device attestation |

### Liveness Properties (Temporal)

| Property | Description |
|----------|-------------|
| **EventualAuth** | Every user eventually gets a verified token (or system is degraded) |
| **DKGEventualCompletion** | Every started DKG session eventually completes |
| **KeyRotationEventualCompletion** | Key rotation transitions eventually finish |

## Constants

| Constant | Default | Meaning |
|----------|---------|---------|
| `Users` | `{u1, u2, u3}` | Set of user identifiers |
| `TSSNodes` | `{n1, n2, n3, n4, n5}` | Set of TSS signing nodes |
| `Threshold` | `3` | Minimum honest nodes needed to sign |
| `MaxCeremonies` | `3` | Upper bound on concurrent ceremonies |
| `ClassificationLevels` | `{0, 1, 2, 3}` | Security classification levels (U, C, S, TS) |
| `DKGParticipants` | `{p1, p2, p3, p4, p5}` | FROST DKG participant identifiers |
| `ShamirNodes` | `{s1..s13}` | Shamir secret sharing nodes for Tier 4 |
| `ShamirThreshold` | `7` | Minimum Shamir shares for emergency recovery |
| `MaxEpochs` | `3` | Upper bound on ratchet epochs |

## How to Run

### Prerequisites

Install the TLA+ tools. The easiest way is via the [TLA+ Toolbox](https://lamport.azurewebsites.net/tla/toolbox.html) or the VS Code TLA+ extension.

### Using TLC from the command line

```bash
cd formal-model/

# Run the model checker
java -cp /path/to/tla2tools.jar tlc2.TLC milnet.tla -config milnet.cfg -workers auto
```

### Using the TLA+ Toolbox

1. Open the Toolbox and create a new spec pointing to `milnet.tla`.
2. Create a model using the constants defined in `milnet.cfg`.
3. Add all invariants and temporal properties listed in `milnet.cfg`.
4. Run TLC.

**Note**: The expanded model with 13 Shamir nodes and 5 DKG participants has a large state space. Consider reducing constants for initial exploration (e.g., `ShamirNodes = {s1, s2, s3}` with `ShamirThreshold = 2`).

## Architecture Modeled

```
                    ┌── Tier 1: FIDO2 + Risk Scoring ──────────────┐
                    │── Tier 2: OPAQUE + TSS (3-of-5) ─────────────│
Client -> Gateway ->│── Tier 3: Attestation ───────────────────────│-> Verifier
                    │── Tier 4: Shamir (7-of-13) + OOB ────────────│
                    └──────────────────────────────────────────────┘
                                      │
                              ┌───────┴───────┐
                              │   Adversary    │
                              │ CompromiseNode │
                              │  ForgeAttempt  │
                              └────────────────┘

Cross-cutting concerns:
  - FROST DKG: key generation for TSS nodes
  - OPAQUE: server-blind password auth
  - Ratchet: forward secrecy for token epochs
  - Cross-Domain Guard: Bell-LaPadula MAC enforcement
  - Token Lifecycle: issuance, revocation, expiry
  - Key Rotation: atomic dual-key transition
```

The model abstracts each module interaction into discrete actions. Byzantine behavior is modeled via `CompromiseNode` (marks a TSS node as compromised) and `ForgeAttempt` (adversary produces a forged token only when threshold-many nodes are compromised).
