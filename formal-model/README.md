# MILNET SSO TLA+ Formal Model

## Overview

This TLA+ specification formally models the Tier 2 authentication ceremony of the MILNET SSO system. It captures the core flow from client initiation through OPAQUE authentication, receipt collection, threshold signing (TSS), and token verification, including an adversary model for node compromise and token forgery.

## What the Model Verifies

### Safety Properties (Invariants)

- **TypeOK** -- All state variables have correct types and values.
- **NoUnauthToken** -- Every verified token traces back to a completed ceremony for the same user. No token can be verified without a legitimate authentication flow.
- **ThresholdIntegrity** -- If fewer than 3 (threshold) of the 5 TSS nodes are compromised, no forged tokens can exist in the system.
- **SessionUniqueness** -- No two ceremonies share a session ID.
- **SessionIdMonotonic** -- Session IDs are assigned from a strictly increasing counter, guaranteeing freshness.

### Liveness Property (Temporal)

- **EventualAuth** -- Under weak fairness, every user eventually either gets a verified token or the system is degraded (threshold-many nodes compromised). This ensures the protocol does not deadlock for legitimate users when the system is healthy.

## Constants

| Constant | Default | Meaning |
|---|---|---|
| `Users` | `{u1, u2, u3}` | Set of user identifiers |
| `TSSNodes` | `{n1, n2, n3, n4, n5}` | Set of TSS signing nodes |
| `Threshold` | `3` | Minimum honest nodes needed to sign |
| `MaxCeremonies` | `3` | Upper bound on concurrent ceremonies (for finite model checking) |

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
3. Add the invariants (`NoUnauthToken`, `ThresholdIntegrity`, `SessionUniqueness`, `SessionIdMonotonic`, `TypeOK`) and the temporal property (`EventualAuth`).
4. Run TLC.

## Architecture Modeled

```
Client -> Gateway -> Orchestrator -> OPAQUE -> TSS (3-of-5) -> Verifier
                                                 ^
                                          Adversary (CompromiseNode, ForgeAttempt)
```

The model abstracts each module interaction into discrete actions. Byzantine behavior is modeled via `CompromiseNode` (marks a TSS node as compromised) and `ForgeAttempt` (adversary produces a forged token only when threshold-many nodes are compromised).
