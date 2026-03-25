# Key Ceremony Runbook

Classification: **CONTROLLED UNCLASSIFIED INFORMATION (CUI)**
Version: 1.0
Last Updated: 2026-03-25

---

## Table of Contents

1. [Pre-Ceremony Preparation](#1-pre-ceremony-preparation)
2. [DKG Ceremony (FROST 3-of-5)](#2-dkg-ceremony-frost-3-of-5)
3. [Key Custodian Responsibilities](#3-key-custodian-responsibilities)
4. [Witness Attestation Form](#4-witness-attestation-form)
5. [Emergency Key Recovery](#5-emergency-key-recovery)
6. [Annual Key Rotation Ceremony](#6-annual-key-rotation-ceremony)

---

## 1. Pre-Ceremony Preparation

### 1.1 Required Roles

| Role | Count | Clearance Required | Description |
|------|-------|--------------------|-------------|
| Ceremony Director | 1 | TS/SCI | Oversees and orchestrates all ceremony steps |
| Key Custodian | 3-5 | TS/SCI | Each generates and stores one FROST key share |
| Witness | 2 | SECRET or higher | Observes and attests to procedure integrity |
| Auditor | 1 | TS/SCI | Records all actions in the audit log, verifies compliance |

**Minimum quorum**: Ceremony Director + 3 Custodians + 1 Witness + 1 Auditor = 6 persons.

All participants must present government-issued photo ID and current clearance verification before entering the ceremony room.

### 1.2 Required Materials

| Item | Quantity | Verification |
|------|----------|-------------|
| FIPS 140-3 Level 3 HSM(s) | 1-5 (one per custodian preferred) | Firmware hash matches vendor manifest |
| Smart cards (PIV/CAC) | 5 (one per custodian) | Unexpired, verified chain of custody |
| Air-gapped laptops | 5 (one per custodian) | Freshly imaged, SHA-384 hash of boot image recorded |
| USB drives (write-once) | 5 | New, still in manufacturer seal |
| Tamper-evident bags | 10 | Unique serial numbers recorded before ceremony |
| Faraday bag (phones) | 1 | Verified RF-blocking |
| Printed ceremony checklists | 6+ | One per participant |
| Black permanent markers | 6+ | For signing tamper-evident bags |
| Video recording equipment | 0 | **Cameras are NOT permitted** in the ceremony room |
| Time source (GPS clock) | 1 | NTP-independent, battery-backed |

### 1.3 Environmental Requirements

- **Location**: SCIF (Sensitive Compartmented Information Facility) or equivalent secure room rated for TS/SCI material handling.
- **RF isolation**: Room must block all wireless signals. Verify with RF sweep before start.
- **Electronic devices**: All personal phones, smartwatches, and wireless devices surrendered into a Faraday bag at the door. Receipt issued.
- **Entry log**: Physical sign-in sheet with name, badge number, entry/exit timestamps.
- **Two-person integrity (TPI)**: No individual may be alone in the ceremony room at any time.

### 1.4 Pre-Checks (T-24 hours and T-0)

**T-24 hours (Ceremony Director + Auditor)**:

```
1. [ ] Verify HSM firmware version matches approved baseline
       $ hsm-tool --firmware-check --expected-hash <vendor_hash>

2. [ ] Verify air-gapped laptop OS image hashes
       $ sha384sum /dev/sda | tee laptop_N_image_hash.txt
       Compare against approved image hash in configuration management DB.

3. [ ] Verify ceremony software binary hashes
       $ sha384sum milnet-ceremony-tool | tee ceremony_tool_hash.txt
       Cross-reference with signed release manifest from build pipeline.
       See: ../REPLICATION.md for build instructions.

4. [ ] Verify all participant clearances are current (via security office)

5. [ ] Verify tamper-evident bag serial numbers are sequential and unbroken

6. [ ] Pre-stage all materials in the SCIF safe
```

**T-0 (All participants present)**:

```
7.  [ ] Ceremony Director reads aloud the ceremony purpose and procedure
8.  [ ] Each participant signs the attendance sheet
9.  [ ] Auditor starts the written audit log (timestamp, UTC)
10. [ ] RF sweep of ceremony room confirmed clean
11. [ ] All personal electronic devices collected into Faraday bag
```

---

## 2. DKG Ceremony (FROST 3-of-5)

This procedure generates a FROST threshold signing key split into 5 shares, where any 3 shares can produce a valid signature but fewer than 3 reveal no information about the group secret.

### 2.1 Overview

- **Protocol**: FROST (Flexible Round-Optimized Schnorr Threshold Signatures) over Ristretto255
- **Parameters**: n=5 (total shares), t=3 (threshold)
- **Binding**: Each share is encrypted to one custodian's PIV/CAC smart card public key
- **Implementation reference**: `crypto/src/threshold.rs` (the `dkg()` function)

### 2.2 Step-by-Step Procedure

#### Phase 1: Individual Key Material Generation

Each custodian (C1 through C5) performs the following on their own air-gapped laptop. Steps are read aloud by the Ceremony Director. Witnesses observe each custodian's screen.

```
STEP 2.2.1 — Each custodian boots their air-gapped laptop from verified USB image.

STEP 2.2.2 — Each custodian inserts their smart card and verifies it is recognized:
  $ milnet-ceremony-tool smartcard --verify
  Expected: "Smart card CN=<custodian_name> verified, certificate chain valid"

STEP 2.2.3 — Each custodian generates their DKG round-1 package:
  $ milnet-ceremony-tool dkg round1 \
      --participant-index <1-5> \
      --threshold 3 \
      --total-participants 5 \
      --output round1_C<N>.pkg
  The tool outputs a commitment package (public) and retains secret state in memory.
  Auditor records the SHA-384 hash of each round1_C<N>.pkg file.

STEP 2.2.4 — Round-1 packages are collected onto a single transfer USB by the
  Ceremony Director, witnessed by both Witnesses. Each custodian verifies their
  file hash after copy.
```

#### Phase 2: DKG Round 2 (Share Distribution)

```
STEP 2.2.5 — The transfer USB is brought to each custodian's laptop in turn.
  Each custodian loads all 5 round-1 packages and computes their round-2 response:
  $ milnet-ceremony-tool dkg round2 \
      --participant-index <1-5> \
      --round1-packages round1_C1.pkg,round1_C2.pkg,round1_C3.pkg,round1_C4.pkg,round1_C5.pkg \
      --output round2_C<N>.pkg
  Auditor records SHA-384 hash of each round2_C<N>.pkg file.

STEP 2.2.6 — Round-2 packages collected onto transfer USB (same procedure as 2.2.4).
```

#### Phase 3: Share Finalization

```
STEP 2.2.7 — Each custodian finalizes their key share:
  $ milnet-ceremony-tool dkg finalize \
      --participant-index <1-5> \
      --round2-packages round2_C1.pkg,round2_C2.pkg,round2_C3.pkg,round2_C4.pkg,round2_C5.pkg \
      --output-share share_C<N>.enc \
      --encrypt-to-smartcard
  The tool:
    a) Derives the custodian's final key share
    b) Derives the group public key (must be identical for all 5 custodians)
    c) Encrypts the share to the custodian's smart card public key
    d) Outputs the encrypted share file and prints the group public key fingerprint

STEP 2.2.8 — All 5 custodians read aloud their group public key fingerprint.
  The Ceremony Director verifies all 5 match.
  Auditor records the canonical group public key fingerprint:

  GROUP PUBLIC KEY FINGERPRINT: ____________________________________________

STEP 2.2.9 — Each custodian's encrypted share is written to their personal
  write-once USB drive. The Ceremony Director and one Witness observe each write.

STEP 2.2.10 — Each write-once USB is placed into a tamper-evident bag.
  The bag is sealed and signed across the seal by:
    - The custodian
    - Both witnesses
    - The Ceremony Director
  Auditor records tamper-evident bag serial number for each custodian.

  | Custodian | Bag Serial | SHA-384 of Encrypted Share |
  |-----------|------------|---------------------------|
  | C1        |            |                           |
  | C2        |            |                           |
  | C3        |            |                           |
  | C4        |            |                           |
  | C5        |            |                           |
```

#### Phase 4: Verification

```
STEP 2.2.11 — Signing test: Any 3 custodians (e.g., C1, C2, C3) decrypt their
  shares via smart card and perform a test threshold signature:
  $ milnet-ceremony-tool verify-threshold \
      --shares share_C1.enc,share_C2.enc,share_C3.enc \
      --message "CEREMONY VERIFICATION TEST" \
      --group-public-key <fingerprint>
  Expected: "Threshold signature VALID. Group key binding confirmed."

STEP 2.2.12 — Cleanup: All air-gapped laptops are securely wiped:
  $ milnet-ceremony-tool secure-erase --confirm
  Auditor verifies wipe completion on each laptop.
  Transfer USB is physically destroyed (shredded) in view of all participants.
```

#### Phase 5: Group Public Key Registration

```
STEP 2.2.13 — The group public key is registered in the system configuration.
  This step occurs on the production system (not air-gapped) by the Ceremony Director
  with Auditor present:
  - Update the FROST group verifying key in the TSS configuration
  - Reference: tss/src/distributed.rs, verifier/src/verify.rs
  - Deploy via the standard CI/CD pipeline (see ../REPLICATION.md)

STEP 2.2.14 — Ceremony Director declares the ceremony complete.
  All participants sign the Witness Attestation Form (Section 4).
  Auditor closes the audit log with final timestamp.
```

---

## 3. Key Custodian Responsibilities

### 3.1 Storage Requirements

Each custodian must store their tamper-evident bag containing the encrypted key share according to these requirements:

| Requirement | Specification |
|-------------|--------------|
| Physical security | GSA-approved security container (Class 5 or 6) |
| Access control | Two-person integrity for container access |
| Environmental | Temperature 60-80F, humidity 30-50%, no direct sunlight |
| Logging | All access to the container must be logged |
| Inspection | Weekly visual inspection of tamper-evident bag seal integrity |

### 3.2 Geographic Distribution

Shares must be stored at geographically separated facilities to survive single-site catastrophic events:

| Share | Minimum Separation | Example |
|-------|-------------------|---------|
| C1, C2 | Different buildings, same installation | Bldg A, Bldg B |
| C3 | Different installation, same region | Alternate site, <100mi |
| C4 | Different region | CONUS alternate, >500mi |
| C5 | Off-continent or hardened facility | OCONUS or underground |

No two shares may be stored in the same physical security container.

### 3.3 Emergency Contact Procedures

Each custodian must maintain a current emergency contact card on file with the Ceremony Director containing:

- Primary phone (SIPR-compatible if available)
- Secondary phone
- Secure email address
- Physical mailing address
- Next-of-kin or designated alternate custodian (with equivalent clearance)

**Response time requirements**:
- Routine key operations: respond within 24 hours
- Emergency key recovery: respond within 4 hours
- Compromise notification: respond within 1 hour

### 3.4 Share Recovery Procedures

If a custodian's tamper-evident bag is found with a broken seal, damaged, or missing:

1. **Immediately notify** the Ceremony Director and Auditor
2. **Assume compromise** of that share
3. **Initiate emergency re-keying** (Section 5) within 72 hours
4. **Conduct investigation** into the chain-of-custody failure
5. **File incident report** per organizational security policy

If a custodian becomes **permanently unavailable** (death, incapacitation, clearance revocation):

1. Ceremony Director designates a replacement custodian with equivalent clearance
2. The unavailable custodian's share is **not recovered** (it remains sealed)
3. A **new DKG ceremony** (Section 2) is conducted to generate entirely new key material
4. Old group key is rotated out per Section 6

---

## 4. Witness Attestation Form

```
═══════════════════════════════════════════════════════════════════════════
                   MILNET SSO KEY CEREMONY — WITNESS ATTESTATION
═══════════════════════════════════════════════════════════════════════════

CEREMONY INFORMATION
─────────────────────────────────────────────────────────────────────────
Date (UTC):           ______________________
Location (SCIF ID):   ______________________
Ceremony Type:        [ ] Initial DKG    [ ] Key Rotation    [ ] Emergency Recovery
Ceremony Identifier:  ______________________

PARTICIPANTS
─────────────────────────────────────────────────────────────────────────
Ceremony Director:   Name: ____________________  Badge: __________
Key Custodian 1:     Name: ____________________  Badge: __________
Key Custodian 2:     Name: ____________________  Badge: __________
Key Custodian 3:     Name: ____________________  Badge: __________
Key Custodian 4:     Name: ____________________  Badge: __________
Key Custodian 5:     Name: ____________________  Badge: __________
Witness 1:           Name: ____________________  Badge: __________
Witness 2:           Name: ____________________  Badge: __________
Auditor:             Name: ____________________  Badge: __________

GROUP PUBLIC KEY
─────────────────────────────────────────────────────────────────────────
SHA-384 Fingerprint of Group Public Key:

  ________________________________________________________________________

All 5 custodians confirmed identical fingerprint:  [ ] Yes   [ ] No

PROCEDURE VERIFICATION CHECKLIST
─────────────────────────────────────────────────────────────────────────
[ ] 1.  SCIF/secure room verified, RF sweep completed
[ ] 2.  All personal electronic devices surrendered
[ ] 3.  All participant identities and clearances verified
[ ] 4.  HSM firmware hashes verified against vendor manifest
[ ] 5.  Ceremony software binary hashes verified against signed release
[ ] 6.  Air-gapped laptop image hashes verified
[ ] 7.  DKG Round 1 completed by all 5 custodians
[ ] 8.  DKG Round 2 completed by all 5 custodians
[ ] 9.  Share finalization completed, all group key fingerprints match
[ ] 10. Threshold signing verification test passed (3-of-5)
[ ] 11. Each share encrypted to custodian's smart card
[ ] 12. Each share sealed in tamper-evident bag with signatures
[ ] 13. All air-gapped laptops securely wiped
[ ] 14. Transfer USB physically destroyed
[ ] 15. Group public key registered in production configuration

TAMPER-EVIDENT BAG REGISTRY
─────────────────────────────────────────────────────────────────────────
Custodian 1: Bag Serial ____________  Share Hash ________________________
Custodian 2: Bag Serial ____________  Share Hash ________________________
Custodian 3: Bag Serial ____________  Share Hash ________________________
Custodian 4: Bag Serial ____________  Share Hash ________________________
Custodian 5: Bag Serial ____________  Share Hash ________________________

SIGNATURES
─────────────────────────────────────────────────────────────────────────
I attest that the above ceremony was conducted in accordance with the
MILNET SSO Key Ceremony Runbook and that all steps were completed as
described. No deviations from procedure occurred unless noted below.

Ceremony Director: ___________________________ Date: __________
Key Custodian 1:   ___________________________ Date: __________
Key Custodian 2:   ___________________________ Date: __________
Key Custodian 3:   ___________________________ Date: __________
Key Custodian 4:   ___________________________ Date: __________
Key Custodian 5:   ___________________________ Date: __________
Witness 1:         ___________________________ Date: __________
Witness 2:         ___________________________ Date: __________
Auditor:           ___________________________ Date: __________

DEVIATIONS FROM PROCEDURE (if any)
─────────────────────────────────────────────────────────────────────────
________________________________________________________________________
________________________________________________________________________
________________________________________________________________________

NOTARIZATION BLOCK
─────────────────────────────────────────────────────────────────────────
State of: ______________________
County of: _____________________

On this ___ day of ____________, 20__, before me personally appeared
the above-named individuals, known to me (or proved to me on the basis
of satisfactory evidence) to be the persons whose names are subscribed
to the within instrument and acknowledged to me that they executed the
same in their authorized capacities.

WITNESS my hand and official seal.

Notary Public: ___________________________
Commission Number: ______________________
My Commission Expires: __________________

[SEAL]

═══════════════════════════════════════════════════════════════════════════
```

---

## 5. Emergency Key Recovery

### 5.1 When to Invoke

Emergency key recovery must be invoked when:

- **Custodian death or incapacitation**: A custodian is permanently unable to access their share, AND the system requires an immediate signing operation that cannot wait for a full re-keying ceremony.
- **Facility destruction**: A storage facility is destroyed (fire, natural disaster, hostile action), AND the share stored there is needed.
- **Confirmed compromise**: Evidence that a share has been accessed by unauthorized personnel.
- **Operational necessity**: Mission-critical signing required and fewer than 3 custodians are available through normal channels.

**Decision authority**: Emergency recovery requires written authorization from the Ceremony Director AND the organizational ISSM (Information System Security Manager).

### 5.2 Procedure for Assembling 3-of-5 Shares

```
STEP 5.2.1 — Ceremony Director contacts available custodians using emergency
  contact procedures (Section 3.3). Minimum 3 custodians required.

STEP 5.2.2 — Available custodians travel to a designated secure facility.
  If the primary SCIF is unavailable, the alternate SCIF is used.
  Two-person integrity maintained at all times.

STEP 5.2.3 — Each custodian presents their tamper-evident bag.
  Auditor verifies bag serial numbers against the ceremony registry.
  Witnesses verify seal integrity and signatures on each bag.

STEP 5.2.4 — Each custodian opens their bag and decrypts their share
  using their smart card on an air-gapped laptop:
  $ milnet-ceremony-tool share decrypt \
      --input share_C<N>.enc \
      --smartcard

STEP 5.2.5 — The 3+ decrypted shares are used for the required signing operation:
  $ milnet-ceremony-tool threshold-sign \
      --shares share_C<A>.dec,share_C<B>.dec,share_C<C>.dec \
      --message <data_to_sign> \
      --group-public-key <fingerprint>

STEP 5.2.6 — After signing, all decrypted share material is securely erased:
  $ milnet-ceremony-tool secure-erase --confirm
  Custodians re-encrypt shares to their smart cards and re-seal in
  NEW tamper-evident bags (new serial numbers recorded by Auditor).

STEP 5.2.7 — Auditor files emergency recovery report including:
  - Authorization documentation
  - Participants present
  - Reason for emergency
  - Actions taken
  - New tamper-evident bag serial numbers
```

### 5.3 Re-Keying Procedure After Emergency Recovery

After any emergency recovery event, a full re-keying ceremony must be scheduled within **30 days**. The re-keying follows the same procedure as the Annual Key Rotation (Section 6) with the following additional requirements:

1. All 5 shares must be regenerated (not just the compromised one)
2. The old group key must remain active during the transition period for verification of previously-issued tokens
3. A root cause analysis of the emergency must be completed before the new ceremony
4. Any custodian involved in the incident may be replaced at the Ceremony Director's discretion

---

## 6. Annual Key Rotation Ceremony

### 6.1 Schedule and Notification

- **Frequency**: Every 12 months from the date of the last DKG ceremony, or sooner if triggered by policy change, compromise, or operational need.
- **Notification**: Ceremony Director sends written notice to all custodians and participants at least **30 days** before the scheduled rotation date.
- **Confirmation**: All participants must confirm availability at least **14 days** before the ceremony.
- **Rescheduling**: If quorum cannot be achieved, reschedule within **14 days** of the original date. Document the delay.

### 6.2 Rotation Procedure

```
PHASE A — Generate New Key Material
─────────────────────────────────────────────────────────────────────────
STEP 6.2.1 — Conduct a full DKG ceremony (Section 2) to generate new
  group key and new shares. The new key is designated KEY_NEW.
  The existing key is designated KEY_OLD.

PHASE B — Transition Period (dual-key validation)
─────────────────────────────────────────────────────────────────────────
STEP 6.2.2 — Deploy KEY_NEW to the TSS nodes alongside KEY_OLD.
  The verifier must accept tokens signed by EITHER key during transition.
  Reference: verifier/src/verify.rs

STEP 6.2.3 — Configure new token issuance to use KEY_NEW exclusively.
  Reference: tss/src/distributed.rs

STEP 6.2.4 — Transition period lasts for the maximum token lifetime
  (default: 10 minutes) plus a safety buffer (default: 1 hour).
  During this period, monitor for:
  - Successful token issuance with KEY_NEW
  - Successful verification of KEY_NEW tokens
  - No KEY_OLD tokens being issued

PHASE C — Backward Compatibility Verification
─────────────────────────────────────────────────────────────────────────
STEP 6.2.5 — Verify that tokens issued under KEY_OLD during the transition
  period are still accepted until their natural expiry.

STEP 6.2.6 — Verify that new tokens issued under KEY_NEW are accepted by
  all verifier instances.

STEP 6.2.7 — Run the full test suite to confirm no regressions:
  See: ../REPLICATION.md for test execution instructions.

PHASE D — Decommission Old Key
─────────────────────────────────────────────────────────────────────────
STEP 6.2.8 — After the transition period, remove KEY_OLD from all verifier
  configurations.

STEP 6.2.9 — Old key share tamper-evident bags are collected from all 5
  custodians, opened in the presence of witnesses, and the USB drives are
  physically destroyed (shredded).

STEP 6.2.10 — Auditor records destruction of old key material including:
  - Old bag serial numbers
  - Method of destruction
  - Witnesses present
  - Timestamp

STEP 6.2.11 — Update the ceremony registry with new bag serial numbers
  and new group public key fingerprint.
```

### 6.3 Rotation Audit Trail

The following artifacts must be retained for **7 years** per records retention policy:

- Witness Attestation Form for the new ceremony
- Audit log of the rotation procedure
- Destruction log for old key material
- System configuration change records
- Test suite results from backward compatibility verification

---

## References

- [NIST SP 800-57 Part 1: Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) [DEPLOY: configure actual URL for local mirror]
- [FROST Protocol Specification (IETF RFC 9591)](https://www.rfc-editor.org/rfc/rfc9591.html) [DEPLOY: configure actual URL for local mirror]
- MILNET SSO Architecture: [../../ARCHITECTURE.md](../../ARCHITECTURE.md)
- MILNET SSO Deployment Guide: [../../DEPLOY.md](../../DEPLOY.md)
- MILNET SSO Replication Guide: [../REPLICATION.md](../REPLICATION.md)
- FROST DKG Implementation: `crypto/src/threshold.rs`
- Token Builder: `tss/src/distributed.rs`
- Token Verifier: `verifier/src/verify.rs`
- TLA+ Formal Model: [../../formal-model/milnet.tla](../../formal-model/milnet.tla)
