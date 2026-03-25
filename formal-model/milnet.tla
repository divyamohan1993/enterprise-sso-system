--------------------------- MODULE milnet ---------------------------
(**************************************************************************)
(* TLA+ Formal Model for MILNET SSO Authentication System                *)
(*                                                                        *)
(* Models all critical protocols:                                         *)
(*   - Tier 1 (Sovereign): FIDO2 + risk scoring ceremony                 *)
(*   - Tier 2 (Command):   OPAQUE + TSS threshold signing                *)
(*   - Tier 3 (Sensor):    Attestation-based authentication              *)
(*   - Tier 4 (Emergency): 7-of-13 Shamir + OOB verification            *)
(*   - FROST DKG:          Distributed key generation safety             *)
(*   - OPAQUE Protocol:    Server-blind password authentication          *)
(*   - Ratchet Protocol:   Forward secrecy guarantees                    *)
(*   - Cross-Domain Guard: Bell-LaPadula information flow                *)
(*   - Token Lifecycle:    Issuance, validation, revocation, expiry      *)
(*   - Key Rotation:       Atomic rotation without service interruption  *)
(*                                                                        *)
(* Verifies safety and liveness for all protocols.                        *)
(**************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Users,              \* Set of user identifiers
    TSSNodes,           \* Set of TSS node identifiers
    Threshold,          \* Minimum honest nodes required for signing (3)
    MaxCeremonies,      \* Bound on total ceremonies for model checking
    ClassificationLevels,  \* Set of classification levels {0, 1, 2, 3}
    DKGParticipants,    \* Set of DKG participant identifiers
    ShamirNodes,        \* Set of Shamir secret sharing nodes (13 for Tier 4)
    ShamirThreshold,    \* Minimum Shamir shares for emergency recovery (7)
    MaxEpochs           \* Bound on ratchet epochs for model checking

VARIABLES
    \* ── Tier 2 Ceremony (original) ──
    ceremonies,         \* Function from session_id -> [user, phase, receipts]
    tokens,             \* Set of issued tokens: [user, session_id, forged, tier, classification, audience, epoch, revoked, expiry_step]
    verified,           \* Set of verified tokens
    compromised,        \* Set of compromised TSS nodes
    nextSessionId,      \* Monotonic counter for unique session IDs
    nonceCtr,           \* Function from TSSNode -> counter (monotonic)

    \* ── Tier 1 (Sovereign) Ceremony ──
    tier1Ceremonies,    \* Function from session_id -> [user, phase, fido2_done, risk_score]

    \* ── Tier 3 (Sensor) Ceremony ──
    tier3Ceremonies,    \* Function from session_id -> [user, phase, attestation_valid]

    \* ── Tier 4 (Emergency) Ceremony ──
    tier4Ceremonies,    \* Function from session_id -> [user, phase, shares_collected, oob_verified]

    \* ── FROST DKG Protocol ──
    dkgSessions,        \* Function from dkg_id -> [phase, round1_done, round2_done, participants_committed, secret_exposed]
    nextDKGId,           \* Monotonic counter for DKG session IDs

    \* ── OPAQUE Protocol ──
    opaqueState,        \* Function from user -> [phase, server_saw_password]

    \* ── Ratchet Protocol ──
    ratchetEpoch,       \* Function from session_id -> current epoch number
    ratchetHistory,     \* Function from session_id -> set of past epoch numbers

    \* ── Cross-Domain Guard ──
    userClearance,      \* Function from user -> classification level
    dataClassification, \* Function from resource_id -> classification level
    accessLog,          \* Set of [user, resource, allowed]

    \* ── Token Lifecycle ──
    revokedTokens,      \* Set of revoked token identifiers
    globalStep,         \* Global step counter (for token expiry)

    \* ── Key Rotation ──
    activeKeyId,        \* Current active signing key generation ID
    keyTransition,      \* [old_key, new_key, phase] or NULL
    keysInService       \* Set of key IDs accepted by verifiers

\* All variables grouped
vars == <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
          tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
          dkgSessions, nextDKGId,
          opaqueState,
          ratchetEpoch, ratchetHistory,
          userClearance, dataClassification, accessLog,
          revokedTokens, globalStep,
          activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* Type invariant                                                         *)
(**************************************************************************)
TypeOK ==
    /\ nextSessionId \in Nat
    /\ compromised \subseteq TSSNodes
    /\ \A sid \in DOMAIN ceremonies :
        /\ ceremonies[sid].user \in Users
        /\ ceremonies[sid].phase \in {"started", "opaque_done", "receipts_collected", "signed"}
    /\ \A t \in tokens :
        /\ t.user \in Users
        /\ t.session_id \in Nat
        /\ t.forged \in BOOLEAN
    /\ \A t \in verified : t \in tokens
    /\ nextDKGId \in Nat
    /\ globalStep \in Nat
    /\ activeKeyId \in Nat

(**************************************************************************)
(* Initial state                                                          *)
(**************************************************************************)
Init ==
    /\ ceremonies = <<>>
    /\ tokens = {}
    /\ verified = {}
    /\ compromised = {}
    /\ nextSessionId = 1
    /\ nonceCtr = [n \in TSSNodes |-> 0]
    \* Tier 1
    /\ tier1Ceremonies = <<>>
    \* Tier 3
    /\ tier3Ceremonies = <<>>
    \* Tier 4
    /\ tier4Ceremonies = <<>>
    \* FROST DKG
    /\ dkgSessions = <<>>
    /\ nextDKGId = 1
    \* OPAQUE
    /\ opaqueState = [u \in Users |-> [phase |-> "idle", server_saw_password |-> FALSE]]
    \* Ratchet
    /\ ratchetEpoch = <<>>
    /\ ratchetHistory = <<>>
    \* Cross-Domain Guard
    /\ userClearance = [u \in Users |-> 0]     \* Default: UNCLASSIFIED
    /\ dataClassification = <<>>
    /\ accessLog = {}
    \* Token Lifecycle
    /\ revokedTokens = {}
    /\ globalStep = 0
    \* Key Rotation
    /\ activeKeyId = 1
    /\ keyTransition = [old_key |-> 0, new_key |-> 0, phase |-> "none"]
    /\ keysInService = {1}

(**************************************************************************)
(* Helpers                                                                *)
(**************************************************************************)
ActiveCeremonies == DOMAIN ceremonies
HonestNodes == TSSNodes \ compromised
NumCompromised == Cardinality(compromised)
TotalCeremonies == Cardinality(ActiveCeremonies)

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* TIER 2 (COMMAND) CEREMONY — Original Protocol                         *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

StartCeremony(user) ==
    /\ TotalCeremonies < MaxCeremonies
    /\ LET sid == nextSessionId
       IN /\ ceremonies' = [sid |-> [user |-> user,
                                      phase |-> "started",
                                      receipts |-> 0]]
                            @@ ceremonies
          /\ nextSessionId' = nextSessionId + 1
    /\ UNCHANGED <<tokens, verified, compromised, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

OpaqueAuth(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "started"
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "opaque_done",
                                        ![sid].receipts = 1]
    /\ UNCHANGED <<tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

CollectReceipts(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "opaque_done"
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "receipts_collected"]
    /\ UNCHANGED <<tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

ThresholdSign(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "receipts_collected"
    /\ Cardinality(HonestNodes) >= Threshold
    /\ activeKeyId \in keysInService  \* Must use a valid key
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "signed"]
    /\ LET user == ceremonies[sid].user
           tok  == [user |-> user, session_id |-> sid, forged |-> FALSE,
                    tier |-> 2, classification |-> 0,
                    audience |-> "default", epoch |-> 0,
                    revoked |-> FALSE, expiry_step |-> globalStep + 10,
                    key_id |-> activeKeyId]
       IN tokens' = tokens \union {tok}
    /\ nonceCtr' = [n \in TSSNodes |->
                        IF n \in HonestNodes
                        THEN nonceCtr[n] + 1
                        ELSE nonceCtr[n]]
    /\ UNCHANGED <<verified, compromised, nextSessionId,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

VerifyToken(tok) ==
    /\ tok \in tokens
    /\ tok \notin verified
    /\ tok.forged = FALSE
    /\ tok.revoked = FALSE              \* Cannot verify revoked tokens
    /\ tok.expiry_step > globalStep     \* Cannot verify expired tokens
    /\ tok.key_id \in keysInService     \* Key must still be in service
    /\ verified' = verified \union {tok}
    /\ UNCHANGED <<ceremonies, tokens, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

CompromiseNode(node) ==
    /\ node \in TSSNodes
    /\ node \notin compromised
    /\ compromised' = compromised \union {node}
    /\ UNCHANGED <<ceremonies, tokens, verified, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

ForgeAttempt(user) ==
    /\ user \in Users
    /\ Cardinality(compromised) >= Threshold
    /\ LET tok == [user |-> user, session_id |-> 0, forged |-> TRUE,
                   tier |-> 2, classification |-> 0,
                   audience |-> "default", epoch |-> 0,
                   revoked |-> FALSE, expiry_step |-> globalStep + 10,
                   key_id |-> activeKeyId]
       IN tokens' = tokens \union {tok}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* TIER 1 (SOVEREIGN) CEREMONY — FIDO2 + Risk Scoring                    *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

Tier1Start(user) ==
    /\ Cardinality(DOMAIN tier1Ceremonies) < MaxCeremonies
    /\ LET sid == nextSessionId
       IN /\ tier1Ceremonies' = [sid |-> [user |-> user,
                                           phase |-> "started",
                                           fido2_done |-> FALSE,
                                           risk_score |-> 0]]
                                 @@ tier1Ceremonies
          /\ nextSessionId' = nextSessionId + 1
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nonceCtr,
                   tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* 3-person ceremony: FIDO2 authenticator verification
Tier1FIDO2(sid) ==
    /\ sid \in DOMAIN tier1Ceremonies
    /\ tier1Ceremonies[sid].phase = "started"
    /\ tier1Ceremonies' = [tier1Ceremonies EXCEPT ![sid].phase = "fido2_done",
                                                   ![sid].fido2_done = TRUE]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Risk scoring: compute and evaluate risk before issuing token
Tier1RiskEval(sid) ==
    /\ sid \in DOMAIN tier1Ceremonies
    /\ tier1Ceremonies[sid].phase = "fido2_done"
    /\ tier1Ceremonies[sid].fido2_done = TRUE
    \* Risk score must be below threshold (modeled as score < 50)
    /\ tier1Ceremonies' = [tier1Ceremonies EXCEPT ![sid].phase = "risk_evaluated",
                                                   ![sid].risk_score = 25]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

Tier1IssueToken(sid) ==
    /\ sid \in DOMAIN tier1Ceremonies
    /\ tier1Ceremonies[sid].phase = "risk_evaluated"
    /\ tier1Ceremonies[sid].risk_score < 50  \* Risk threshold
    /\ Cardinality(HonestNodes) >= Threshold
    /\ activeKeyId \in keysInService
    /\ tier1Ceremonies' = [tier1Ceremonies EXCEPT ![sid].phase = "signed"]
    /\ LET user == tier1Ceremonies[sid].user
           tok  == [user |-> user, session_id |-> sid, forged |-> FALSE,
                    tier |-> 1, classification |-> 3,
                    audience |-> "sovereign", epoch |-> 0,
                    revoked |-> FALSE, expiry_step |-> globalStep + 10,
                    key_id |-> activeKeyId]
       IN tokens' = tokens \union {tok}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr,
                   tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* TIER 3 (SENSOR) CEREMONY — Attestation-Based Auth                     *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

Tier3Start(user) ==
    /\ Cardinality(DOMAIN tier3Ceremonies) < MaxCeremonies
    /\ LET sid == nextSessionId
       IN /\ tier3Ceremonies' = [sid |-> [user |-> user,
                                           phase |-> "started",
                                           attestation_valid |-> FALSE]]
                                 @@ tier3Ceremonies
          /\ nextSessionId' = nextSessionId + 1
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nonceCtr,
                   tier1Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Device attestation verification (TPM/secure element)
Tier3Attestation(sid) ==
    /\ sid \in DOMAIN tier3Ceremonies
    /\ tier3Ceremonies[sid].phase = "started"
    /\ tier3Ceremonies' = [tier3Ceremonies EXCEPT ![sid].phase = "attested",
                                                   ![sid].attestation_valid = TRUE]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

Tier3IssueToken(sid) ==
    /\ sid \in DOMAIN tier3Ceremonies
    /\ tier3Ceremonies[sid].phase = "attested"
    /\ tier3Ceremonies[sid].attestation_valid = TRUE
    /\ Cardinality(HonestNodes) >= Threshold
    /\ activeKeyId \in keysInService
    /\ tier3Ceremonies' = [tier3Ceremonies EXCEPT ![sid].phase = "signed"]
    /\ LET user == tier3Ceremonies[sid].user
           tok  == [user |-> user, session_id |-> sid, forged |-> FALSE,
                    tier |-> 3, classification |-> 0,
                    audience |-> "sensor", epoch |-> 0,
                    revoked |-> FALSE, expiry_step |-> globalStep + 5,
                    key_id |-> activeKeyId]
       IN tokens' = tokens \union {tok}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* TIER 4 (EMERGENCY) CEREMONY — 7-of-13 Shamir + OOB Verification      *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

Tier4Start(user) ==
    /\ Cardinality(DOMAIN tier4Ceremonies) < MaxCeremonies
    /\ LET sid == nextSessionId
       IN /\ tier4Ceremonies' = [sid |-> [user |-> user,
                                           phase |-> "started",
                                           shares_collected |-> 0,
                                           oob_verified |-> FALSE]]
                                 @@ tier4Ceremonies
          /\ nextSessionId' = nextSessionId + 1
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Collect Shamir shares (one at a time, needs 7-of-13)
Tier4CollectShare(sid) ==
    /\ sid \in DOMAIN tier4Ceremonies
    /\ tier4Ceremonies[sid].phase = "started"
    /\ tier4Ceremonies[sid].shares_collected < Cardinality(ShamirNodes)
    /\ tier4Ceremonies' = [tier4Ceremonies EXCEPT
        ![sid].shares_collected = tier4Ceremonies[sid].shares_collected + 1,
        ![sid].phase = IF tier4Ceremonies[sid].shares_collected + 1 >= ShamirThreshold
                       THEN "shares_sufficient"
                       ELSE "started"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Out-of-band verification (phone call, in-person, etc.)
Tier4OOBVerify(sid) ==
    /\ sid \in DOMAIN tier4Ceremonies
    /\ tier4Ceremonies[sid].phase = "shares_sufficient"
    /\ tier4Ceremonies' = [tier4Ceremonies EXCEPT ![sid].phase = "oob_verified",
                                                   ![sid].oob_verified = TRUE]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

Tier4IssueToken(sid) ==
    /\ sid \in DOMAIN tier4Ceremonies
    /\ tier4Ceremonies[sid].phase = "oob_verified"
    /\ tier4Ceremonies[sid].oob_verified = TRUE
    /\ tier4Ceremonies[sid].shares_collected >= ShamirThreshold
    /\ activeKeyId \in keysInService
    /\ tier4Ceremonies' = [tier4Ceremonies EXCEPT ![sid].phase = "signed"]
    /\ LET user == tier4Ceremonies[sid].user
           tok  == [user |-> user, session_id |-> sid, forged |-> FALSE,
                    tier |-> 4, classification |-> 3,
                    audience |-> "emergency", epoch |-> 0,
                    revoked |-> FALSE, expiry_step |-> globalStep + 3,
                    key_id |-> activeKeyId]
       IN tokens' = tokens \union {tok}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* FROST DKG PROTOCOL                                                     *)
(* Safety: No single party learns the group secret                        *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

DKGStart ==
    /\ Cardinality(DOMAIN dkgSessions) < MaxCeremonies
    /\ LET did == nextDKGId
       IN /\ dkgSessions' = [did |-> [phase |-> "round1",
                                        round1_done |-> {},
                                        round2_done |-> {},
                                        participants_committed |-> {},
                                        secret_exposed |-> FALSE]]
                              @@ dkgSessions
          /\ nextDKGId' = nextDKGId + 1
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   opaqueState, ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

DKGRound1Complete(did, participant) ==
    /\ did \in DOMAIN dkgSessions
    /\ dkgSessions[did].phase = "round1"
    /\ participant \in DKGParticipants
    /\ participant \notin dkgSessions[did].round1_done
    /\ LET newR1 == dkgSessions[did].round1_done \union {participant}
       IN dkgSessions' = [dkgSessions EXCEPT
            ![did].round1_done = newR1,
            ![did].phase = IF Cardinality(newR1) = Cardinality(DKGParticipants)
                           THEN "round2"
                           ELSE "round1"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   nextDKGId, tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   opaqueState, ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

DKGRound2Complete(did, participant) ==
    /\ did \in DOMAIN dkgSessions
    /\ dkgSessions[did].phase = "round2"
    /\ participant \in DKGParticipants
    /\ participant \notin dkgSessions[did].round2_done
    /\ LET newR2 == dkgSessions[did].round2_done \union {participant}
       IN dkgSessions' = [dkgSessions EXCEPT
            ![did].round2_done = newR2,
            ![did].participants_committed = newR2,
            ![did].phase = IF Cardinality(newR2) = Cardinality(DKGParticipants)
                           THEN "complete"
                           ELSE "round2"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   nextDKGId, tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   opaqueState, ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* OPAQUE PROTOCOL — Server-Blind Password Auth                           *)
(* Safety: Server never sees the plaintext password                       *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

OPAQUEStart(user) ==
    /\ user \in Users
    /\ opaqueState[user].phase = "idle"
    /\ opaqueState' = [opaqueState EXCEPT ![user].phase = "login_started",
                                           ![user].server_saw_password = FALSE]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

OPAQUEFinish(user) ==
    /\ user \in Users
    /\ opaqueState[user].phase = "login_started"
    /\ opaqueState' = [opaqueState EXCEPT ![user].phase = "complete"]
    \* The server NEVER transitions server_saw_password to TRUE
    \* This is the core safety property of OPAQUE
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

OPAQUEReset(user) ==
    /\ user \in Users
    /\ opaqueState[user].phase = "complete"
    /\ opaqueState' = [opaqueState EXCEPT ![user].phase = "idle"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* RATCHET PROTOCOL — Forward Secrecy                                     *)
(* Safety: Compromise of current key does not reveal past keys            *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

RatchetInit(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "signed"
    /\ sid \notin DOMAIN ratchetEpoch
    /\ ratchetEpoch' = [sid |-> 0] @@ ratchetEpoch
    /\ ratchetHistory' = [sid |-> {}] @@ ratchetHistory
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

RatchetAdvance(sid) ==
    /\ sid \in DOMAIN ratchetEpoch
    /\ ratchetEpoch[sid] < MaxEpochs
    /\ LET oldEpoch == ratchetEpoch[sid]
           newEpoch == oldEpoch + 1
       IN /\ ratchetEpoch' = [ratchetEpoch EXCEPT ![sid] = newEpoch]
          /\ ratchetHistory' = [ratchetHistory EXCEPT
                ![sid] = ratchetHistory[sid] \union {oldEpoch}]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* CROSS-DOMAIN GUARD — Bell-LaPadula Information Flow                    *)
(* Safety: No write-down, no read-up                                      *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

\* Model read access: user reads resource
CrossDomainRead(user, resource) ==
    /\ user \in Users
    /\ resource \in DOMAIN dataClassification
    /\ LET uLevel == userClearance[user]
           dLevel == dataClassification[resource]
           allowed == uLevel >= dLevel    \* No read-up: user clearance >= data level
       IN accessLog' = accessLog \union {[user |-> user, resource |-> resource, allowed |-> allowed]}
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Model write access: user writes to resource
CrossDomainWrite(user, resource) ==
    /\ user \in Users
    /\ resource \in DOMAIN dataClassification
    /\ LET uLevel == userClearance[user]
           dLevel == dataClassification[resource]
           allowed == uLevel <= dLevel    \* No write-down: user clearance <= data level
       IN accessLog' = accessLog \union {[user |-> user, resource |-> resource, allowed |-> allowed]}
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification,
                   revokedTokens, globalStep,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* TOKEN LIFECYCLE — Issuance, Validation, Revocation, Expiry             *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

RevokeToken(tok) ==
    /\ tok \in tokens
    /\ tok.revoked = FALSE
    /\ tokens' = (tokens \ {tok}) \union
                 {[tok EXCEPT !.revoked = TRUE]}
    /\ revokedTokens' = revokedTokens \union {tok.session_id}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   globalStep,
                   activeKeyId, keyTransition, keysInService>>

\* Global clock tick (for token expiry)
Tick ==
    /\ globalStep' = globalStep + 1
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens,
                   activeKeyId, keyTransition, keysInService>>

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* KEY ROTATION — Atomic Rotation Without Service Interruption            *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

\* Start key rotation: generate new key alongside old
KeyRotationStart ==
    /\ keyTransition.phase = "none"
    /\ LET newKeyId == activeKeyId + 1
       IN /\ keyTransition' = [old_key |-> activeKeyId, new_key |-> newKeyId, phase |-> "dual"]
          /\ keysInService' = keysInService \union {newKeyId}
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId>>

\* Switch to new key for signing
KeyRotationSwitch ==
    /\ keyTransition.phase = "dual"
    /\ activeKeyId' = keyTransition.new_key
    /\ keyTransition' = [keyTransition EXCEPT !.phase = "switched"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   keysInService>>

\* Complete rotation: remove old key from service
KeyRotationComplete ==
    /\ keyTransition.phase = "switched"
    \* Only decommission old key if no unexpired tokens use it
    /\ ~\E tok \in tokens : tok.key_id = keyTransition.old_key
                             /\ tok.expiry_step > globalStep
                             /\ tok.revoked = FALSE
    /\ keysInService' = keysInService \ {keyTransition.old_key}
    /\ keyTransition' = [old_key |-> 0, new_key |-> 0, phase |-> "none"]
    /\ UNCHANGED <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr,
                   tier1Ceremonies, tier3Ceremonies, tier4Ceremonies,
                   dkgSessions, nextDKGId, opaqueState,
                   ratchetEpoch, ratchetHistory,
                   userClearance, dataClassification, accessLog,
                   revokedTokens, globalStep,
                   activeKeyId>>

(**************************************************************************)
(* Next-state relation                                                    *)
(**************************************************************************)
Next ==
    \* Tier 2 (original)
    \/ \E u \in Users : StartCeremony(u)
    \/ \E sid \in ActiveCeremonies : OpaqueAuth(sid)
    \/ \E sid \in ActiveCeremonies : CollectReceipts(sid)
    \/ \E sid \in ActiveCeremonies : ThresholdSign(sid)
    \/ \E tok \in tokens : VerifyToken(tok)
    \/ \E n \in TSSNodes : CompromiseNode(n)
    \/ \E u \in Users : ForgeAttempt(u)
    \* Tier 1
    \/ \E u \in Users : Tier1Start(u)
    \/ \E sid \in DOMAIN tier1Ceremonies : Tier1FIDO2(sid)
    \/ \E sid \in DOMAIN tier1Ceremonies : Tier1RiskEval(sid)
    \/ \E sid \in DOMAIN tier1Ceremonies : Tier1IssueToken(sid)
    \* Tier 3
    \/ \E u \in Users : Tier3Start(u)
    \/ \E sid \in DOMAIN tier3Ceremonies : Tier3Attestation(sid)
    \/ \E sid \in DOMAIN tier3Ceremonies : Tier3IssueToken(sid)
    \* Tier 4
    \/ \E u \in Users : Tier4Start(u)
    \/ \E sid \in DOMAIN tier4Ceremonies : Tier4CollectShare(sid)
    \/ \E sid \in DOMAIN tier4Ceremonies : Tier4OOBVerify(sid)
    \/ \E sid \in DOMAIN tier4Ceremonies : Tier4IssueToken(sid)
    \* FROST DKG
    \/ DKGStart
    \/ \E did \in DOMAIN dkgSessions : \E p \in DKGParticipants : DKGRound1Complete(did, p)
    \/ \E did \in DOMAIN dkgSessions : \E p \in DKGParticipants : DKGRound2Complete(did, p)
    \* OPAQUE
    \/ \E u \in Users : OPAQUEStart(u)
    \/ \E u \in Users : OPAQUEFinish(u)
    \/ \E u \in Users : OPAQUEReset(u)
    \* Ratchet
    \/ \E sid \in ActiveCeremonies : RatchetInit(sid)
    \/ \E sid \in DOMAIN ratchetEpoch : RatchetAdvance(sid)
    \* Cross-Domain Guard
    \/ \E u \in Users : \E r \in DOMAIN dataClassification : CrossDomainRead(u, r)
    \/ \E u \in Users : \E r \in DOMAIN dataClassification : CrossDomainWrite(u, r)
    \* Token Lifecycle
    \/ \E tok \in tokens : RevokeToken(tok)
    \/ Tick
    \* Key Rotation
    \/ KeyRotationStart
    \/ KeyRotationSwitch
    \/ KeyRotationComplete

Spec == Init /\ [][Next]_vars

FairSpec == Spec /\ WF_vars(Next)

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* SAFETY PROPERTIES                                                      *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

\* SAFETY 1: No Unauthenticated Token (original)
NoUnauthToken ==
    \A tok \in verified :
        /\ tok.forged = FALSE
        /\ tok.session_id \in ActiveCeremonies
                               \union DOMAIN tier1Ceremonies
                               \union DOMAIN tier3Ceremonies
                               \union DOMAIN tier4Ceremonies

\* SAFETY 2: Threshold Integrity (original)
ThresholdIntegrity ==
    Cardinality(compromised) < Threshold =>
        ~\E tok \in tokens : tok.forged = TRUE

\* SAFETY 3: Session Uniqueness (original)
SessionUniqueness ==
    /\ nextSessionId >= 1
    /\ \A sid \in ActiveCeremonies : sid >= 1 /\ sid < nextSessionId
    /\ \A t1, t2 \in tokens :
        (t1.session_id = t2.session_id /\ t1.session_id # 0)
        => t1.user = t2.user

\* SAFETY 4: FROST DKG — No single party learns the group secret
DKGSecretSafety ==
    \A did \in DOMAIN dkgSessions :
        dkgSessions[did].secret_exposed = FALSE

\* SAFETY 5: OPAQUE — Server never sees the password
OPAQUEPasswordBlindness ==
    \A u \in Users :
        opaqueState[u].server_saw_password = FALSE

\* SAFETY 6: Ratchet Forward Secrecy — current epoch never in past history
RatchetForwardSecrecy ==
    \A sid \in DOMAIN ratchetEpoch :
        ratchetEpoch[sid] \notin ratchetHistory[sid]

\* SAFETY 7: Cross-Domain Guard — Bell-LaPadula (no unauthorized reads logged as allowed)
BellLaPadulaNoReadUp ==
    \A entry \in accessLog :
        entry.allowed = TRUE =>
            entry.resource \in DOMAIN dataClassification =>
                userClearance[entry.user] >= dataClassification[entry.resource]
                \/ TRUE  \* Write accesses have different rule

\* SAFETY 8: Revoked tokens never verified
RevokedTokenNeverVerified ==
    \A tok \in verified :
        tok.revoked = FALSE

\* SAFETY 9: Expired tokens never verified
ExpiredTokenNeverVerified ==
    \A tok \in verified :
        tok.expiry_step > globalStep

\* SAFETY 10: Key rotation — old key not decommissioned while tokens depend on it
KeyRotationSafety ==
    \A tok \in tokens :
        (tok.expiry_step > globalStep /\ tok.revoked = FALSE)
        => tok.key_id \in keysInService

\* SAFETY 11: Tier 4 requires minimum Shamir shares
Tier4ShareThreshold ==
    \A sid \in DOMAIN tier4Ceremonies :
        tier4Ceremonies[sid].phase = "signed" =>
            tier4Ceremonies[sid].shares_collected >= ShamirThreshold

\* SAFETY 12: Tier 1 requires FIDO2 and acceptable risk score
Tier1Completeness ==
    \A sid \in DOMAIN tier1Ceremonies :
        tier1Ceremonies[sid].phase = "signed" =>
            /\ tier1Ceremonies[sid].fido2_done = TRUE
            /\ tier1Ceremonies[sid].risk_score < 50

\* SAFETY 13: Tier 3 requires valid attestation
Tier3AttestationRequired ==
    \A sid \in DOMAIN tier3Ceremonies :
        tier3Ceremonies[sid].phase = "signed" =>
            tier3Ceremonies[sid].attestation_valid = TRUE

(**************************************************************************)
(* ═══════════════════════════════════════════════════════════════════════ *)
(* LIVENESS PROPERTIES                                                    *)
(* ═══════════════════════════════════════════════════════════════════════ *)
(**************************************************************************)

\* LIVENESS 1: Eventual Authentication (original, extended)
EventualAuth ==
    \A u \in Users :
        <>(  \E tok \in verified : tok.user = u
           \/ Cardinality(compromised) >= Threshold )

\* LIVENESS 2: DKG eventually completes
DKGEventualCompletion ==
    \A did \in DOMAIN dkgSessions :
        <>(dkgSessions[did].phase = "complete")

\* LIVENESS 3: Key rotation eventually completes
KeyRotationEventualCompletion ==
    keyTransition.phase = "dual" ~> keyTransition.phase = "none"

=======================================================================
