--------------------------- MODULE milnet ---------------------------
(**************************************************************************)
(* TLA+ Formal Model for MILNET SSO Authentication Ceremony (Tier 2)     *)
(*                                                                        *)
(* Models the core flow:                                                  *)
(*   Client -> Gateway -> Orchestrator -> OPAQUE -> TSS -> Verifier       *)
(*                                                                        *)
(* Verifies safety (no unauth tokens, threshold integrity, session        *)
(* uniqueness) and liveness (legitimate users eventually authenticate).   *)
(**************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Users,          \* Set of user identifiers
    TSSNodes,       \* Set of TSS node identifiers
    Threshold,      \* Minimum honest nodes required for signing (3)
    MaxCeremonies   \* Bound on total ceremonies for model checking

VARIABLES
    ceremonies,     \* Function from session_id -> [user, phase, receipts]
    tokens,         \* Set of issued tokens: [user, session_id, forged]
    verified,       \* Set of verified tokens
    compromised,    \* Set of compromised TSS nodes
    nextSessionId,  \* Monotonic counter for unique session IDs
    nonceCtr        \* Function from TSSNode -> counter (monotonic)

vars == <<ceremonies, tokens, verified, compromised, nextSessionId, nonceCtr>>

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

(**************************************************************************)
(* Initial state                                                          *)
(**************************************************************************)
Init ==
    /\ ceremonies = <<>>      \* Empty function (no active ceremonies)
    /\ tokens = {}
    /\ verified = {}
    /\ compromised = {}
    /\ nextSessionId = 1
    /\ nonceCtr = [n \in TSSNodes |-> 0]

(**************************************************************************)
(* Helpers                                                                *)
(**************************************************************************)
ActiveCeremonies == DOMAIN ceremonies

HonestNodes == TSSNodes \ compromised

NumCompromised == Cardinality(compromised)

TotalCeremonies == Cardinality(ActiveCeremonies)

(**************************************************************************)
(* Actions                                                                *)
(**************************************************************************)

\* Client initiates authentication via Gateway
StartCeremony(user) ==
    /\ TotalCeremonies < MaxCeremonies
    /\ LET sid == nextSessionId
       IN /\ ceremonies' = [sid |-> [user |-> user,
                                      phase |-> "started",
                                      receipts |-> 0]]
                            @@ ceremonies
          /\ nextSessionId' = nextSessionId + 1
    /\ UNCHANGED <<tokens, verified, compromised, nonceCtr>>

\* OPAQUE completes password authentication, issues receipt
OpaqueAuth(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "started"
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "opaque_done",
                                        ![sid].receipts = 1]
    /\ UNCHANGED <<tokens, verified, compromised, nextSessionId, nonceCtr>>

\* Orchestrator collects and bundles receipts
CollectReceipts(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "opaque_done"
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "receipts_collected"]
    /\ UNCHANGED <<tokens, verified, compromised, nextSessionId, nonceCtr>>

\* TSS validates receipt chain and threshold-signs token (3-of-5)
\* Only succeeds if enough honest nodes remain
ThresholdSign(sid) ==
    /\ sid \in ActiveCeremonies
    /\ ceremonies[sid].phase = "receipts_collected"
    /\ Cardinality(HonestNodes) >= Threshold
    /\ ceremonies' = [ceremonies EXCEPT ![sid].phase = "signed"]
    /\ LET user == ceremonies[sid].user
           tok  == [user |-> user, session_id |-> sid, forged |-> FALSE]
       IN tokens' = tokens \union {tok}
    \* Advance nonce counters on participating honest nodes
    /\ nonceCtr' = [n \in TSSNodes |->
                        IF n \in HonestNodes
                        THEN nonceCtr[n] + 1
                        ELSE nonceCtr[n]]
    /\ UNCHANGED <<verified, compromised, nextSessionId>>

\* Verifier checks token signature and validity
VerifyToken(tok) ==
    /\ tok \in tokens
    /\ tok \notin verified
    /\ tok.forged = FALSE   \* Verifier rejects forged tokens
    /\ verified' = verified \union {tok}
    /\ UNCHANGED <<ceremonies, tokens, compromised, nextSessionId, nonceCtr>>

\* Adversary compromises a TSS node
CompromiseNode(node) ==
    /\ node \in TSSNodes
    /\ node \notin compromised
    /\ compromised' = compromised \union {node}
    /\ UNCHANGED <<ceremonies, tokens, verified, nextSessionId, nonceCtr>>

\* Adversary attempts to forge a token without valid ceremony
\* Can only succeed if threshold or more nodes are compromised
ForgeAttempt(user) ==
    /\ user \in Users
    /\ Cardinality(compromised) >= Threshold
    /\ LET tok == [user |-> user, session_id |-> 0, forged |-> TRUE]
       IN tokens' = tokens \union {tok}
    /\ UNCHANGED <<ceremonies, verified, compromised, nextSessionId, nonceCtr>>

(**************************************************************************)
(* Next-state relation                                                    *)
(**************************************************************************)
Next ==
    \/ \E u \in Users : StartCeremony(u)
    \/ \E sid \in ActiveCeremonies : OpaqueAuth(sid)
    \/ \E sid \in ActiveCeremonies : CollectReceipts(sid)
    \/ \E sid \in ActiveCeremonies : ThresholdSign(sid)
    \/ \E tok \in tokens : VerifyToken(tok)
    \/ \E n \in TSSNodes : CompromiseNode(n)
    \/ \E u \in Users : ForgeAttempt(u)

Spec == Init /\ [][Next]_vars

FairSpec == Spec /\ WF_vars(Next)

(**************************************************************************)
(* SAFETY PROPERTY 1: No Unauthenticated Token                           *)
(* Every verified token traces back to a completed (signed) ceremony.     *)
(**************************************************************************)
NoUnauthToken ==
    \A tok \in verified :
        /\ tok.forged = FALSE
        /\ tok.session_id \in ActiveCeremonies
        /\ ceremonies[tok.session_id].phase = "signed"
        /\ ceremonies[tok.session_id].user = tok.user

(**************************************************************************)
(* SAFETY PROPERTY 2: Threshold Integrity                                 *)
(* If fewer than Threshold nodes are compromised, no forged tokens exist. *)
(**************************************************************************)
ThresholdIntegrity ==
    Cardinality(compromised) < Threshold =>
        ~\E tok \in tokens : tok.forged = TRUE

(**************************************************************************)
(* SAFETY PROPERTY 3: Session Uniqueness                                  *)
(* No two ceremonies share a session ID (guaranteed by monotonic counter).*)
(**************************************************************************)
SessionUniqueness ==
    \* Session IDs are unique: each is below the counter and the counter
    \* only increments, so no ID is ever assigned twice.
    /\ nextSessionId >= 1
    /\ \A sid \in ActiveCeremonies : sid >= 1 /\ sid < nextSessionId
    \* No two tokens from different ceremonies share a session_id
    /\ \A t1, t2 \in tokens :
        (t1.session_id = t2.session_id /\ t1.session_id # 0)
        => t1.user = t2.user

(**************************************************************************)
(* LIVENESS PROPERTY: Eventual Authentication                             *)
(* Under fairness, every user eventually has a verified token.            *)
(**************************************************************************)
EventualAuth ==
    \A u \in Users :
        <>(  \E tok \in verified : tok.user = u
           \/ Cardinality(compromised) >= Threshold )

=======================================================================
