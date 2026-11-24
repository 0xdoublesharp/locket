-------------------------- MODULE AutomationClientAuth --------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS ChallengeIds, Nonces, Capacity, Horizon, Freshness, NoValue

Symmetry ==
    {[id \in ChallengeIds \cup Nonces |-> IF id \in ChallengeIds THEN challenges[id] ELSE nonces[id]] :
       challenges \in Permutations(ChallengeIds), nonces \in Permutations(Nonces)}

Times == 0..Horizon
ClientIds == {"registered-key", "other-key"}
Client == "registered-key"
Actions == {"run-policy", "resolve-reference", "scan-known-values"}
Policies == {"build", "deploy"}
AllowedActions == {"run-policy", "resolve-reference"}
AllowedPolicies == {"build"}
Methods == {"PrepareExec", "ResolveReference", "ScanKnownValues"}
PermittedLabels(method) ==
    CASE method = "PrepareExec" -> {"run-policy"}
      [] method = "ResolveReference" -> {"resolve-reference", "run-policy"}
      [] OTHER -> {"scan-known-values"}
Never == -1
Challenge == [id : ChallengeIds, client : ClientIds, nonce : Nonces, issued : Times]
Requests(ids) == [client : ClientIds, id : ids, nonce : Nonces, method : Methods,
                  action : Actions, policy : Policies, timestamp : Times]
Pending == [request : Requests(ChallengeIds), challenge : Challenge, checkedAt : Times, signatureOK : BOOLEAN]
Statuses == {NoValue, "Capacity", "VerificationFailed", "RegistryStorageFailure",
              "Denied", "Replay", "DbFailure", "AuditFailure", "Authenticated"}

VARIABLES clock, registry, challenges, pending, db, observation
vars == <<clock, registry, challenges, pending, db, observation>>

(* The success audit count independently records a second acceptance, even
   when two attempts use the same nonce and the same clock tick. *)
EmptyDb == [used |-> {}, auditCount |-> [n \in Nonces |-> 0], lastUsed |-> Never]
DbState == [used : SUBSET Nonces, auditCount : [Nonces -> 0..2], lastUsed : Times \cup {Never}]
Report(status, snapshot, auth, granted) ==
    [status |-> status, before |-> snapshot, auth |-> auth, granted |-> granted]
Silent == Report(NoValue, NoValue, NoValue, FALSE)
Error(status) == Report(status, NoValue, NoValue, FALSE)

Init ==
    /\ clock = 0
    /\ registry = "absent"
    /\ challenges = {}
    /\ pending = NoValue
    /\ db = EmptyDb
    /\ observation = Silent

RegisterClient(verified, storageOK) ==
    /\ registry = "absent"
    /\ registry' = IF verified /\ storageOK THEN "active" ELSE registry
    /\ observation' = IF ~verified THEN Error("VerificationFailed")
                      ELSE IF ~storageOK THEN Error("RegistryStorageFailure") ELSE Silent
    /\ UNCHANGED <<clock, challenges, pending, db>>

RevokeClient ==
    /\ registry = "active"
    /\ registry' = "revoked"
    /\ observation' = Silent
    /\ UNCHANGED <<clock, challenges, pending, db>>

Fresh(timestamp, at) == timestamp - at <= Freshness /\ at - timestamp <= Freshness

ClientHello(id, client, nonce) ==
    LET live == {c \in challenges : Fresh(c.issued, clock)}
    IN /\ IF Cardinality(live) >= Capacity
          THEN /\ challenges' = live
               /\ observation' = Error("Capacity")
          ELSE /\ id \notin {c.id : c \in live}
               /\ challenges' = live \cup {[id |-> id, client |-> client,
                                            nonce |-> nonce, issued |-> clock]}
               /\ observation' = Silent
       /\ UNCHANGED <<clock, registry, pending, db>>

Allowed(request) ==
    /\ request.action \in PermittedLabels(request.method) \cap AllowedActions
    /\ request.policy \in AllowedPolicies

ChallengeMatches(request, challenge) ==
    /\ request.id = challenge.id
    /\ request.client = challenge.client
    /\ request.nonce = challenge.nonce

(* Abstract Ed25519 verification to the outcome for the challenge and
   canonical request. Initial denials leave the challenge in the pool.
   Once taken, a challenge is burned even on mismatch or failure. *)
StartSignedRequest(request, challenge, signatureOK) ==
    LET prechecked == request.client = Client
                        /\ Allowed(request) /\ Fresh(request.timestamp, clock)
           checked == ChallengeMatches(request, challenge)
                      /\ Fresh(challenge.issued, clock) /\ signatureOK
       IN /\ challenges' = IF prechecked THEN {c \in challenges : c.id # request.id} ELSE challenges
          /\ pending' = IF prechecked /\ checked
                        THEN [request |-> request, challenge |-> challenge, checkedAt |-> clock,
                              signatureOK |-> signatureOK]
                        ELSE NoValue
          /\ observation' = IF pending' = NoValue THEN Error("Denied") ELSE Silent
       /\ UNCHANGED <<clock, registry, db>>

(* Commit-time revocation check is the required linearization point.
   Writes and successful dispatch are observable only on transaction success.
   The nonce table persists for the entire modeled retention horizon. *)
FinishSignedRequest(write) ==
    /\ pending # NoValue
    /\ LET nonce == pending.request.nonce
           status == CASE registry # "active" -> "Denied"
                       [] nonce \in db.used -> "Replay"
                       [] write = "db" -> "DbFailure"
                       [] write = "audit" -> "AuditFailure"
                       [] OTHER -> "Authenticated"
           committed == status = "Authenticated"
       IN /\ db' = IF committed
                   THEN [used |-> db.used \cup {nonce},
                         auditCount |-> [db.auditCount EXCEPT ![nonce] = @ + 1],
                         lastUsed |-> clock]
                   ELSE db
          /\ observation' = Report(status, db, pending,
                                    committed /\ pending.request.method = "PrepareExec")
    /\ pending' = NoValue
    /\ UNCHANGED <<clock, registry, challenges>>

Tick ==
    /\ clock < Horizon
    /\ clock' = clock + 1
    /\ observation' = Silent
    /\ UNCHANGED <<registry, challenges, pending, db>>

Restart ==
    /\ challenges' = {}
    /\ pending' = NoValue
    /\ observation' = Silent
    /\ UNCHANGED <<clock, registry, db>>

Next ==
    \/ \E verified, storageOK \in BOOLEAN : RegisterClient(verified, storageOK)
    \/ RevokeClient
    \/ \E id \in ChallengeIds, client \in ClientIds, nonce \in Nonces : ClientHello(id, client, nonce)
    \/ /\ pending = NoValue /\ registry = "active"
       /\ \E challenge \in challenges :
           \E request \in Requests({challenge.id}), signatureOK \in BOOLEAN :
              StartSignedRequest(request, challenge, signatureOK)
    \/ \E write \in {"ok", "db", "audit"} : FinishSignedRequest(write)
    \/ Tick
    \/ Restart

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ clock \in Times /\ registry \in {"absent", "active", "revoked"}
    /\ challenges \in SUBSET Challenge
    /\ pending \in Pending \cup {NoValue}
    /\ db \in DbState
    /\ observation \in [status : Statuses, before : DbState \cup {NoValue},
                        auth : Pending \cup {NoValue}, granted : BOOLEAN]

BoundedChallenges ==
    /\ Cardinality(challenges) <= Capacity
    /\ \A c1, c2 \in challenges : c1.id = c2.id => c1 = c2

PersistentSingleUse ==
    /\ \A n \in Nonces : db.auditCount[n] <= 1
    /\ db.used = {n \in Nonces : db.auditCount[n] = 1}

AuthorizedAuthentication == observation.status = "Authenticated" =>
    LET auth == observation.auth
        req == auth.request
    IN /\ registry = "active" /\ req.client = Client
       /\ Allowed(req) /\ ChallengeMatches(req, auth.challenge) /\ auth.signatureOK
       /\ Fresh(req.timestamp, auth.checkedAt) /\ Fresh(auth.challenge.issued, auth.checkedAt)

FailureRollsBack == observation.status \in {"Replay", "DbFailure", "AuditFailure"} =>
    /\ db = observation.before
    /\ ~observation.granted
    /\ (observation.status = "Replay") = (observation.auth.request.nonce \in db.used)
=============================================================================
