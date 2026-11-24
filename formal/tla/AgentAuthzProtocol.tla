---------------------------- MODULE AgentAuthzProtocol ----------------------------
EXTENDS Integers

CONSTANT NoValue
Profiles == {"ordinary", "dangerous"}
Policies == {"build", "deploy"}
GrantActions == {"Reveal", "ResolveReference", "PrepareExec", "Export"}
ResolveActions == {"ResolveReference", "PrepareExec"}
Methods == {"Unlock", "RequestGrant", "PrepareExec"}
LockEvents == {"Lock", "IdleExpiry", "SessionLock"}

(* All peers have the daemon UID. The local peer can reconnect after taking
   over the human's PID, but its kernel start-time token is different. *)
Human == [principal |-> "human", pid |-> 1, started |-> 0]
Automation == [principal |-> "automation", pid |-> 2, started |-> 0]
Local == [principal |-> "local", pid |-> 3, started |-> 0]
Recycled == [principal |-> "local", pid |-> 1, started |-> 1]
Peers == {Human, Automation, Local, Recycled}
Process(peer) == [pid |-> peer.pid, started |-> peer.started]

Requests == [method : Methods, peer : Peers, action : GrantActions \cup {NoValue},
             profile : Profiles \cup {NoValue}, policy : Policies \cup {NoValue},
             confirmed : BOOLEAN]
UnlockRequest(peer) ==
    [method |-> "Unlock", peer |-> peer, action |-> NoValue, profile |-> NoValue,
     policy |-> NoValue, confirmed |-> FALSE]
GrantRequest(method, peer, action, profile, policy, confirm) ==
    [method |-> method, peer |-> peer, action |-> action, profile |-> profile,
     policy |-> policy, confirmed |-> confirm]

VARIABLES unlocked, blocked, recycled, pending, invalidated, grants, result
vars == <<unlocked, blocked, recycled, pending, invalidated, grants, result>>

Outcomes == {NoValue, "Unlocked", "Granted", "Plaintext", "Denied", "StaleVerification",
              "AuditIntegrityFailed"}
Observation(outcome, request, peer, profile, policy, authenticated) ==
    [outcome |-> outcome, request |-> request, peer |-> peer,
     profile |-> profile, policy |-> policy, authenticated |-> authenticated]
Report(outcome, request) == Observation(outcome, request, NoValue, NoValue, NoValue, FALSE)
NoResult == Report(NoValue, NoValue)

Init ==
    /\ unlocked = FALSE
    /\ blocked = FALSE
    /\ recycled = FALSE
    /\ pending = NoValue
    /\ invalidated = FALSE
    /\ grants = {}
    /\ result = NoResult

LivePeers == IF recycled THEN {Automation, Local, Recycled} ELSE {Human, Automation, Local}

CanStart == /\ pending = NoValue
            /\ ~blocked

StartUnlock(peer) ==
    /\ CanStart
    /\ peer # Automation  \* Signed automation cannot invoke Unlock.
    /\ pending' = UnlockRequest(peer)
    /\ invalidated' = FALSE
    /\ result' = NoResult
    /\ UNCHANGED <<unlocked, blocked, recycled, grants>>

AllowedScope(method, action, policy) ==
    CASE method = "PrepareExec" -> action = "PrepareExec" /\ policy \in Policies
      [] action = "PrepareExec" -> policy \in Policies
      [] action = "ResolveReference" -> policy \in Policies \cup {NoValue}
      [] OTHER -> policy = NoValue

StartGrant(method, peer, action, profile, policy, confirm) ==
    /\ CanStart
    /\ unlocked
    /\ grants = {}  \* Explore one representative live grant for this project.
    /\ AllowedScope(method, action, policy)
    /\ pending' = GrantRequest(method, peer, action, profile, policy, confirm)
    /\ invalidated' = FALSE
    /\ result' = NoResult
    /\ UNCHANGED <<unlocked, blocked, recycled, grants>>

ConfirmProfile(request) == request.profile # "dangerous" \/ request.confirmed
SignedScope(request) == request.action \in ResolveActions /\ request.policy = "build"

(* Verification and audit outcomes are separate. A failed AGENT_GRANT append
   rolls back the insertion under the grant-table lock before publication. *)
Finish(verified, signatureOK, auditOK) ==
    /\ pending # NoValue
    /\ LET request == pending
           humanOK == request.peer = Human /\ verified
           automationOK == request.peer = Automation /\ signatureOK /\ SignedScope(request)
           outcome ==
               CASE invalidated \/ blocked -> "StaleVerification"
                 [] request.peer \notin LivePeers -> "Denied"
                 [] request.method = "Unlock" -> IF humanOK THEN "Unlocked" ELSE "Denied"
                 [] ~unlocked \/ ~ConfirmProfile(request) \/ ~(humanOK \/ automationOK) -> "Denied"
                 [] humanOK /\ ~auditOK -> "AuditIntegrityFailed"
                 [] OTHER -> "Granted"
       IN /\ unlocked' = (unlocked \/ outcome = "Unlocked")
          /\ grants' = IF outcome = "Granted" THEN grants \cup {request} ELSE grants
          /\ result' = Observation(outcome, request, NoValue, NoValue, NoValue,
                                   IF outcome \in {"Unlocked", "Granted"}
                                   THEN IF request.peer = Automation THEN signatureOK ELSE verified
                                   ELSE FALSE)
    /\ pending' = NoValue
    /\ UNCHANGED <<blocked, recycled, invalidated>>

ClearAuthorization(event) ==
    /\ IF event = "IdleExpiry" THEN unlocked ELSE TRUE
    /\ unlocked' = FALSE
    /\ grants' = {}
    /\ blocked' = (blocked \/ event = "SessionLock")
    /\ invalidated' = (pending # NoValue)
    /\ result' = NoResult
    /\ UNCHANGED <<pending, recycled>>

Resume ==
    /\ blocked
    /\ blocked' = FALSE
    /\ result' = NoResult
    /\ UNCHANGED <<unlocked, recycled, pending, invalidated, grants>>

ReconnectWithRecycledPid ==
    /\ ~recycled
    /\ recycled' = TRUE
    /\ result' = NoResult
    /\ UNCHANGED <<unlocked, blocked, pending, invalidated, grants>>

RevokeGrant ==
    /\ grants # {}
    /\ grants' = {}
    /\ result' = NoResult
    /\ UNCHANGED <<unlocked, blocked, recycled, pending, invalidated>>

ResolveReference(grant, peer, profile, policy) ==
    /\ LET accepted == unlocked /\ ~blocked
                       /\ grant.action \in ResolveActions /\ grant.profile = profile
                       /\ (grant.policy = NoValue \/ grant.policy = policy)
                       /\ Process(grant.peer) = Process(peer)
       IN result' = IF accepted THEN Observation("Plaintext", grant, peer, profile, policy, FALSE)
                    ELSE NoResult
    /\ UNCHANGED <<unlocked, blocked, recycled, pending, invalidated, grants>>

Next ==
    \/ \E peer \in LivePeers : StartUnlock(peer)
    \/ \E peer \in LivePeers, method \in Methods \ {"Unlock"}, action \in GrantActions,
          profile \in Profiles, policy \in Policies \cup {NoValue}, confirm \in BOOLEAN :
           StartGrant(method, peer, action, profile, policy, confirm)
    \/ \E verified, signatureOK, auditOK \in BOOLEAN : Finish(verified, signatureOK, auditOK)
    \/ \E event \in LockEvents : ClearAuthorization(event)
    \/ Resume
    \/ ReconnectWithRecycledPid
    \/ RevokeGrant
    \/ \E grant \in grants, peer \in LivePeers, profile \in Profiles, policy \in Policies :
           ResolveReference(grant, peer, profile, policy)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ unlocked \in BOOLEAN /\ blocked \in BOOLEAN /\ recycled \in BOOLEAN
    /\ pending \in Requests \cup {NoValue} /\ invalidated \in BOOLEAN
    /\ grants \in SUBSET Requests
    /\ result \in [outcome : Outcomes, request : Requests \cup {NoValue},
                   peer : Peers \cup {NoValue}, profile : Profiles \cup {NoValue},
                   policy : Policies \cup {NoValue}, authenticated : BOOLEAN]

VerifiedPrincipalOnly ==
    /\ \A g \in grants : g.peer = Human \/ (g.peer = Automation /\ SignedScope(g))
    /\ result.outcome = "Plaintext" => result.peer.principal # "local"
    /\ result.outcome \in {"Unlocked", "Granted"} => result.authenticated
    /\ result.outcome = "Unlocked" => result.request.peer = Human

DangerousConfirmation ==
    /\ \A g \in grants : ConfirmProfile(g)
    /\ (result.outcome = "Plaintext" /\ result.profile = "dangerous") => result.request.confirmed

PolicyBinding ==
    /\ \A g \in grants : g.action = "PrepareExec" => g.policy \in Policies
    /\ result.outcome = "Plaintext" =>
           (result.request.policy = NoValue \/ result.request.policy = result.policy)

LockInvalidatesVerification ==
    /\ (~unlocked \/ blocked) => grants = {}
    /\ invalidated => ~unlocked /\ grants = {}
    /\ result.outcome = "StaleVerification" => ~unlocked /\ grants = {}

AuditRollback == result.outcome = "AuditIntegrityFailed" => result.request \notin grants

RecycledPidDenied ==
    result.outcome = "Plaintext" => Process(result.peer) = Process(result.request.peer)
=============================================================================
