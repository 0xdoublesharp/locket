----------------------- MODULE AgentUnlockGrantLifecycle -----------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Projects, Nonces, Clients, MaxChallenges, Horizon, Freshness, TTLs

Profiles == {"normal", "dangerous"}
Actions == {"resolve", "prepare"}
Time == 0..Horizon
Deadlines == 0..(Horizon + 1)
SecretCounts == 0..1

VARIABLES now, keys, sessionBlocked, grants, ideSessions,
          challenges, minted, replay, redeemed, badAccess, badGrant, badAuth

vars == <<now, keys, sessionBlocked, grants, ideSessions,
          challenges, minted, replay, redeemed, badAccess, badGrant, badAuth>>

Init ==
    /\ now = 0
    /\ keys = [p \in Projects |-> 0]
    /\ sessionBlocked = FALSE
    /\ grants = {}
    /\ ideSessions = {}
    /\ challenges = {}
    /\ minted = {}
    /\ replay = {}
    /\ redeemed = [n \in Nonces |-> 0]
    /\ badAccess = FALSE
    /\ badGrant = FALSE
    /\ badAuth = FALSE

Deadline(ttl) == IF now + ttl <= Horizon THEN now + ttl ELSE Horizon + 1
KeyLive(p) == keys[p] > now

Symmetry ==
    {[id \in Projects \cup Nonces \cup Clients |->
         IF id \in Projects THEN projects[id]
         ELSE IF id \in Nonces THEN nonces[id]
         ELSE clients[id]] :
       projects \in Permutations(Projects), nonces \in Permutations(Nonces),
       clients \in Permutations(Clients)}
ToOtherProjects(entries, p) == {e \in entries : e.project # p}

Unlock(S, ttl) ==
    /\ ~sessionBlocked
    /\ S # {}
    /\ keys' = [p \in Projects |-> IF p \in S THEN Deadline(ttl) ELSE keys[p]]
    /\ UNCHANGED <<now, sessionBlocked, grants, ideSessions, challenges,
                   minted, replay, redeemed, badAccess, badGrant, badAuth>>

UnlockBatch(S, ttl) ==
    /\ Cardinality(S) >= 2
    /\ Unlock(S, ttl)

LockProject(p) ==
    /\ keys' = [keys EXCEPT ![p] = 0]
    /\ grants' = ToOtherProjects(grants, p)
    /\ ideSessions' = ToOtherProjects(ideSessions, p)
    /\ UNCHANGED <<now, sessionBlocked, challenges, minted, replay,
                   redeemed, badAccess, badGrant, badAuth>>

SessionLockOrSleep ==
    /\ sessionBlocked' = TRUE
    /\ keys' = [p \in Projects |-> 0]
    /\ grants' = {}
    /\ ideSessions' = {}
    /\ UNCHANGED <<now, challenges, minted, replay, redeemed,
                   badAccess, badGrant, badAuth>>

Resume ==
    /\ sessionBlocked
    /\ sessionBlocked' = FALSE
    /\ UNCHANGED <<now, keys, grants, ideSessions, challenges, minted,
                   replay, redeemed, badAccess, badGrant, badAuth>>

Tick ==
    /\ now < Horizon
    /\ now' = now + 1
    /\ keys' = [p \in Projects |-> IF keys[p] > now' THEN keys[p] ELSE 0]
    /\ grants' = {g \in grants : keys'[g.project] # 0}
    /\ ideSessions' = {s \in ideSessions : keys'[s.project] # 0}
    /\ UNCHANGED <<sessionBlocked, challenges, minted, replay, redeemed,
                   badAccess, badGrant, badAuth>>

IssueGrant(p, profile, action, ttl, confirmed) ==
    /\ KeyLive(p)
    /\ ~sessionBlocked
    /\ profile # "dangerous" \/ confirmed
    /\ grants' = {[project |-> p, profile |-> profile, action |-> action,
                    deadline |-> Deadline(ttl), confirmed |-> (profile = "dangerous" /\ confirmed)]}
    /\ UNCHANGED <<now, keys, sessionBlocked, ideSessions, challenges,
                   minted, replay, redeemed, badAccess, badGrant, badAuth>>

\* Resolve may use an existing PrepareExec grant within its execution context.
AllowedGrantActions(request) ==
    IF request = "resolve" THEN Actions ELSE {"prepare"}

GrantAllows(g, p, profile, request, bindingMatches) ==
    /\ KeyLive(p)
    /\ now < g.deadline
    /\ g.project = p
    /\ g.profile = profile
    /\ g.action \in AllowedGrantActions(request)
    /\ bindingMatches

UseGrant(p, profile, request, bindingMatches) ==
    /\ badGrant' = badGrant \/
         (\E g \in grants :
            /\ GrantAllows(g, p, profile, request, bindingMatches)
            /\ ~(/\ g.project = p /\ g.profile = profile /\ now < g.deadline
                 /\ (g.action = request \/ (request = "resolve" /\ g.action = "prepare"))
                 /\ bindingMatches /\ (profile = "normal" \/ g.confirmed)))
    /\ badAccess' = badAccess \/
         (~KeyLive(p) /\ (\E g \in grants : GrantAllows(g, p, profile, request, bindingMatches)))
    /\ UNCHANGED <<now, keys, sessionBlocked, grants, ideSessions, challenges,
                   minted, replay, redeemed, badAuth>>

RevokeGrant ==
    /\ grants' = {}
    /\ UNCHANGED <<now, keys, sessionBlocked, ideSessions, challenges, minted,
                   replay, redeemed, badAccess, badGrant, badAuth>>

RegisterIdeSession(p, profile, count, ttl) ==
    /\ KeyLive(p)
    /\ ~sessionBlocked
    /\ ideSessions' = {[project |-> p, profile |-> profile, secretCount |-> count,
                         deadline |-> Deadline(ttl)]}
    /\ UNCHANGED <<now, keys, sessionBlocked, grants, challenges,
                   minted, replay, redeemed, badAccess, badGrant, badAuth>>

IdeAllows(s, p, profile) ==
    /\ KeyLive(p)
    /\ s.project = p
    /\ s.profile = profile
    /\ s.secretCount > 0
    /\ now < s.deadline

UseIdeSession(p, profile) ==
    /\ badAccess' = badAccess \/
         (~KeyLive(p) /\ (\E s \in ideSessions : IdeAllows(s, p, profile)))
    /\ UNCHANGED <<now, keys, sessionBlocked, grants, ideSessions, challenges,
                   minted, replay, redeemed, badGrant, badAuth>>

Fresh(issuedAt) == now - issuedAt <= Freshness
FreshChallenges == {c \in challenges : Fresh(c.issuedAt)}

IssueChallenge(nonce, client) ==
    /\ nonce \notin minted
    /\ LET retained == FreshChallenges IN
       IF Cardinality(retained) < MaxChallenges
       THEN /\ challenges' = retained \cup {[nonce |-> nonce, client |-> client, issuedAt |-> now]}
            /\ minted' = minted \cup {nonce}
       ELSE /\ challenges' = retained
            /\ minted' = minted
    /\ UNCHANGED <<now, keys, sessionBlocked, grants, ideSessions, replay,
                   redeemed, badAccess, badGrant, badAuth>>

\* A matched challenge ID is consumed even if later validation fails.
\* Client policy and request timestamp have passed the pre-lookup checks.
\* signatureOK abstracts the signature check after taking the challenge.
AuthWithChallenge(p, client, nonce, signatureOK) ==
    /\ LET offered == {c \in challenges : c.nonce = nonce}
           accepted == KeyLive(p) /\ signatureOK /\ nonce \notin replay /\
                       (\E c \in offered : c.client = client /\ Fresh(c.issuedAt))
       IN /\ challenges' = challenges \ offered
          /\ replay' = IF accepted THEN replay \cup {nonce} ELSE replay
          /\ redeemed' = IF accepted THEN [redeemed EXCEPT ![nonce] = @ + 1] ELSE redeemed
          /\ badAuth' = badAuth \/
                (accepted /\ (redeemed[nonce] # 0 \/
                   ~(\E c \in offered : c.client = client /\
                                 c.issuedAt <= now /\ now <= c.issuedAt + Freshness)))
    /\ UNCHANGED <<now, keys, sessionBlocked, grants, ideSessions,
                   minted, badAccess, badGrant>>

Next ==
    \/ SessionLockOrSleep \/ Resume \/ Tick \/ RevokeGrant
    \/ \E S \in SUBSET Projects, ttl \in TTLs : UnlockBatch(S, ttl)
    \/ \E p \in Projects :
         \/ LockProject(p)
         \/ \E ttl \in TTLs :
              \/ Unlock({p}, ttl)
              \/ \E profile \in Profiles :
                   \/ \E action \in Actions, confirmed \in BOOLEAN :
                        IssueGrant(p, profile, action, ttl, confirmed)
                   \/ \E count \in SecretCounts : RegisterIdeSession(p, profile, count, ttl)
         \/ \E profile \in Profiles :
              \/ \E action \in Actions, bindingMatches \in BOOLEAN :
                   UseGrant(p, profile, action, bindingMatches)
              \/ UseIdeSession(p, profile)
         \/ \E client \in Clients, nonce \in Nonces, signatureOK \in BOOLEAN :
              AuthWithChallenge(p, client, nonce, signatureOK)
    \/ \E nonce \in Nonces, client \in Clients : IssueChallenge(nonce, client)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ now \in Time
    /\ keys \in [Projects -> Deadlines]
    /\ sessionBlocked \in BOOLEAN
    /\ grants \subseteq [project : Projects, profile : Profiles, action : Actions,
                          deadline : Deadlines, confirmed : BOOLEAN]
    /\ Cardinality(grants) <= 1
    /\ ideSessions \subseteq [project : Projects, profile : Profiles,
                               secretCount : SecretCounts, deadline : Deadlines]
    /\ Cardinality(ideSessions) <= 1
    /\ challenges \subseteq [nonce : Nonces, client : Clients, issuedAt : 0..now]
    /\ minted \subseteq Nonces
    /\ replay \subseteq minted
    /\ redeemed \in [Nonces -> 0..2]
    /\ badAccess \in BOOLEAN
    /\ badGrant \in BOOLEAN
    /\ badAuth \in BOOLEAN

LockedProjectFailClosed ==
    /\ ~badAccess
    /\ \A p \in Projects :
         /\ sessionBlocked => keys[p] = 0
         /\ keys[p] = 0 \/ keys[p] > now
         /\ keys[p] = 0 =>
              /\ \A g \in grants : g.project # p
              /\ \A s \in ideSessions : s.project # p

GrantScopeAndDangerousGating ==
    /\ ~badGrant
    /\ \A g \in grants : g.profile = "dangerous" => g.confirmed

AutomationReplayFreedom ==
    /\ ~badAuth
    /\ Cardinality(challenges) <= MaxChallenges
    /\ \A c \in challenges : c.nonce \in minted \ replay
    /\ \A n \in Nonces : redeemed[n] = (IF n \in replay THEN 1 ELSE 0)

=============================================================================
