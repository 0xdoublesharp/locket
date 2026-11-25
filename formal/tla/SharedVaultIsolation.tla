-------------------------- MODULE SharedVaultIsolation --------------------------
Projects == {"ProjA", "ProjB"}
Shared == "Shared"
Vaults == Projects \cup {Shared}
CopyKey == "TOKEN"
SharedKeys == {CopyKey, "OTHER"}
LocalRefs(p) == {<<p, "TOKEN">>}
SharedRefs(keys) == {<<Shared, key>> : key \in keys}
Policies == SUBSET SharedKeys
NoGrant == [project |-> "none", declared |-> {}]
NoCopy == [pending |-> FALSE, overwrite |-> FALSE, confirmed |-> FALSE]
Absent == "absent"
Seed == "seed"

VARIABLES unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
          copies, badScope, badLock, badCopy, badDocker

vars == <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
          copies, badScope, badLock, badCopy, badDocker>>

Init ==
    /\ unlocked = {}
    /\ sessionLocked = FALSE
    /\ grant = NoGrant
    /\ sharedValue \in {Absent, Seed}
    /\ dangerousTarget \in BOOLEAN
    /\ copies = [p \in Projects |-> NoCopy]
    /\ badScope = FALSE
    /\ badLock = FALSE
    /\ badCopy = FALSE
    /\ badDocker = FALSE

Unlock(vault) ==
    /\ ~sessionLocked
    /\ unlocked' = unlocked \cup {vault}
    /\ UNCHANGED <<sessionLocked, grant, sharedValue, dangerousTarget,
                   copies, badScope, badLock, badCopy, badDocker>>

Lock(vault) ==
    /\ unlocked' = unlocked \ {vault}
    /\ grant' = IF grant = NoGrant THEN NoGrant
                ELSE IF grant.project = vault THEN NoGrant ELSE grant
    /\ UNCHANGED <<sessionLocked, sharedValue, dangerousTarget,
                   copies, badScope, badLock, badCopy, badDocker>>

NativeLock ==
    /\ sessionLocked' = TRUE
    /\ unlocked' = {}
    /\ grant' = NoGrant
    /\ UNCHANGED <<sharedValue, dangerousTarget, copies,
                   badScope, badLock, badCopy, badDocker>>

Resume ==
    /\ sessionLocked
    /\ sessionLocked' = FALSE
    /\ UNCHANGED <<unlocked, grant, sharedValue, dangerousTarget,
                   copies, badScope, badLock, badCopy, badDocker>>

PrepareExec(project, policy) ==
    /\ project \in unlocked
    /\ grant' = [project |-> project, declared |-> policy]
    /\ UNCHANGED <<unlocked, sessionLocked, sharedValue, dangerousTarget,
                   copies, badScope, badLock, badCopy, badDocker>>

AvailableShared ==
    IF sharedValue = Absent THEN SharedKeys \ {CopyKey} ELSE SharedKeys

CanRun(project, policy) ==
    /\ project \in unlocked
    /\ policy = {} \/ Shared \in unlocked
    /\ policy \subseteq AvailableShared

ResolveGrant(ref) ==
    /\ grant # NoGrant
    /\ LET resolved ==
            IF CanRun(grant.project, grant.declared)
               /\ ref \in LocalRefs(grant.project) \cup SharedRefs(grant.declared)
            THEN {ref} ELSE {}
       IN /\ badScope' = (badScope \/
                 (\E secret \in resolved :
                     IF secret[1] = Shared THEN secret[2] \notin grant.declared
                     ELSE secret[1] # grant.project))
          /\ badLock' = (badLock \/
                 (resolved # {} /\
                    (sessionLocked \/ grant.project \notin unlocked \/
                     (grant.declared # {} /\ Shared \notin unlocked))))
    /\ UNCHANGED <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
                   copies, badCopy, badDocker>>

Run(project, policy) ==
    /\ LET delivered ==
            IF CanRun(project, policy)
            THEN LocalRefs(project) \cup SharedRefs(policy)
            ELSE {}
       IN /\ badScope' = (badScope \/
                 (\E secret \in delivered :
                     IF secret[1] = Shared THEN secret[2] \notin policy
                     ELSE secret[1] # project))
          /\ badLock' = (badLock \/
                 (delivered # {} /\
                    (sessionLocked \/ project \notin unlocked \/
                     (policy # {} /\ Shared \notin unlocked))))
    /\ UNCHANGED <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
                   copies, badCopy, badDocker>>

ExecShared(key) ==
    /\ LET delivered ==
            IF Shared \in unlocked /\ key \in AvailableShared
            THEN SharedRefs({key}) ELSE {}
       IN /\ badScope' = (badScope \/
                 (\E secret \in delivered : secret[1] # Shared))
          /\ badLock' = (badLock \/
                 (delivered # {} /\ (sessionLocked \/ Shared \notin unlocked)))
    /\ UNCHANGED <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
                   copies, badCopy, badDocker>>

BeginCopy(project, overwrite, confirmed) ==
    /\ copies[project] = NoCopy
    /\ copies' = [copies EXCEPT
           ![project] = [pending |-> TRUE, overwrite |-> overwrite, confirmed |-> confirmed]]
    /\ UNCHANGED <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
                   badScope, badLock, badCopy, badDocker>>

\* Requests overlap before the transaction. The destination is read inside the
\* transaction so a second non-overwriting copy sees the first commit.
CopySecretToShared(project) ==
    /\ copies[project] # NoCopy
    /\ LET request == copies[project]
           accepted ==
               /\ project \in unlocked /\ Shared \in unlocked
               /\ sharedValue = Absent \/ request.overwrite
               /\ ~dangerousTarget \/ request.confirmed
           destination == IF accepted THEN project ELSE sharedValue
       IN /\ sharedValue' = destination
          /\ badCopy' = (badCopy \/
                 ((accepted \/ destination # sharedValue) /\
                    (sessionLocked \/ ~({project, Shared} \subseteq unlocked) \/
                     (sharedValue # Absent /\ ~request.overwrite) \/
                     (dangerousTarget /\ ~request.confirmed))))
    /\ copies' = [copies EXCEPT ![project] = NoCopy]
    /\ UNCHANGED <<unlocked, sessionLocked, grant, dangerousTarget,
                   badScope, badLock, badDocker>>

DockerOrCompose(project, policy) ==
    /\ LET permitted == policy = {} /\ project \in unlocked
       IN badDocker' = (badDocker \/ (permitted /\ policy # {}))
    /\ UNCHANGED <<unlocked, sessionLocked, grant, sharedValue, dangerousTarget,
                   copies, badScope, badLock, badCopy>>

Next ==
    \/ \E vault \in Vaults : Unlock(vault) \/ Lock(vault)
    \/ NativeLock \/ Resume
    \/ \E p \in Projects, policy \in Policies :
            PrepareExec(p, policy) \/ Run(p, policy) \/ DockerOrCompose(p, policy)
    \/ \E ref \in (UNION {LocalRefs(p) : p \in Projects}) \cup SharedRefs(SharedKeys) :
            ResolveGrant(ref)
    \/ \E key \in SharedKeys : ExecShared(key)
    \/ \E p \in Projects :
            \/ \E overwrite, confirmed \in BOOLEAN : BeginCopy(p, overwrite, confirmed)
            \/ CopySecretToShared(p)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ unlocked \subseteq Vaults
    /\ sessionLocked \in BOOLEAN
    /\ grant \in {NoGrant} \cup [project : Projects, declared : Policies]
    /\ sharedValue \in {Absent, Seed} \cup Projects
    /\ dangerousTarget \in BOOLEAN
    /\ copies \in [Projects -> {NoCopy} \cup [pending : {TRUE}, overwrite : BOOLEAN, confirmed : BOOLEAN]]
    /\ {badScope, badLock, badCopy, badDocker} \subseteq BOOLEAN

NoCrossProjectBleed == ~badScope
DualVaultFailClosed == ~badLock /\ (sessionLocked => unlocked = {} /\ grant = NoGrant)
CopyToSharedAtomicityAndSafety == ~badCopy
DockerRejectsSharedSecrets == ~badDocker

=============================================================================
