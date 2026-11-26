---- MODULE SharedSecretLinks ----
EXTENDS Naturals

Projects == {"ProjA", "ProjB"}
Shared == "Shared"
Vaults == Projects \cup {Shared}
None == "none"
NoReview == {<<None, 0>>}
MaxUnlinks == 2
LinkIds == {<<p, generation>> : p \in Projects, generation \in 0..(MaxUnlinks - 1)}
EmptyExport == [project |-> None, links |-> {}, dedupTags |-> {}]

VARIABLES unlocked, sessionLocked, sharedExists, links, dangerous, reviewedLinks,
          unlinkAudits, linkedRead, teamExport
vars == <<unlocked, sessionLocked, sharedExists, links, dangerous, reviewedLinks,
          unlinkAudits, linkedRead, teamExport>>

Init ==
    /\ unlocked = {} /\ sessionLocked = FALSE
    /\ sharedExists = FALSE /\ links = {} /\ dangerous \in SUBSET Vaults
    /\ reviewedLinks = NoReview
    /\ unlinkAudits = [p \in Projects |-> 0]
    /\ linkedRead = None /\ teamExport = EmptyExport

CanUse(v) == ~sessionLocked /\ v \in unlocked
Confirmed(vaults, confirmed) == confirmed \/ (vaults \cap dangerous = {})
ActiveLinkIds == {<<p, unlinkAudits[p]>> : p \in links}
AppendUnlinkAudits(removed) ==
    [p \in Projects |-> unlinkAudits[p] + (IF p \in removed THEN 1 ELSE 0)]

Unlock(v) ==
    /\ ~sessionLocked
    /\ unlocked' = unlocked \cup {v} /\ linkedRead' = None
    /\ UNCHANGED <<sessionLocked, sharedExists, links, dangerous, reviewedLinks,
                   unlinkAudits, teamExport>>

Lock(v) ==
    /\ unlocked' = unlocked \ {v} /\ linkedRead' = None
    /\ UNCHANGED <<sessionLocked, sharedExists, links, dangerous, reviewedLinks,
                   unlinkAudits, teamExport>>

NativeLock ==
    /\ sessionLocked' = TRUE /\ unlocked' = {} /\ linkedRead' = None
    /\ UNCHANGED <<sharedExists, links, dangerous, reviewedLinks, unlinkAudits, teamExport>>

Resume ==
    /\ sessionLocked /\ sessionLocked' = FALSE /\ unlocked' = {} /\ linkedRead' = None
    /\ UNCHANGED <<sharedExists, links, dangerous, reviewedLinks, unlinkAudits, teamExport>>

CreateShared(confirmed) ==
    /\ CanUse(Shared) /\ ~sharedExists /\ Confirmed({Shared}, confirmed)
    /\ sharedExists' = TRUE /\ linkedRead' = None /\ reviewedLinks' = NoReview
    /\ UNCHANGED <<unlocked, sessionLocked, links, dangerous, unlinkAudits, teamExport>>

\* Link mutations read target metadata and require only the consumer's unlock.
\* One live alias per consumer, with enough history to unlink and relink once.
LinkProject(p, confirmed) ==
    /\ CanUse(p) /\ sharedExists /\ p \notin links /\ Confirmed({p}, confirmed)
    /\ unlinkAudits[p] < MaxUnlinks
    /\ links' = links \cup {p} /\ linkedRead' = None
    /\ UNCHANGED <<unlocked, sessionLocked, sharedExists, dangerous, reviewedLinks,
                   unlinkAudits, teamExport>>

UnlinkProject(p, confirmed) ==
    /\ CanUse(p) /\ p \in links /\ Confirmed({p}, confirmed)
    /\ links' = links \ {p} /\ unlinkAudits' = AppendUnlinkAudits({p})
    /\ linkedRead' = None
    /\ UNCHANGED <<unlocked, sessionLocked, sharedExists, dangerous, reviewedLinks, teamExport>>

CanRead(p) == sharedExists /\ p \in links /\ CanUse(p) /\ CanUse(Shared)

\* The same vault gate applies to a linked value read, run, or Docker resolution.
ReadLinked(p, accepted) ==
    /\ accepted = CanRead(p)
    /\ linkedRead' = IF accepted THEN p ELSE None
    /\ UNCHANGED <<unlocked, sessionLocked, sharedExists, links, dangerous, reviewedLinks,
                   unlinkAudits, teamExport>>

ReviewUsages ==
    /\ sharedExists
    /\ reviewedLinks' = ActiveLinkIds /\ linkedRead' = None
    /\ UNCHANGED <<unlocked, sessionLocked, sharedExists, links, dangerous, unlinkAudits,
                   teamExport>>

\* The reviewed unlink-all flow sends the exact IDs returned by ReviewUsages.
\* An ordinary delete sends no review and is allowed only with no usages.
CanDelete(unlinkAll, confirmed) ==
    /\ sharedExists /\ CanUse(Shared) /\ links \subseteq unlocked
    /\ Confirmed(links \cup {Shared}, confirmed)
    /\ IF unlinkAll THEN reviewedLinks = ActiveLinkIds ELSE links = {}

DeleteShared(unlinkAll, confirmed, accepted) ==
    /\ accepted = CanDelete(unlinkAll, confirmed)
    /\ sharedExists' = (sharedExists /\ ~accepted)
    /\ links' = IF accepted THEN {} ELSE links
    /\ unlinkAudits' = IF accepted THEN AppendUnlinkAudits(links) ELSE unlinkAudits
    /\ linkedRead' = None
    /\ UNCHANGED <<unlocked, sessionLocked, dangerous, reviewedLinks, teamExport>>

PublishTeamSync(p) ==
    /\ CanUse(p)
    /\ teamExport' = [project |-> p, links |-> {}, dedupTags |-> {}]
    /\ linkedRead' = None
    /\ UNCHANGED <<unlocked, sessionLocked, sharedExists, links, dangerous, reviewedLinks,
                   unlinkAudits>>

Next ==
    \/ \E v \in Vaults : Unlock(v) \/ Lock(v)
    \/ NativeLock \/ Resume \/ ReviewUsages
    \/ \E confirmed \in BOOLEAN : CreateShared(confirmed)
    \/ \E p \in Projects, confirmed \in BOOLEAN : LinkProject(p, confirmed) \/ UnlinkProject(p, confirmed)
    \/ \E p \in Projects, accepted \in BOOLEAN : ReadLinked(p, accepted)
    \/ \E unlinkAll, confirmed, accepted \in BOOLEAN : DeleteShared(unlinkAll, confirmed, accepted)
    \/ \E p \in Projects : PublishTeamSync(p)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ unlocked \subseteq Vaults /\ sessionLocked \in BOOLEAN
    /\ sharedExists \in BOOLEAN /\ links \subseteq Projects /\ dangerous \subseteq Vaults
    /\ reviewedLinks \in (SUBSET LinkIds) \cup {NoReview}
    /\ unlinkAudits \in [Projects -> 0..MaxUnlinks]
    /\ ActiveLinkIds \subseteq LinkIds
    /\ linkedRead \in Projects \cup {None}
    /\ teamExport \in [project : Projects \cup {None}, links : SUBSET Projects,
                      dedupTags : SUBSET {"localDedupTag"}]

DualVaultLinkedReadSafety ==
    linkedRead # None => sharedExists /\ linkedRead \in links /\ ~sessionLocked
                         /\ {linkedRead, Shared} \subseteq unlocked

NoDanglingLinks == ~sharedExists => links = {}

LinksNeverExportedInTeamSync == teamExport.links = {} /\ teamExport.dedupTags = {}

\* Edge invariants inspect the actual pre-mutation state and audit increments.
\* Checking accepted actions for each request also binds the authorization flags.
DeleteAuthorization ==
    /\ (sharedExists /\ ~sharedExists') =>
          \E unlinkAll, confirmed \in BOOLEAN : DeleteShared(unlinkAll, confirmed, TRUE)
    /\ \A unlinkAll, confirmed \in BOOLEAN :
          DeleteShared(unlinkAll, confirmed, TRUE) =>
              /\ sharedExists /\ ~sessionLocked /\ links \cup {Shared} \subseteq unlocked
              /\ (links # {} => unlinkAll)
              /\ (unlinkAll => reviewedLinks = ActiveLinkIds)
              /\ (dangerous \cap (links \cup {Shared}) # {} => confirmed)

DeleteRequiresSnapshotUnlinkAllAndUnlocks == [][DeleteAuthorization]_vars

UnlinkAuditCompleteness ==
    /\ (sharedExists /\ ~sharedExists') => links' = {}
    /\ \A p \in Projects :
         unlinkAudits'[p] = unlinkAudits[p] + (IF p \in links \ links' THEN 1 ELSE 0)

CascadingUnlinkAuditCompleteness == [][UnlinkAuditCompleteness]_vars
====
