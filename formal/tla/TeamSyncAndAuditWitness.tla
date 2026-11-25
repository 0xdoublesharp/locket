---- MODULE TeamSyncAndAuditWitness ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANT MaxTip

Owner == "owner"
Recipients == {"developerA", "developerB"}
Devices == {Owner} \cup Recipients
Roles == {"admin", "developer", "unenrolled", "revoked"}
ActiveAdmin(roles, actor) == actor = Owner /\ roles[actor] = "admin"
Project == "project"
Nonces == {"nonceA", "nonceB", "nonceC"}
Absent == <<>>

VARIABLES scenario, team, audit, roster
vars == <<scenario, team, audit, roster>>

Member == "developerA"
Replicas == Recipients
RosterStatus == {"active", "omitted", "revoked"}
RosterDocument(status, revision, signer, invitation) ==
    [status |-> status, revision |-> revision, predecessor |-> revision - 1,
     signer |-> signer, invitation |-> invitation]
FirstRoster == RosterDocument("active", 1, Owner, Absent)
NewReplica == [revision |-> 1, status |-> "active", removedAt |-> 0, keyEpoch |-> 1]
RosterInit ==
    [published |-> <<FirstRoster>>, invitation |-> Absent,
     replicas |-> [d \in Replicas |-> NewReplica],
     inbox |-> [d \in Replicas |-> 0]]

Init ==
    /\ scenario \in {"team", "audit", "roster"}
    /\ roster = RosterInit
    /\ team = [roles |-> [d \in Devices |->
                            CASE d = Owner -> "admin"
                              [] d = "developerA" -> "developer"
                              [] OTHER -> "unenrolled"],
                keyEpoch |-> 1,
                revokedAt |-> [d \in Recipients |-> 0],
                changes |-> <<>>,
                packages |-> [d \in Recipients |-> <<>>],
                reconciled |-> [d \in Recipients |-> 0],
                draft |-> Absent]
    /\ audit = [tip |-> 0, intactThrough |-> 0, status |-> "unchecked",
                submitted |-> Absent, external |-> <<>>, local |-> <<>>]

Membership ==
    \E actor \in Devices, d \in Recipients:
        /\ ActiveAdmin(team.roles, actor)
        /\ team.roles[d] \in {"unenrolled", "developer"}
        /\ LET revoked == team.roles[d] = "developer"
               epoch == IF revoked THEN team.keyEpoch + 1 ELSE team.keyEpoch
               role == IF revoked THEN "revoked" ELSE "developer"
           IN team' = [team EXCEPT !.roles[d] = role,
                                   !.keyEpoch = epoch,
                                   !.revokedAt[d] = IF revoked THEN epoch ELSE @,
                                   !.changes = Append(@, [actor |-> actor, roles |-> team.roles,
                                                          target |-> d, result |-> role,
                                                          before |-> team.keyEpoch, after |-> epoch])]

PreparePackage ==
    /\ team.draft = Absent
    /\ \E actor \in Devices, d \in Recipients:
        /\ ActiveAdmin(team.roles, actor)
        /\ team.roles[d] = "developer"
        /\ Len(team.packages[d]) < 2
        /\ team' = [team EXCEPT !.draft =
            <<[recipient |-> d, roles |-> team.roles, keyEpoch |-> team.keyEpoch,
               prev |-> Len(team.packages[d])]>>]

Publish ==
    /\ team.draft # Absent
    /\ LET draft == Head(team.draft)
           d == draft.recipient
           fresh == /\ draft.roles = team.roles
                    /\ draft.keyEpoch = team.keyEpoch
                    /\ draft.prev = Len(team.packages[d])
       IN team' = IF fresh
                  THEN [team EXCEPT !.draft = Absent,
                                    !.packages[d] = Append(@,
                                        [sealedTo |-> d, keyEpoch |-> draft.keyEpoch,
                                         version |-> draft.prev + 1, prev |-> draft.prev])]
                  ELSE [team EXCEPT !.draft = Absent]

Reconcile ==
    \E d, addressedDevice \in Recipients:
      \E i \in 1..Len(team.packages[addressedDevice]):
        LET p == team.packages[addressedDevice][i]
        IN /\ p.sealedTo = d
           /\ p.prev = team.reconciled[d]
           /\ team' = [team EXCEPT !.reconciled[d] = p.version]

TeamStep ==
    /\ scenario = "team"
    /\ Membership \/ PreparePackage \/ Publish \/ Reconcile
    /\ UNCHANGED <<audit, roster, scenario>>

PublishRemoval ==
    /\ Len(roster.published) = 1
    /\ \E status \in {"omitted", "revoked"}:
        roster' = [roster EXCEPT !.published = Append(@, RosterDocument(status, 2, Owner, Absent))]

\* Separate authorization, bound to the pinned owner, removed identity and revision.
OwnerReinvites ==
    /\ Len(roster.published) = 2
    /\ roster.invitation = Absent
    /\ roster' = [roster EXCEPT !.invitation = <<Owner, Member, 2>>]

PublishRelisting ==
    /\ Len(roster.published) = 2
    /\ \E signer \in {Owner, Member}, claimed \in {Absent, <<Owner, Member, 2>>}:
        /\ (signer = Owner /\ claimed # Absent) => claimed = roster.invitation
        /\ roster' = [roster EXCEPT !.published =
            Append(@, RosterDocument("active", 3, signer, claimed))]

ReceiveRoster ==
    \E d \in Replicas, i \in 1..Len(roster.published):
        /\ roster.inbox[d] = 0
        /\ roster' = [roster EXCEPT !.inbox[d] = i]

ReconcileRoster ==
    \E d \in Replicas:
        /\ roster.inbox[d] # 0
        /\ LET local == roster.replicas[d]
               update == roster.published[roster.inbox[d]]
               accepted == /\ update.signer = Owner
                           /\ update.revision = local.revision + 1
                           /\ update.predecessor = local.revision
                           /\ IF update.status = "active" /\ local.removedAt > 0
                              THEN /\ update.invitation = <<Owner, Member, local.removedAt>>
                                   /\ update.invitation = roster.invitation
                              ELSE TRUE
               nextReplica == [revision |-> update.revision, status |-> update.status,
                               removedAt |-> IF update.status = "active" THEN local.removedAt
                                             ELSE update.revision,
                               keyEpoch |-> IF update.status = "active" THEN update.revision
                                            ELSE local.keyEpoch]
           IN roster' = [roster EXCEPT !.inbox[d] = 0,
                                       !.replicas[d] = IF accepted THEN nextReplica ELSE @]

RosterStep ==
    /\ scenario = "roster"
    /\ PublishRemoval \/ OwnerReinvites \/ PublishRelisting \/ ReceiveRoster \/ ReconcileRoster
    /\ UNCHANGED <<team, audit, scenario>>

Last(chain) == chain[Len(chain)]
SeqNo(chain) == IF chain = <<>> THEN 0 ELSE Last(chain).seqNo

\* An authenticated receipt itself is its symbolic, collision-free digest.
DigestHead(chain) == IF chain = <<>> THEN Absent ELSE <<Last(chain)>>
Checkpoint(seq) == <<Project, seq, "authenticated prefix">>

VerifyReceipt(r, chain) ==
    /\ r.signed /\ r.project = Project
    /\ r.seqNo > SeqNo(chain)
    /\ r.prev = DigestHead(chain)
    /\ \A i \in 1..Len(chain): r.nonce # chain[i].nonce

AppendAudit ==
    /\ audit.tip < MaxTip
    /\ audit' = [audit EXCEPT !.tip = @ + 1, !.status = "unchecked",
                              !.intactThrough = IF @ = audit.tip THEN @ + 1 ELSE @]

Submit ==
    /\ audit.submitted = Absent
    /\ audit.tip > SeqNo(audit.external)
    /\ audit.tip = audit.intactThrough
    /\ \E n \in Nonces:
        audit' = [audit EXCEPT !.submitted =
            <<[signed |-> TRUE, project |-> Project, seqNo |-> audit.tip,
               nonce |-> n, prev |-> DigestHead(audit.external),
               checkpoint |-> Checkpoint(audit.tip)]>>]

SignOrReject ==
    /\ audit.submitted # Absent
    /\ LET r == Head(audit.submitted)
           candidates == {r,
               [r EXCEPT !.signed = FALSE],
               [r EXCEPT !.project = "anotherProject"],
               [r EXCEPT !.seqNo = SeqNo(audit.external)],
               [r EXCEPT !.prev = IF @ = Absent THEN <<[r EXCEPT !.signed = FALSE]>>
                                   ELSE Absent]}
       IN \E candidate \in candidates:
           audit' = IF VerifyReceipt(candidate, audit.external)
                    THEN [audit EXCEPT !.submitted = Absent, !.status = "unchecked",
                                       !.external = Append(@, candidate)]
                    ELSE [audit EXCEPT !.submitted = Absent]

Persist ==
    LET index == Len(audit.local) + 1
    IN /\ index <= Len(audit.external)
       /\ LET r == audit.external[index]
          IN /\ VerifyReceipt(r, audit.local)
             /\ audit' = [audit EXCEPT !.local = Append(@, r), !.status = "unchecked"]

RestoreOrModifyLocal ==
    \E tip \in 0..audit.tip, prefix \in 0..audit.intactThrough,
       persisted \in 0..Len(audit.local):
        /\ prefix <= tip
        /\ tip < audit.tip \/ prefix < audit.intactThrough \/ persisted < Len(audit.local)
        /\ audit' = [audit EXCEPT !.tip = tip, !.intactThrough = prefix,
                                  !.local = SubSeq(@, 1, persisted), !.status = "unchecked"]

Restart ==
    /\ audit.status = "unchecked"
    /\ LET anchor == SeqNo(audit.external)
           accepted == /\ DigestHead(audit.local) = DigestHead(audit.external)
                       /\ audit.tip >= anchor
                       /\ audit.intactThrough >= anchor
                       /\ IF anchor = 0 THEN TRUE
                          ELSE Last(audit.external).checkpoint = Checkpoint(anchor)
       IN audit' = [audit EXCEPT !.status = IF accepted THEN "verified" ELSE "rejected"]

AuditStep ==
    /\ scenario = "audit"
    /\ AppendAudit \/ Submit \/ SignOrReject \/ Persist \/ RestoreOrModifyLocal \/ Restart
    /\ UNCHANGED <<team, roster, scenario>>

Next == TeamStep \/ AuditStep \/ RosterStep
Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ scenario \in {"team", "audit", "roster"}
    /\ team.roles \in [Devices -> Roles]
    /\ team.keyEpoch \in 1..(Cardinality(Recipients) + 1)
    /\ team.revokedAt \in [Recipients -> 0..team.keyEpoch]
    /\ \A d \in Recipients:
        /\ (team.revokedAt[d] > 0) = (team.roles[d] = "revoked")
        /\ Len(team.packages[d]) <= 2
        /\ team.reconciled[d] \in 0..Len(team.packages[d])
        /\ \A i \in 1..Len(team.packages[d]):
            LET p == team.packages[d][i]
            IN /\ p.sealedTo = d
               /\ p.keyEpoch \in 1..team.keyEpoch
               /\ p.version = i /\ p.prev = i - 1
    /\ team.draft = Absent \/
        /\ Len(team.draft) = 1
        /\ Head(team.draft) \in [recipient : Recipients, roles : [Devices -> Roles],
                                keyEpoch : 1..team.keyEpoch, prev : 0..1]
    /\ Len(team.changes) <= 3
    /\ audit.tip \in 0..MaxTip
    /\ audit.intactThrough \in 0..audit.tip
    /\ audit.status \in {"unchecked", "verified", "rejected"}
    /\ Len(audit.local) <= Len(audit.external)
    /\ Len(audit.external) <= MaxTip
    /\ audit.submitted = Absent \/
        /\ Len(audit.submitted) = 1
        /\ Head(audit.submitted).seqNo \in 1..MaxTip
        /\ Head(audit.submitted).nonce \in Nonces
    /\ \A i \in 1..Len(audit.external): audit.external[i].seqNo \in 1..MaxTip

\* Derive removal from the accepted prefix, independently of the receiver's tombstone.
NoSilentMemberReinstatement ==
    \A d \in Replicas:
        LET local == roster.replicas[d]
        IN \A i \in 1..local.revision:
            (/\ roster.published[i].status # "active"
             /\ local.status = "active" \/ local.keyEpoch >= i) =>
                    \E j \in (i + 1)..local.revision:
                        LET update == roster.published[j]
                        IN /\ update.status = "active"
                           /\ update.signer = Owner
                           /\ update.invitation = <<Owner, Member, i>>
                           /\ update.invitation = roster.invitation

RosterReconciliationMonotonicity ==
    /\ Len(roster.published) \in 1..3
    /\ \A d \in Replicas:
        LET local == roster.replicas[d]
        IN /\ roster.inbox[d] \in 0..Len(roster.published)
           /\ local.revision \in 1..Len(roster.published)
           /\ local.status = roster.published[local.revision].status
           /\ local.status \in RosterStatus
           /\ local.keyEpoch \in 1..local.revision
           /\ local.removedAt \in 0..local.revision
           /\ \A i \in 1..local.revision:
                /\ roster.published[i].signer = Owner
                /\ roster.published[i].revision = i
                /\ roster.published[i].predecessor = i - 1
    /\ \A a, b \in Replicas:
        roster.replicas[a].revision = roster.replicas[b].revision =>
            roster.replicas[a] = roster.replicas[b]

RevokedDeviceExcludedFromNewEpochs ==
    \A d \in Recipients:
        team.revokedAt[d] > 0 =>
            \A i \in 1..Len(team.packages[d]): team.packages[d][i].keyEpoch < team.revokedAt[d]

OnlyActiveAdminChangesMembership ==
    \A i \in 1..Len(team.changes):
        LET change == team.changes[i]
        IN /\ ActiveAdmin(change.roles, change.actor)
           /\ IF change.result = "revoked"
              THEN change.after = change.before + 1
              ELSE change.after = change.before

WitnessMonotonicityAndAntiRollback ==
    /\ audit.local = SubSeq(audit.external, 1, Len(audit.local))
    /\ \A i \in 1..Len(audit.external):
        LET r == audit.external[i]
        IN /\ r.nonce \in Nonces
           /\ r.checkpoint = Checkpoint(r.seqNo)
           /\ VerifyReceipt(r, SubSeq(audit.external, 1, i - 1))
           /\ \A j \in 1..(i - 1):
               /\ audit.external[j].seqNo < r.seqNo
               /\ audit.external[j].nonce # r.nonce
    /\ audit.status = "verified" =>
         /\ audit.local = audit.external
         /\ audit.tip >= SeqNo(audit.external)
         /\ audit.intactThrough >= SeqNo(audit.external)

GuardMembershipTransition ==
    (team.roles' # team.roles \/ team.keyEpoch' # team.keyEpoch) =>
        /\ Len(team.changes') = Len(team.changes) + 1
        /\ ActiveAdmin(team.roles, Last(team.changes').actor)

MembershipRequiresAdmin == [][GuardMembershipTransition]_vars
====
