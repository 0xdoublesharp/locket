------------------------ MODULE SecretLifecycleAuditChain --------------------
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Horizon, MaxVersions, MaxAuditRows, GraceTTLs, K_audit, K_master

\* One project/profile/name. The ranks also identify the source rows.
TeamManaged == 1
UserLocal == 2
MachineLocal == 3
Sources == {TeamManaged, UserLocal, MachineLocal}
Versions == 1..MaxVersions
NoSource == 0
NoVersion == 0
Genesis == <<>>

NoRow == [status |-> "absent", current |-> NoVersion,
          versions |-> [v \in Versions |-> [status |-> "absent", graceUntil |-> 0]]]
EmptySecrets == [s \in Sources |-> NoRow]

VARIABLES now, secrets, log, checkpoint, mutations, tombstones, purged
vars == <<now, secrets, log, checkpoint, mutations, tombstones, purged>>

Init ==
    /\ now = 0
    /\ secrets = EmptySecrets
    /\ log = <<>>
    /\ checkpoint = [seq |-> 0, rowMac |-> Genesis, mac |-> Genesis]
    /\ mutations = 0
    /\ tombstones = {}
    /\ purged = {}

Version(status, grace) == [status |-> status, graceUntil |-> grace]
Event(op, source, version, grace) ==
    [op |-> op, source |-> source, version |-> version, grace |-> grace]

\* Symbolic domain-separated tags. No secret values enter an audit event.
RowMac(key, n, previous, event) == <<key, "row", n, previous, event>>
CheckpointMac(key, n, digest) == <<key, "checkpoint", n, digest>>
LastMac(history) == IF Len(history) = 0 THEN Genesis ELSE history[Len(history)].mac

AppendAudit(event) ==
    /\ Len(log) < MaxAuditRows
    /\ LET n == Len(log) + 1
           previous == LastMac(log)
       IN log' = Append(log, [seq |-> n, prevMac |-> previous, event |-> event,
                             mac |-> RowMac(K_audit, n, previous, event)])

Mutate(event) ==
    /\ AppendAudit(event)
    /\ mutations' = mutations + 1
    /\ UNCHANGED <<now, checkpoint>>

CreateSecret(s) ==
    /\ secrets[s].status = "absent"
    /\ secrets' = [secrets EXCEPT ![s].status = "active", ![s].current = 1,
                                  ![s].versions[1] = Version("current", 0)]
    /\ Mutate(Event("create", s, 1, 0))
    /\ UNCHANGED <<tombstones, purged>>

RotateSecret(s, graceTTL) ==
    /\ secrets[s].status = "active"
    /\ LET old == secrets[s].current
           new == old + 1
           deadline == now + graceTTL
       IN /\ new \in Versions
          /\ secrets[s].versions[old].status = "current"
          /\ secrets[s].versions[new].status = "absent"
          /\ secrets' = [secrets EXCEPT ![s].current = new,
                                        ![s].versions[old] = Version("deprecated", deadline),
                                        ![s].versions[new] = Version("current", 0)]
          /\ Mutate(Event("rotate", s, new, deadline))
    /\ UNCHANGED <<tombstones, purged>>

PurgeVersion(s, v) ==
    /\ secrets[s].versions[v].status \in {"current", "deprecated"}
    /\ secrets[s].status = "deleted" \/ v # secrets[s].current
    /\ secrets' = [secrets EXCEPT ![s].versions[v] = Version("purged", 0)]
    /\ Mutate(Event("purge", s, v, 0))
    /\ purged' = purged \cup {<<s, v>>}
    /\ UNCHANGED tombstones

TombstoneSecret(s) ==
    /\ secrets[s].status = "active"
    /\ secrets' = [secrets EXCEPT ![s].status = "deleted"]
    /\ Mutate(Event("delete", s, NoVersion, 0))
    /\ tombstones' = tombstones \cup {s}
    /\ UNCHANGED purged

Tick ==
    /\ now < Horizon
    /\ now' = now + 1
    /\ UNCHANGED <<secrets, log, checkpoint, mutations, tombstones, purged>>

\* Source selection precedes version lookup. A missing or expired pin at the
\* winning source cannot fall through to a lower source.
SelectSource(selector) ==
    IF selector # NoSource
    THEN IF secrets[selector].status = "active" THEN selector ELSE NoSource
    ELSE IF secrets[MachineLocal].status = "active" THEN MachineLocal
    ELSE IF secrets[UserLocal].status = "active" THEN UserLocal
    ELSE IF secrets[TeamManaged].status = "active" THEN TeamManaged
    ELSE NoSource

ResolveResult(selector, pin) ==
    LET s == SelectSource(selector) IN
    IF s = NoSource THEN <<NoSource, NoVersion>>
    ELSE LET v == IF pin = NoVersion THEN secrets[s].current ELSE pin
             row == secrets[s].versions[v]
         IN IF row.status = "current" \/
               (pin # NoVersion /\ row.status = "deprecated" /\ row.graceUntil > now)
            THEN <<s, v>>
            ELSE <<NoSource, NoVersion>>

EligibleSource(s, selector) ==
    /\ secrets[s].status = "active"
    /\ IF selector = NoSource
       THEN \A higher \in Sources : higher > s => secrets[higher].status # "active"
       ELSE selector = s

EligibleVersion(s, v, pin) ==
    LET row == secrets[s].versions[v] IN
    IF pin = NoVersion
    THEN v = secrets[s].current /\ row.status = "current"
    ELSE v = pin /\ (row.status = "current" \/
                     (row.status = "deprecated" /\ now < row.graceUntil))

ResolutionCorrect(selector, pin) ==
    LET result == ResolveResult(selector, pin) IN
    /\ result[1] = NoSource \/
       (EligibleSource(result[1], selector) /\ EligibleVersion(result[1], result[2], pin))
    /\ \A s \in Sources, v \in Versions :
         (EligibleSource(s, selector) /\ EligibleVersion(s, v, pin)) => result = <<s, v>>

Resolve(selector, pin) ==
    /\ ResolveResult(selector, pin) # <<NoSource, NoVersion>>
    /\ UNCHANGED vars

Previous(history, n) == IF n = 1 THEN Genesis ELSE history[n - 1].mac
ValidChain(history) ==
    \A n \in 1..Len(history) :
       LET row == history[n] IN
       /\ row.seq = n
       /\ row.prevMac = Previous(history, n)
       /\ row.mac = RowMac(K_audit, n, row.prevMac, row.event)

ValidCheckpoint(history, anchor) ==
    /\ anchor.seq \in 1..Len(history)
    /\ history[anchor.seq].mac = anchor.rowMac
    /\ anchor.mac = CheckpointMac(K_audit, anchor.seq, anchor.rowMac)

SaveCheckpoint ==
    /\ Len(log) > checkpoint.seq
    /\ ValidChain(log)
    /\ checkpoint' = [seq |-> Len(log), rowMac |-> LastMac(log),
                      mac |-> CheckpointMac(K_audit, Len(log), LastMac(log))]
    /\ UNCHANGED <<now, secrets, log, mutations, tombstones, purged>>

VerifyAudit(useCheckpoint) ==
    /\ ValidChain(log)
    /\ ~useCheckpoint \/ ValidCheckpoint(log, checkpoint)
    /\ AppendAudit(Event(IF useCheckpoint THEN "verify-checkpoint" ELSE "verify", NoSource, NoVersion, 0))
    /\ UNCHANGED <<now, secrets, checkpoint, mutations, tombstones, purged>>

Next ==
    \/ Tick \/ SaveCheckpoint
    \/ \E anchored \in BOOLEAN : VerifyAudit(anchored)
    \/ \E selector \in Sources \cup {NoSource}, pin \in Versions \cup {NoVersion} :
         Resolve(selector, pin)
    \/ \E s \in Sources :
         \/ CreateSecret(s)
         \/ TombstoneSecret(s)
         \/ \E ttl \in GraceTTLs : RotateSecret(s, ttl)
         \/ \E v \in Versions : PurgeVersion(s, v)

Spec == Init /\ [][Next]_vars

GraceDeadlines == 0..(Horizon + CHOOSE t \in GraceTTLs : \A u \in GraceTTLs : u <= t)
VersionType == [status : {"absent", "current", "deprecated", "purged"},
                graceUntil : GraceDeadlines]
EventType == [op : {"create", "rotate", "purge", "delete", "verify", "verify-checkpoint"},
              source : Sources \cup {NoSource}, version : Versions \cup {NoVersion},
              grace : GraceDeadlines]
TypeInvariant ==
    /\ now \in 0..Horizon
    /\ secrets \in [Sources -> [status : {"absent", "active", "deleted"},
                                 current : Versions \cup {NoVersion},
                                 versions : [Versions -> VersionType]]]
    /\ Len(log) \in 0..MaxAuditRows
    /\ \A n \in 1..Len(log) : log[n].event \in EventType /\ log[n].seq \in 1..MaxAuditRows
    /\ checkpoint.seq \in 0..Len(log)
    /\ mutations \in 0..MaxAuditRows
    /\ tombstones \subseteq Sources
    /\ purged \subseteq Sources \X Versions

SingleCurrentVersionPerActiveSource ==
    \A s \in Sources :
       secrets[s].status = "active" =>
          /\ secrets[s].current \in Versions
          /\ {v \in Versions : secrets[s].versions[v].status = "current"} = {secrets[s].current}

PurgedVersionNeverCurrentOrResolvable ==
    \A pair \in purged :
       LET s == pair[1]
           v == pair[2]
       IN /\ secrets[s].versions[v].status = "purged"
          /\ secrets[s].status = "active" => secrets[s].current # v
          /\ \A selector \in Sources \cup {NoSource}, pin \in Versions \cup {NoVersion} :
                ResolveResult(selector, pin) # pair

NoTombstoneReactivation ==
    \A s \in tombstones : secrets[s].status = "deleted"

ResolutionPrecedenceAndGraceSoundness ==
    \A selector \in Sources \cup {NoSource}, pin \in Versions \cup {NoVersion} :
       ResolutionCorrect(selector, pin)

\* Reconstruct the database independently from authenticated event metadata.
ApplyEvent(snapshot, event) ==
    LET s == event.source
        v == event.version
    IN CASE event.op = "create" ->
             [snapshot EXCEPT ![s].status = "active", ![s].current = v,
                              ![s].versions[v] = Version("current", 0)]
         [] event.op = "rotate" ->
             [snapshot EXCEPT ![s].current = v, ![s].versions[v] = Version("current", 0),
                 ![s].versions[v - 1] = Version("deprecated", event.grace)]
         [] event.op = "purge" ->
             [snapshot EXCEPT ![s].versions[v] = Version("purged", 0)]
         [] event.op = "delete" ->
             [snapshot EXCEPT ![s].status = "deleted"]
         [] OTHER -> snapshot

RECURSIVE Replay(_)
Replay(history) ==
    IF Len(history) = 0 THEN EmptySecrets
    ELSE ApplyEvent(Replay(SubSeq(history, 1, Len(history) - 1)), history[Len(history)].event)

AuditChainContinuityAndKeySeparation ==
    /\ K_audit # K_master
    /\ ValidChain(log)
    /\ \A n \in 1..Len(log) :
          log[n].mac # RowMac(K_master, n, log[n].prevMac, log[n].event)
    /\ mutations = Cardinality({n \in 1..Len(log) : log[n].event.op \notin {"verify", "verify-checkpoint"}})
    /\ secrets = Replay(log)
    /\ checkpoint.seq = 0 \/ ValidCheckpoint(log, checkpoint)

\* A retained anchor can advance while its old row remains authenticated.
CheckpointExtends ==
    checkpoint.seq # 0 =>
       /\ checkpoint'.seq >= checkpoint.seq
       /\ ValidCheckpoint(log', checkpoint)

CheckpointMonotonicity == [][CheckpointExtends]_vars

=============================================================================
