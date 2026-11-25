---- MODULE SecretLifecycleAuditChainTrace ----
EXTENDS SecretLifecycleAuditChain, SecretLifecycleAuditChainTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

\* Rust verifies the actual HMACs and records the ordered lifecycle events.
\* The base model checks its symbolic tags and replays that same event history.
Observed == [secrets |-> secrets, events |-> [i \in 1..Len(log) |-> log[i].event],
             anchor |-> checkpoint.seq]

Apply(row) ==
    LET arg == row.input IN
    CASE row.action = "create" -> CreateSecret(arg[1])
      [] row.action = "rotate" -> RotateSecret(arg[1], arg[2])
      [] row.action = "delete" -> TombstoneSecret(arg[1])
      [] row.action = "purge" -> PurgeVersion(arg[1], arg[2])
      [] row.action = "checkpoint" -> SaveCheckpoint
      [] row.action = "verify" -> VerifyAudit(TRUE)
      [] row.action = "resolve" ->
         /\ arg[3] = ResolveResult(arg[1], arg[2])
         /\ IF arg[3] = <<NoSource, NoVersion>>
            THEN UNCHANGED vars
            ELSE Resolve(arg[1], arg[2])
      [] row.action = "createDenied" ->
         /\ secrets[arg[1]].status = "deleted"
         /\ UNCHANGED vars
      [] OTHER -> FALSE

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

ModelAllows(row) ==
    IF row.action = "createDenied" \/
       (row.action = "resolve" /\ row.input[3] = <<NoSource, NoVersion>>)
    THEN UNCHANGED vars ELSE Next

Complete == traceIdx = Len(Trace) + 1
\* Apply binds the primed variables. Check the model relation as a
\* Boolean expression over that candidate so TLC does not enumerate it again.
ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] IN
         /\ Apply(row)
         /\ TRUE = ModelAllows(row)
         /\ Observed' = row.state
         /\ traceIdx' = traceIdx + 1
    ELSE /\ UNCHANGED vars
         /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
