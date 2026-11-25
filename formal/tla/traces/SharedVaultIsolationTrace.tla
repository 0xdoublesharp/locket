---- MODULE SharedVaultIsolationTrace ----
EXTENDS SharedVaultIsolation, SharedVaultIsolationTraceData, Integers

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

Observed == [unlocked |-> unlocked, sessionLocked |-> sessionLocked, grant |-> grant,
             sharedValue |-> sharedValue, dangerousTarget |-> dangerousTarget, copies |-> copies]

CopyAllowed(p, request) ==
    /\ {p, Shared} \subseteq unlocked
    /\ sharedValue = Absent \/ request.overwrite
    /\ ~dangerousTarget \/ request.confirmed

Apply(row) ==
    LET arg == row.input IN
    CASE row.action = "unlock" -> Unlock(arg[1])
      [] row.action = "prepare" -> PrepareExec(arg[1], arg[2])
      [] row.action = "resolve" ->
         /\ grant # NoGrant
         /\ arg[2] = (CanRun(grant.project, grant.declared) /\
                       arg[1] \in LocalRefs(grant.project) \cup SharedRefs(grant.declared))
         /\ ResolveGrant(arg[1])
      [] row.action = "beginCopy" -> BeginCopy(arg[1], arg[2], arg[3])
      [] row.action = "copy" ->
         /\ arg[2] = CopyAllowed(arg[1], copies[arg[1]])
         /\ CopySecretToShared(arg[1])
      [] row.action = "nativeLock" -> NativeLock
      [] OTHER -> FALSE

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

Complete == traceIdx = Len(Trace) + 1
\* Apply binds the primed variables. Check the model relation as a
\* Boolean expression over that candidate so TLC does not enumerate it again.
ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] IN
         /\ Apply(row)
         /\ TRUE = Next
         /\ Observed' = row.state
         /\ traceIdx' = traceIdx + 1
    ELSE /\ UNCHANGED vars
         /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
