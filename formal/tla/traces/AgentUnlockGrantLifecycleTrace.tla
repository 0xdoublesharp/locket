---- MODULE AgentUnlockGrantLifecycleTrace ----
EXTENDS AgentUnlockGrantLifecycle, AgentUnlockGrantLifecycleTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

Observed == [now |-> now, keys |-> keys, sessionBlocked |-> sessionBlocked, grants |-> grants]

Apply(row) ==
    LET arg == row.input IN
    CASE row.action = "unlock" -> Unlock(arg[1], arg[2])
      [] row.action = "lock" -> LockProject(arg[1])
      [] row.action = "grant" -> IssueGrant(arg[1], arg[2], arg[3], arg[4], arg[5])
      [] row.action = "revoke" -> RevokeGrant
      [] row.action = "tick" -> Tick
      [] row.action = "nativeLock" -> SessionLockOrSleep
      [] row.action = "resume" -> Resume
      [] row.action = "resolve" ->
         /\ arg[4] = (\E g \in grants : GrantAllows(g, arg[1], arg[2], "resolve", arg[3]))
         /\ UseGrant(arg[1], arg[2], "resolve", arg[3])
      \* Refused requests leave the modeled state unchanged.
      [] row.action = "grantDenied" ->
         /\ ~(KeyLive(arg[1]) /\ ~sessionBlocked /\ (arg[2] # "dangerous" \/ arg[3]))
         /\ UNCHANGED vars
      [] row.action = "unlockDenied" ->
         /\ arg[1] \in Projects /\ sessionBlocked
         /\ UNCHANGED vars
      [] OTHER -> FALSE

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

ModelAllows(row) ==
    IF row.action \in {"grantDenied", "unlockDenied"} THEN UNCHANGED vars ELSE Next

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

\* The explicit terminal self-loop is the only replay edge that can stutter.
\* Keep TLC deadlock checking on so a mismatched observation fails at once.
TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
