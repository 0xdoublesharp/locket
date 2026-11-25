---- MODULE TeamSyncAndAuditWitnessTrace ----
EXTENDS TeamSyncAndAuditWitness, TeamSyncAndAuditWitnessTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

\* This trace exercises the model's authenticated team package scenario.
Observed == [roles |-> team.roles, keyEpoch |-> team.keyEpoch,
             packages |-> team.packages["developerA"],
             reconciled |-> team.reconciled["developerA"]]

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ scenario = "team" /\ Init
    /\ Observed = Trace[1].state /\ traceIdx = 1

Advance(row) ==
    /\ Observed' = row.state
    /\ traceIdx' = traceIdx + 1

\* The Rust publication prepares and commits the signed package in one call.
Apply(row) ==
    /\ CASE row.action = "membership" -> Membership /\ Advance(row)
         [] row.action = "publish" ->
              IF team.draft = Absent
              THEN PreparePackage /\ UNCHANGED traceIdx
              ELSE Publish /\ Advance(row)
         [] row.action = "reconcile" -> Reconcile /\ Advance(row)
         [] OTHER -> FALSE
    /\ UNCHANGED <<audit, roster, scenario>>

Complete == traceIdx = Len(Trace) + 1
\* Apply binds the primed variables. Check the model relation as a
\* Boolean expression over that candidate so TLC does not enumerate it again.
ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] IN
         /\ Apply(row)
         /\ TRUE = Next
    ELSE /\ UNCHANGED vars
         /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
