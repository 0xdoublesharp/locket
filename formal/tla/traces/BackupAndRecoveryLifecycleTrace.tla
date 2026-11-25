---- MODULE BackupAndRecoveryLifecycleTrace ----
EXTENDS BackupAndRecoveryLifecycle, BackupAndRecoveryLifecycleTraceData

VARIABLES traceIdx, traceCase
replayVars == <<vars, traceIdx, traceCase>>
Selected == IF traceCase = "published" THEN Trace ELSE RejectedTrace

\* Bind the model's symbolic digest to the independently hashed bundle on
\* disk. The audit digest in the trace is read separately from SQLite.
RecordedDigest == Trace[Len(Trace)].state.published
Observed == [published |-> vault.bundle, audited |-> audit["BACKUP_EXPORT"],
             occupancy |-> vault.profile.local]

ReplayInit ==
    /\ traceCase \in {"published", "rejected"}
    /\ Len(Selected) > 1 /\ Selected[1].action = "init"
    /\ Init /\ Observed = Selected[1].state
    /\ traceIdx = 1

Advance(row) ==
    /\ Observed' = row.state
    /\ traceIdx' = traceIdx + 1

\* Export is a single Rust RPC. Refine its observed boundary into the
\* model's internal steps, each of which must satisfy the base Next relation.
Apply(row) ==
    CASE row.action = "preview" ->
         /\ UNCHANGED vars /\ Advance(row)
      [] row.action \in {"export", "exportDenied"} ->
         CASE export = "idle" -> SealExport /\ UNCHANGED traceIdx
           [] export = "sealed" ->
                IF row.action = "export"
                THEN AuditExport /\ UNCHANGED traceIdx
                ELSE AbortExport /\ Advance(row)
           [] export = "audited" /\ row.action = "export" -> PublishExport /\ Advance(row)
           [] OTHER -> FALSE
      [] OTHER -> FALSE

ModelAllows(row) == IF row.action = "preview" THEN UNCHANGED vars ELSE Next

Complete == traceIdx = Len(Selected) + 1
\* Apply binds the primed variables. Check the model relation as a
\* Boolean expression over that candidate so TLC does not enumerate it again.
ReplayNext ==
    /\ UNCHANGED traceCase
    /\ IF traceIdx < Len(Selected)
       THEN LET row == Selected[traceIdx + 1] IN
            /\ Apply(row)
            /\ TRUE = ModelAllows(row)
       ELSE /\ UNCHANGED vars
            /\ traceIdx' = Len(Selected) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
