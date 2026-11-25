---- MODULE AgentDaemonLifecycleTrace ----
EXTENDS AgentDaemonLifecycle, AgentDaemonLifecycleTraceData, Sequences

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>
Primary == "Primary"
Secondary == "Secondary"

Observed == [socket |-> socket # None, pidFile |-> pidFile # None,
             secondaryFailed |-> worker[Secondary] = "failed"]

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

Complete == traceIdx = Len(Trace) + 1

AtObservation(row) ==
    CASE row.action = "start" -> worker'[Primary] = "running"
      [] row.action = "contend" -> worker'[Secondary] = "failed"
      [] row.action = "stop" -> worker'[Primary] = "dead"
      [] OTHER -> FALSE

Apply(row) ==
    CASE row.action = "start" ->
        CASE worker[Primary] = "idle" -> Start(Primary)
          [] worker[Primary] = "contending" -> AcquireLease(Primary)
          [] socket = None -> BindSocket(Primary)
          [] OTHER -> PublishPid(Primary)
      [] row.action = "contend" ->
        IF worker[Secondary] = "idle" THEN Start(Secondary) ELSE FailStartup(Secondary)
      [] row.action = "stop" ->
        IF worker[Primary] = "running" THEN Stop(Primary) ELSE ReleaseEndpoint(Primary)
      [] OTHER -> FALSE

ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] IN
         /\ Apply(row) /\ TRUE = Next
         /\ IF AtObservation(row)
            THEN /\ Observed' = row.state /\ traceIdx' = traceIdx + 1
            ELSE UNCHANGED traceIdx
    ELSE /\ UNCHANGED vars /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
