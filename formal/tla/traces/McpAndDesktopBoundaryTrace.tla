---- MODULE McpAndDesktopBoundaryTrace ----
EXTENDS McpAndDesktopBoundary, McpAndDesktopBoundaryTraceData, Naturals, Sequences

VARIABLE traceIdx, scenario
replayVars == <<vars, traceIdx, scenario>>
Traces == [regular |-> RecordedTrace, symlink |-> RejectedTrace]

\* An inspect response exposes dotenv key names. Project/profile fields
\* have no counterpart in this RPC; a plaintext marker is observable.
Observed == [phase |-> phase, response |-> response \cap {"secret-name", Plaintext}]

ReplayInit ==
    /\ scenario \in DOMAIN Traces
    /\ Len(Traces[scenario]) > 1 /\ Traces[scenario][1].action = "init"
    /\ Init /\ Observed = Traces[scenario][1].state
    /\ traceIdx = 1

Apply(row) ==
    CASE phase = "idle" ->
        /\ Begin /\ request' = Request(Inspect, "cwd", FALSE, FALSE, FALSE, FALSE)
      [] phase = "resolve" ->
        IF fs.fileLink = row.input[1] THEN Resolve
        ELSE /\ FilesystemChange /\ fs' = [fs EXCEPT !.fileLink = row.input[1]]
      [] phase = "validated" -> Open
      [] phase = "opened" -> Read
      [] phase = "respond" -> Respond
      [] OTHER -> FALSE

Complete == traceIdx = Len(Traces[scenario]) + 1

ReplayNext ==
    LET rows == Traces[scenario] IN
    /\ UNCHANGED scenario
    /\ IF traceIdx < Len(rows)
       THEN LET row == rows[traceIdx + 1] IN
            /\ row.action = "inspect"
            /\ Apply(row) /\ TRUE = Next
            /\ IF phase' # "done" THEN UNCHANGED traceIdx
               ELSE /\ Observed' = row.state /\ traceIdx' = traceIdx + 1
       ELSE /\ UNCHANGED vars /\ traceIdx' = Len(rows) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
