---- MODULE EgressProxyAndRedactionTrace ----
EXTENDS EgressProxyAndRedaction, EgressProxyAndRedactionTraceData

VARIABLE traceIdx, scenario

replayVars == <<vars, traceIdx, scenario>>
Traces == [screening |-> RecordedTrace, authentication |-> RejectedTrace]
Observed == [phase |-> phase, forwarded |-> forwarded]

ReplayInit ==
    /\ scenario \in DOMAIN Traces
    /\ Len(Traces[scenario]) > 1 /\ Traces[scenario][1].action = "init"
    /\ Init /\ Observed = Traces[scenario][1].state
    /\ traceIdx = 1

Apply(row) ==
    CASE phase = "start" ->
        /\ Begin
        /\ request' = [peer |-> "loopback", auth |-> row.input[1], method |-> "HTTP",
                        host |-> "binding", agrees |-> TRUE, framing |-> "none",
                        field |-> "placeholder", allowLoopback |-> FALSE]
      [] phase = "resolve" -> Resolve /\ checked' = {"loopback"}
      [] OTHER -> FALSE

Complete == traceIdx = Len(Traces[scenario]) + 1

ReplayNext ==
    LET rows == Traces[scenario] IN
    /\ UNCHANGED scenario
    /\ IF traceIdx < Len(rows)
       THEN LET row == rows[traceIdx + 1] IN
            /\ row.action = "request"
            /\ Apply(row) /\ TRUE = Next
            /\ IF phase' = "resolve" THEN UNCHANGED traceIdx
               ELSE /\ Observed' = row.state /\ traceIdx' = traceIdx + 1
       ELSE /\ UNCHANGED vars /\ traceIdx' = Len(rows) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
