---- MODULE AgentAuthzProtocolTrace ----
EXTENDS AgentAuthzProtocol, AgentAuthzProtocolTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

Observed == [unlocked |-> unlocked, blocked |-> blocked,
             grant |-> grants # {}, outcome |-> IF result.outcome = NoValue THEN "none" ELSE result.outcome]

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

Complete == traceIdx = Len(Trace) + 1

ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] arg == row.input IN
         IF row.action \in {"unlock", "grant"} /\ pending = NoValue
         THEN /\ IF row.action = "unlock" THEN StartUnlock(Human)
                  ELSE StartGrant("RequestGrant", Human, "Reveal", "dangerous", NoValue, arg[1])
              /\ TRUE = Next
              /\ UNCHANGED traceIdx
         ELSE /\ CASE row.action = "unlock" -> Finish(arg[1], FALSE, TRUE)
                      [] row.action = "grant" -> Finish(TRUE, FALSE, arg[2])
                      [] row.action = "lock" -> ClearAuthorization("Lock")
                      [] OTHER -> FALSE
              /\ TRUE = Next
              /\ Observed' = row.state
              /\ traceIdx' = traceIdx + 1
    ELSE /\ UNCHANGED vars /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
