---- MODULE AutomationClientAuthTrace ----
EXTENDS AutomationClientAuth, AutomationClientAuthTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

Observed == [registry |-> registry, challenges |-> Cardinality(challenges),
             used |-> db.used, auditCount |-> db.auditCount["nonceA"] + db.auditCount["nonceB"],
             lastUsed |-> db.lastUsed # Never,
             status |-> IF observation.status = NoValue THEN "none" ELSE observation.status,
             granted |-> observation.granted]

Start(row) ==
    LET arg == row.input
        request == [client |-> Client, id |-> arg[1], nonce |-> arg[2],
                    method |-> "PrepareExec", action |-> "run-policy", policy |-> "build", timestamp |-> 0]
    IN \E challenge \in challenges : StartSignedRequest(request, challenge, row.action = "signed")

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

Complete == traceIdx = Len(Trace) + 1

ReplayNext ==
    IF traceIdx < Len(Trace)
    THEN LET row == Trace[traceIdx + 1] arg == row.input IN
         IF row.action = "signed" /\ pending = NoValue
         THEN /\ Start(row) /\ pending' # NoValue
              /\ TRUE = Next /\ UNCHANGED traceIdx
         ELSE /\ CASE row.action = "register" -> RegisterClient(TRUE, TRUE)
                      [] row.action = "hello" -> ClientHello(arg[1], Client, arg[2])
                      [] row.action = "badSignature" -> Start(row)
                      [] row.action = "signed" -> FinishSignedRequest("ok")
                      [] row.action = "revoke" -> RevokeClient
                      [] OTHER -> FALSE
              /\ TRUE = Next
              /\ Observed' = row.state
              /\ traceIdx' = traceIdx + 1
    ELSE /\ UNCHANGED vars /\ traceIdx' = Len(Trace) + 1

TraceSpec == ReplayInit /\ [][ReplayNext]_replayVars /\ WF_replayVars(ReplayNext)
TraceCompletion == <>Complete
====
