---- MODULE SharedSecretLinksTrace ----
EXTENDS SharedSecretLinks, SharedSecretLinksTraceData

VARIABLE traceIdx
replayVars == <<vars, traceIdx>>

Observed ==
    [unlocked |-> unlocked, sessionLocked |-> sessionLocked, sharedExists |-> sharedExists,
     links |-> links, dangerous |-> dangerous, reviewedLinks |-> reviewedLinks,
     unlinkAudits |-> unlinkAudits, linkedRead |-> linkedRead, teamExport |-> teamExport]

Apply(row) ==
    LET arg == row.input IN
    CASE row.action = "unlock" -> Unlock(arg[1])
      [] row.action = "lock" -> Lock(arg[1])
      [] row.action = "nativeLock" -> NativeLock
      [] row.action = "resume" -> Resume
      [] row.action = "create" -> CreateShared(arg[1])
      [] row.action = "link" -> LinkProject(arg[1], arg[2])
      [] row.action = "unlink" -> UnlinkProject(arg[1], arg[2])
      [] row.action = "read" -> ReadLinked(arg[1], arg[2])
      [] row.action = "review" -> ReviewUsages
      [] row.action = "delete" -> DeleteShared(arg[1], arg[2], arg[3])
      [] row.action = "publish" -> PublishTeamSync(arg[1])
      [] OTHER -> FALSE

ReplayInit ==
    /\ Len(Trace) > 1 /\ Trace[1].action = "init"
    /\ Init /\ Observed = Trace[1].state
    /\ traceIdx = 1

Complete == traceIdx = Len(Trace) + 1

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
