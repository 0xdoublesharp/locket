-------------------------- MODULE AgentDaemonLifecycle --------------------------
EXTENDS Naturals

CONSTANT Capacity
Workers == {"Primary", "Secondary", "Foreign"}
UID(worker) == IF worker = "Foreign" THEN "foreign" ELSE "local"
None == "none"
Owners == Workers \cup {None}
WorkerPhases == {"idle", "contending", "starting", "running", "stopping", "dead", "failed"}
StreamPhases == {"idle", "reading", "forwarding", "disposed"}

VARIABLES worker, lease, socket, pidFile, badCleanup,
          stream, queue, cancelled, errors

endpoint == <<worker, lease, socket, pidFile, badCleanup>>
subscription == <<stream, queue, cancelled, errors>>
vars == <<endpoint, subscription>>

Init ==
    /\ worker = [w \in Workers |-> "idle"]
    /\ lease = None
    /\ socket = None
    /\ pidFile = None
    /\ badCleanup = FALSE
    /\ stream = "idle"
    /\ queue = 0
    /\ cancelled = FALSE
    /\ errors = 0

Start(w) ==
    /\ worker[w] = "idle"
    /\ worker' = [worker EXCEPT ![w] = "contending"]
    /\ UNCHANGED <<lease, socket, pidFile, badCleanup, subscription>>

AcquireLease(w) ==
    /\ worker[w] = "contending"
    /\ lease = None
    /\ lease' = w
    /\ worker' = [worker EXCEPT ![w] = "starting"]
    /\ UNCHANGED <<socket, pidFile, badCleanup, subscription>>

PreviousOwner ==
    IF socket # None THEN socket ELSE pidFile

MayRemoveStale(caller) ==
    /\ PreviousOwner # None
    /\ worker[PreviousOwner] = "dead"
    /\ UID(PreviousOwner) = UID(caller)

EraseStaleEndpoint(caller) ==
    /\ MayRemoveStale(caller)
    /\ badCleanup' = (badCleanup \/
           (\E owner \in {socket, pidFile} \ {None} :
                worker[owner] # "dead" \/ UID(owner) # UID(caller)))
    /\ socket' = None
    /\ pidFile' = None
    /\ UNCHANGED <<worker, lease, subscription>>

RemoveStale(caller) ==
    /\ lease = caller
    /\ worker[caller] = "starting"
    /\ EraseStaleEndpoint(caller)

\* A stop with no live listener takes and releases the same lease around
\* its stale-file inspection and removal.
StopStale(caller) ==
    /\ lease = None
    /\ EraseStaleEndpoint(caller)

FailStartup(w) ==
    /\ \/ /\ worker[w] = "contending"
          /\ lease # None
       \/ /\ worker[w] = "starting"
          /\ socket # w
    /\ worker' = [worker EXCEPT ![w] = "failed"]
    /\ lease' = IF lease = w THEN None ELSE lease
    /\ UNCHANGED <<socket, pidFile, badCleanup, subscription>>

BindSocket(w) ==
    /\ worker[w] = "starting"
    /\ lease = w
    /\ socket = None
    /\ pidFile = None
    /\ socket' = w
    /\ UNCHANGED <<worker, lease, pidFile, badCleanup, subscription>>

PublishPid(w) ==
    /\ worker[w] = "starting"
    /\ lease = w
    /\ socket = w
    /\ pidFile = None
    /\ pidFile' = w
    /\ worker' = [worker EXCEPT ![w] = "running"]
    /\ UNCHANGED <<lease, socket, badCleanup, subscription>>

Stop(caller) ==
    /\ lease # None
    /\ worker[lease] = "running"
    /\ socket = lease /\ pidFile = lease
    /\ UID(caller) = UID(lease)
    /\ worker' = [worker EXCEPT ![lease] = "stopping"]
    /\ UNCHANGED <<lease, socket, pidFile, badCleanup, subscription>>

ReleaseEndpoint(w) ==
    /\ lease = w
    /\ \/ worker[w] = "stopping"
       \/ worker[w] = "starting" /\ socket = w
    /\ worker' = [worker EXCEPT ![w] = "dead"]
    /\ socket' = IF socket = w THEN None ELSE socket
    /\ pidFile' = IF pidFile = w THEN None ELSE pidFile
    /\ lease' = None
    /\ UNCHANGED <<badCleanup, subscription>>

Crash(w) ==
    /\ lease = w
    /\ worker' = [worker EXCEPT ![w] = "dead"]
    /\ lease' = None
    /\ UNCHANGED <<socket, pidFile, badCleanup, subscription>>

SubscribeStatus ==
    /\ stream = "idle"
    /\ socket # None
    /\ worker[socket] = "running"
    /\ stream' = "reading"
    /\ UNCHANGED <<endpoint, queue, cancelled, errors>>

ReadEvent ==
    /\ stream = "reading"
    /\ ~cancelled
    /\ stream' = "forwarding"
    /\ UNCHANGED <<endpoint, queue, cancelled, errors>>

Enqueue ==
    /\ stream = "forwarding"
    /\ ~cancelled
    /\ queue < Capacity
    /\ queue' = queue + 1
    /\ stream' = "reading"
    /\ UNCHANGED <<endpoint, cancelled, errors>>

Consume ==
    /\ queue > 0
    /\ queue' = queue - 1
    /\ UNCHANGED <<endpoint, stream, cancelled, errors>>

DisposeOnFailure(cause) ==
    /\ cause \in {"protocol-error", "socket-close"}
    /\ stream = "reading"
    /\ ~cancelled
    /\ stream' = "disposed"
    /\ errors' = errors + 1
    /\ UNCHANGED <<endpoint, queue, cancelled>>

RequestCancel ==
    /\ stream \in {"reading", "forwarding"}
    /\ ~cancelled
    /\ cancelled' = TRUE
    /\ UNCHANGED <<endpoint, stream, queue, errors>>

\* Disposal closes the connection even if the consumer never drains the
\* queue or the peer cannot accept a cancellation frame.
DisposeOnCancel ==
    /\ cancelled
    /\ stream \in {"reading", "forwarding"}
    /\ stream' = "disposed"
    /\ UNCHANGED <<endpoint, queue, cancelled, errors>>

Next ==
    \/ \E w \in Workers :
            Start(w) \/ AcquireLease(w) \/ RemoveStale(w) \/ FailStartup(w)
            \/ BindSocket(w) \/ PublishPid(w) \/ Stop(w) \/ StopStale(w)
            \/ ReleaseEndpoint(w) \/ Crash(w)
    \/ SubscribeStatus \/ ReadEvent \/ Enqueue \/ Consume
    \/ \E cause \in {"protocol-error", "socket-close"} : DisposeOnFailure(cause)
    \/ RequestCancel \/ DisposeOnCancel

Spec == Init /\ [][Next]_vars /\ WF_vars(DisposeOnCancel)

TypeInvariant ==
    /\ worker \in [Workers -> WorkerPhases]
    /\ {lease, socket, pidFile} \subseteq Owners
    /\ badCleanup \in BOOLEAN
    /\ stream \in StreamPhases
    /\ queue \in 0..Capacity
    /\ cancelled \in BOOLEAN
    /\ errors \in 0..2

LiveSocketAndPidPreserved ==
    /\ \A w \in Workers :
           worker[w] \in {"running", "stopping"} => lease = w /\ socket = w /\ pidFile = w
    /\ pidFile # None => socket = pidFile
    /\ lease = None => (socket # None => worker[socket] = "dead")

SingleOwnerStaleCleanup == ~badCleanup
NoDuplicateStreamError == errors <= 1 /\ (errors # 0 => stream = "disposed")
CancelTerminatesUnderBackpressure == cancelled ~> (stream = "disposed")

=============================================================================
