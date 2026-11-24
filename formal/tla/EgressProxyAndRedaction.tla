---- MODULE EgressProxyAndRedaction ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANT MaxBody

Hosts == {"binding", "otherBinding", "unlisted"}
AllowedHosts == {"binding"}
ConnectHosts == AllowedHosts \cup {"otherBinding"}
ExactHosts == ConnectHosts
IPs == {"public", "loopback", "private", "metadata"}
Methods == {"HTTP", "CONNECT"}
Framings == {"none", "length", "chunked", "ambiguous"}
Fields == {"plain", "placeholder", "proxyCredential"}
Secret == <<"a", "b", "a">>
Patterns == {Secret, <<"b", "a">>}
MaxPatternLen == Len(Secret)
Marker == "*"
Separator == "|"
Alphabet == {"a", "b"}
Responses == UNION {[1..n -> Alphabet] : n \in 0..MaxBody}
LocalRequest == [peer : {"loopback", "remote"},
                 auth : {"valid", "invalid", "missing", "duplicate"},
                 method : Methods, host : Hosts, agrees : BOOLEAN,
                 framing : Framings, field : Fields, allowLoopback : BOOLEAN]
NoAddress == "no address"

VARIABLES phase, request, checked, dnsNow, connected, forwarded, upstream,
          payload, unread, pending, covered, output, header, redirected

vars == <<phase, request, checked, dnsNow, connected, forwarded, upstream,
          payload, unread, pending, covered, output, header, redirected>>
requestState == <<request, checked, dnsNow, connected, forwarded, upstream>>
responseState == <<payload, unread, pending, covered, output, header, redirected>>

Init ==
    /\ phase = "start"
    /\ request = [peer |-> "remote", auth |-> "missing", method |-> "HTTP",
                  host |-> "unlisted", agrees |-> FALSE, framing |-> "none",
                  field |-> "plain", allowLoopback |-> FALSE]
    /\ checked = {}
    /\ dnsNow = {}
    /\ connected = NoAddress
    /\ forwarded = FALSE
    /\ upstream = {}
    /\ payload = <<>>
    /\ unread = <<>>
    /\ pending = <<>>
    /\ covered = 0
    /\ output = <<>>
    /\ header = <<>>
    /\ redirected = FALSE

RequestAllowed(r) ==
    /\ r.peer = "loopback"
    /\ r.auth = "valid"
    /\ r.agrees
    /\ r.framing \in {"none", "length"}
    /\ r.field # "proxyCredential"
    /\ IF r.method = "CONNECT"
       THEN /\ r.framing = "none"
            /\ r.host \in ConnectHosts
            /\ r.field = "plain"
       ELSE r.field # "placeholder" \/ r.host \in AllowedHosts

Begin ==
    /\ phase = "start"
    /\ \E r \in LocalRequest:
        /\ request' = r
        /\ phase' = IF RequestAllowed(r) THEN "resolve" ELSE "rejected"
    /\ UNCHANGED <<checked, dnsNow, connected, forwarded, upstream, responseState>>

IPAllowed(r, ip) ==
    ip = "public" \/ (ip = "loopback" /\ r.allowLoopback /\ r.host \in ExactHosts)

DNSAnswers == SUBSET IPs

Resolve ==
    /\ phase = "resolve"
    /\ \E answers \in DNSAnswers:
        /\ checked' = answers
        /\ dnsNow' = answers
        /\ phase' = IF answers # {} /\ (\A ip \in answers: IPAllowed(request, ip))
                     THEN "screened" ELSE "rejected"
    /\ UNCHANGED <<request, connected, forwarded, upstream, responseState>>

\* DNS may change after screening; connect uses the saved socket addresses.
Rebind ==
    /\ phase = "screened"
    /\ \E answers \in DNSAnswers \ {dnsNow}: dnsNow' = answers
    /\ UNCHANGED <<phase, request, checked, connected, forwarded, upstream, responseState>>

Connect ==
    /\ phase = "screened"
    /\ \E ip \in checked: connected' = ip
    /\ phase' = "connected"
    /\ dnsNow' = {}
    /\ UNCHANGED <<request, checked, forwarded, upstream, responseState>>

ForwardFields(r) ==
    LET headers == {"proxyCredential"} \cup
                   (IF r.field = "proxyCredential" THEN {"copiedCredential"} ELSE {})
        stripped == headers \ {"proxyCredential"}
    IN (IF "copiedCredential" \in stripped THEN {"proxyCredential"} ELSE {}) \cup
       (IF r.method = "HTTP" /\ r.field = "placeholder" THEN {"realSecret"} ELSE {})

Forward ==
    /\ phase = "connected"
    /\ forwarded' = TRUE
    /\ upstream' = ForwardFields(request)
    /\ phase' = IF request.method = "CONNECT" THEN "tunnel" ELSE "respond"
    /\ UNCHANGED <<request, checked, dnsNow, connected, responseState>>

MatchesAt(p, bytes, i) ==
    i + Len(p) - 1 <= Len(bytes) /\ SubSeq(bytes, i, i + Len(p) - 1) = p

Contains(p, bytes) == \E i \in 1..Len(bytes): MatchesAt(p, bytes, i)

Max(a, b) == IF a >= b THEN a ELSE b

\* Emit one marker per intersecting group. With a fixed marker it can be
\* emitted at the group's start, since covered offsets emit no plain bytes.
RECURSIVE Scan(_, _, _)
Scan(bytes, ready, remaining) ==
    IF ready = 0 THEN [buffer |-> bytes, cover |-> remaining, emitted |-> <<>>]
    ELSE LET width == CHOOSE n \in 0..MaxPatternLen:
                            /\ (n = 0 \/ \E p \in Patterns :
                                           Len(p) = n /\ MatchesAt(p, bytes, 1))
                            /\ \A p \in Patterns : MatchesAt(p, bytes, 1) => Len(p) <= n
             suffix == Scan(Tail(bytes), ready - 1, Max(1, Max(remaining, width)) - 1)
             emitted == IF remaining > 0 THEN <<>>
                        ELSE IF width > 0 THEN <<Marker>> ELSE <<Head(bytes)>>
         IN [suffix EXCEPT !.emitted = emitted \o @]

\* A Location echo is a separately redacted header value. CONNECT is opaque
\* and has no substituted material or inspected response in this model.
Respond ==
    /\ phase = "respond"
    /\ \E body \in Responses, redirect \in BOOLEAN:
        /\ payload' = body
        /\ unread' = body
        /\ header' = IF redirect THEN Secret ELSE <<>>
        /\ redirected' = redirect
        /\ output' = IF redirect THEN Scan(header', Len(header'), 0).emitted \o <<Separator>>
                      ELSE <<>>
    /\ phase' = "stream"
    /\ UNCHANGED <<requestState, pending, covered>>

ReadChunk ==
    /\ phase = "stream"
    /\ \E n \in 1..Len(unread):
        LET bytes == pending \o SubSeq(unread, 1, n)
            scan == Scan(bytes, Max(0, Len(bytes) - (MaxPatternLen - 1)), covered)
        IN /\ pending' = scan.buffer
           /\ covered' = scan.cover
           /\ output' = output \o scan.emitted
           /\ unread' = SubSeq(unread, n + 1, Len(unread))
    /\ UNCHANGED <<phase, requestState, payload, header, redirected>>

Flush ==
    /\ phase = "stream"
    /\ unread = <<>>
    /\ output' = output \o Scan(pending, Len(pending), covered).emitted
    /\ phase' = "done"
    /\ pending' = <<>>
    /\ covered' = 0
    /\ UNCHANGED <<requestState, payload, unread, header, redirected>>

Next == Begin \/ Resolve \/ Rebind \/ Connect \/ Forward \/ Respond \/ ReadChunk \/ Flush
Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ phase \in {"start", "resolve", "screened", "connected", "respond",
                   "stream", "done", "rejected", "tunnel"}
    /\ request \in LocalRequest
    /\ checked \subseteq IPs
    /\ dnsNow \subseteq IPs
    /\ connected \in IPs \cup {NoAddress}
    /\ forwarded \in BOOLEAN
    /\ upstream \subseteq {"realSecret", "proxyCredential"}
    /\ payload \in Responses
    /\ unread \in Responses
    /\ pending \in Responses
    /\ Len(pending) < MaxPatternLen
    /\ covered \in 0..(MaxPatternLen - 1)
    /\ \A i \in 1..Len(output): output[i] \in Alphabet \cup {Marker, Separator}
    /\ header \in {<<>>, Secret}
    /\ redirected \in BOOLEAN

NoSecretToUnallowedHost ==
    "realSecret" \in upstream => request.host \in AllowedHosts

NoSecretToPrivateOrMetadataIP ==
    "realSecret" \in upstream =>
        /\ connected \in checked
        /\ IPAllowed(request, connected)

NoProxyCredentialLeak == "proxyCredential" \notin upstream

NoUnredactedSecretInChildOutput == \A p \in Patterns: ~Contains(p, output)

OnlyScreenedRequestsForward ==
    forwarded =>
        /\ RequestAllowed(request)
        /\ connected \in checked
        /\ \A ip \in checked: IPAllowed(request, ip)

ChunkingMatchesBatch ==
    phase = "done" =>
        output = (IF redirected THEN Scan(header, Len(header), 0).emitted \o <<Separator>>
                  ELSE <<>>) \o Scan(payload, Len(payload), 0).emitted
====
