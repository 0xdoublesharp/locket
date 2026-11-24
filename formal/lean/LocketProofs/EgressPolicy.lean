import Std

namespace LocketProofs.EgressPolicy

abbrev Host := List Char

def canonicalHost (host : Host) : Host :=
  let trimmed := match host.reverse with
    | '.' :: rest => rest.reverse
    | _ => host
  trimmed.map Char.toLower

inductive HostRule where
  | exact (base : Host)
  | wildcard (base : Host)

-- These rules and targets have already passed DNS label or IP literal parsing.
def hostRuleMatches (rule : HostRule) (host : Host) : Bool :=
  match rule with
  | .exact base => host == base
  | .wildcard base =>
    let offset := host.length - base.length
    decide (offset > 1) && (host.take offset).getLast? == some '.' &&
      host.drop offset == base

structure Authority where
  host : Host
  port : UInt16
  deriving DecidableEq

structure AuthorityRule where
  host : HostRule
  port : Option UInt16

def hostAllowed (allowedHosts : List AuthorityRule) (target : Authority) : Bool :=
  allowedHosts.any fun rule =>
    rule.port.all (· == target.port) && hostRuleMatches rule.host target.host

def canonicalAuthority (authority : Authority) : Authority :=
  {authority with host := canonicalHost authority.host}

def authorizeRequest (allowedHosts : List AuthorityRule) (header target : Authority) : Bool :=
  decide (canonicalAuthority header = canonicalAuthority target) &&
    hostAllowed allowedHosts (canonicalAuthority target)

theorem wildcard_excludes_apex (base : Host) : hostRuleMatches (.wildcard base) base = false := by
  simp [hostRuleMatches]

theorem wildcard_prevents_label_suffix_spoof
    (base stem : Host) (missingSeparator : stem.getLast? ≠ some '.') :
    hostRuleMatches (.wildcard base) (stem ++ base) = false := by
  simp [hostRuleMatches, List.length_append, missingSeparator]

theorem empty_allowlist_denies_all (target : Authority) : hostAllowed [] target = false := rfl

theorem host_authority_mismatch_rejected
    (mismatch : canonicalAuthority header ≠ canonicalAuthority target) :
    authorizeRequest allowedHosts header target = false := by
  simp [authorizeRequest, mismatch]

structure IPv4 where
  first : UInt8
  second : UInt8
  third : UInt8
  fourth : UInt8

def loopback (ip : IPv4) : Bool := ip.first == 127
def linkLocal (ip : IPv4) : Bool := ip.first == 169 && ip.second == 254

def rfc1918 (ip : IPv4) : Bool :=
  ip.first == 10 ||
  (ip.first == 172 && ip.second >= 16 && ip.second <= 31) ||
  (ip.first == 192 && ip.second == 168)

def otherSpecialUse (ip : IPv4) : Bool :=
  ip.first == 0 || ip.first >= 224 ||
  (ip.first == 100 && ip.second >= 64 && ip.second <= 127) ||
  (ip.first == 192 && ip.second == 0 && (ip.third == 0 || ip.third == 2)) ||
  (ip.first == 192 && ip.second == 88 && ip.third == 99) ||
  (ip.first == 198 && (ip.second == 18 || ip.second == 19)) ||
  (ip.first == 198 && ip.second == 51 && ip.third == 100) ||
  (ip.first == 203 && ip.second == 0 && ip.third == 113)

-- The private-destination override is limited to loopback with an exact rule.
def permitsIPv4 (allowPrivate exactAllowed : Bool) (ip : IPv4) : Bool :=
  if loopback ip then allowPrivate && exactAllowed
  else !(linkLocal ip || rfc1918 ip || otherSpecialUse ip)

theorem private_ipv4_blocked_by_default (ip : IPv4) (exactAllowed : Bool)
    (privateIP : loopback ip ∨ linkLocal ip ∨ rfc1918 ip) :
    permitsIPv4 false exactAllowed ip = false := by
  rcases privateIP with loop | link | privateAddress
  · simp [permitsIPv4, loop]
  · simp [permitsIPv4, link]
  · simp [permitsIPv4, privateAddress]

/-- The authority parser has already checked DNS labels and decimal ports,
    or parsed a bracketed IPv6 literal into its eight numeric words. -/
inductive ParsedHost where
  | dns (spelling : Host)
  | bracketedIPv6 (words : Vector UInt16 8)

inductive HostKey where
  | dns (name : Host)
  | ipv6 (words : Vector UInt16 8)
  deriving DecidableEq

def ParsedHost.normalize : ParsedHost → HostKey
  | .dns spelling => .dns (canonicalHost spelling)
  | .bracketedIPv6 words => .ipv6 words

structure ParsedAuthority where
  host : ParsedHost
  port : Option UInt16

structure AuthorityKey where
  host : HostKey
  port : UInt16
  deriving DecidableEq

def ParsedAuthority.normalize (authority : ParsedAuthority) (defaultPort : Option UInt16) :
    Option AuthorityKey :=
  (authority.port.or defaultPort).map fun port => ⟨authority.host.normalize, port⟩

inductive ParsedHostRule where
  | exact (base : ParsedHost)
  | wildcard (base : Host)

structure ParsedAuthorityRule where
  host : ParsedHostRule
  port : Option UInt16

def parsedRuleMatches (rule : ParsedAuthorityRule) (target : AuthorityKey) : Bool :=
  rule.port.all (· == target.port) &&
    match rule.host, target.host with
    | .exact base, host => decide (base.normalize = host)
    | .wildcard base, .dns host => hostRuleMatches (.wildcard (canonicalHost base)) host
    | .wildcard _, .ipv6 _ => false

def parsedHostAllowed (rules : List ParsedAuthorityRule) (target : AuthorityKey) : Bool :=
  rules.any fun rule => parsedRuleMatches rule target

private theorem canonicalHost_dot_variant (bare : host.reverse.head? ≠ some '.') (dot : Bool) :
    canonicalHost (if dot then host ++ ['.'] else host) = host.map Char.toLower := by
  cases dot <;> cases reversed : host.reverse with
  | nil =>
    have hostEq : host = [] := by simpa using congrArg List.reverse reversed
    simp [canonicalHost, hostEq]
  | cons first rest =>
    have notDot : first ≠ '.' := by simpa [reversed] using bare
    have hostEq : rest.reverse ++ [first] = host := by
      simpa using congrArg List.reverse reversed.symm
    simp [canonicalHost, List.reverse_append, reversed, notDot, hostEq]

theorem dns_spellings_normalize (leftBare : left.reverse.head? ≠ some '.')
    (rightBare : right.reverse.head? ≠ some '.')
    (sameAsciiFold : left.map Char.toLower = right.map Char.toLower) (leftDot rightDot : Bool) :
    (ParsedHost.dns (if leftDot then left ++ ['.'] else left)).normalize =
      (ParsedHost.dns (if rightDot then right ++ ['.'] else right)).normalize := by
  simp [ParsedHost.normalize, canonicalHost_dot_variant leftBare, canonicalHost_dot_variant rightBare,
    sameAsciiFold]

theorem ipv6_brackets_preserve_address (left right : Vector UInt16 8) :
    (ParsedHost.bracketedIPv6 left).normalize = (ParsedHost.bracketedIPv6 right).normalize ↔
      left = right := by
  simp [ParsedHost.normalize]

theorem default_port_matches_explicit (authority : ParsedAuthority) (port : UInt16)
    (omitted : authority.port = none) :
    authority.normalize (some port) = ({authority with port := some port} : ParsedAuthority).normalize none := by
  simp [ParsedAuthority.normalize, omitted]

theorem canonical_allowlist_equivalence (rules : List ParsedAuthorityRule)
    (left right : ParsedAuthority) (leftDefault rightDefault : Option UInt16)
    (sameHost : left.host.normalize = right.host.normalize)
    (samePort : left.port.or leftDefault = right.port.or rightDefault) :
    (left.normalize leftDefault).any (parsedHostAllowed rules) =
      (right.normalize rightDefault).any (parsedHostAllowed rules) := by
  simp [ParsedAuthority.normalize, sameHost, samePort]

def authorityAgrees (target header : Option AuthorityKey) : Bool :=
  match target, header with
  | some destination, some host => decide (destination = host)
  | _, _ => false

def connectHostAgrees (target header : ParsedAuthority) : Bool :=
  authorityAgrees (target.normalize none) (header.normalize (some 443))

/-- CONNECT needs an explicit target port; an omitted Host port means 443. -/
theorem connect_host_agreement_iff (target header : ParsedAuthority) :
    connectHostAgrees target header = true ↔
      target.host.normalize = header.host.normalize ∧ target.port = some (header.port.getD 443) := by
  cases ht : target.port <;> cases hh : header.port <;>
    simp [connectHostAgrees, authorityAgrees, ParsedAuthority.normalize, ht, hh, AuthorityKey.mk.injEq]

def FramingSafe (value : List Char) : Prop :=
  '\r' ∉ value ∧ '\n' ∉ value ∧ '\x00' ∉ value

def validEgressSecret (secret : List Char) : Bool :=
  !secret.isEmpty && !secret.contains '\r' && !secret.contains '\n' && !secret.contains '\x00'

theorem validEgressSecret_iff (secret : List Char) :
    validEgressSecret secret = true ↔ secret ≠ [] ∧ FramingSafe secret := by
  simp [validEgressSecret, FramingSafe, and_assoc]

def injectEgressSecret (rules : List ParsedAuthorityRule) (target header : Option AuthorityKey)
    (before secret suffix : List Char) : Option (List Char) :=
  if authorityAgrees target header && target.any (parsedHostAllowed rules) && validEgressSecret secret then
    some (before ++ secret ++ suffix)
  else none

/-- Retained request bytes have already passed the parser. A raw substitution
    cannot introduce CR, LF, or NUL, including at either splice boundary. -/
theorem injected_value_has_no_framing (prefixSafe : FramingSafe before) (suffixSafe : FramingSafe suffix)
    (injected : injectEgressSecret rules target header before secret suffix = some value) :
    FramingSafe value := by
  unfold injectEgressSecret at injected
  split at injected
  · rename_i allowed
    have secretSafe := ((validEgressSecret_iff secret).mp (Bool.and_eq_true_iff.mp allowed).2).2
    cases injected
    rcases prefixSafe with ⟨beforeCR, beforeLF, beforeNul⟩
    rcases secretSafe with ⟨secretCR, secretLF, secretNul⟩
    rcases suffixSafe with ⟨afterCR, afterLF, afterNul⟩
    simp [FramingSafe, List.mem_append, beforeCR, beforeLF, beforeNul,
      secretCR, secretLF, secretNul, afterCR, afterLF, afterNul]
  · simp at injected

theorem invalid_egress_secret_rejected (invalid : secret = [] ∨ ¬FramingSafe secret) :
    injectEgressSecret rules target header before secret suffix = none := by
  have bad : validEgressSecret secret = false := by
    cases valid : validEgressSecret secret
    · rfl
    · obtain ⟨nonempty, safe⟩ := (validEgressSecret_iff secret).mp valid
      exact False.elim (invalid.elim nonempty (fun badFraming => badFraming safe))
  simp [injectEgressSecret, bad]

theorem unauthorized_request_never_substitutes
    (denied : authorityAgrees target header = false ∨ target.any (parsedHostAllowed rules) = false) :
    injectEgressSecret rules target header before secret suffix = none := by
  cases denied with
  | inl mismatch => simp [injectEgressSecret, mismatch]
  | inr forbidden => simp [injectEgressSecret, forbidden]

end LocketProofs.EgressPolicy
