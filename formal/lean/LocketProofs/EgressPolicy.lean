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

end LocketProofs.EgressPolicy
