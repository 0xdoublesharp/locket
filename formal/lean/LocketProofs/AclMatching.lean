import Std

namespace Locket.Acl

private inductive ArgToken where
  | globstar
  | token (pattern : String)

-- All ways for a globstar to consume a prefix, including zero and all arguments.
def suffixes : List α → List (List α)
  | [] => [[]]
  | x :: xs => (x :: xs) :: suffixes xs

/-- Existential matching over suffixes. The supplied predicate matches one
    argument against a token glob, independently of the argument boundaries. -/
private def argvSpecTokens (matchToken : String → String → Bool) : List ArgToken → List String → Bool
  | [], argv => argv.isEmpty
  | .globstar :: pattern, argv => (suffixes argv).any (argvSpecTokens matchToken pattern)
  | .token token :: pattern, arg :: argv => matchToken token arg && argvSpecTokens matchToken pattern argv
  | .token _ :: _, [] => false

-- A globstar cell is the OR of the current cell below and its right neighbor.
def headOrFalse : List Bool → Bool
  | [] => false
  | cell :: _ => cell

def globstarRow : List Bool → List Bool
  | [] => []
  | cell :: cells =>
    let right := globstarRow cells
    (cell || headOrFalse right) :: right

-- A token cell reads the diagonal below-right cell. With no argument it fails.
def tokenRow (matchToken : String → Bool) : List String → List Bool → List Bool
  | arg :: argv, next :: below => (matchToken arg && next) :: tokenRow matchToken argv below
  | _, _ => [false]

/-- Each row has one cell per suffix, including the empty suffix. A step
    traverses the previous row once, so the DP uses O(mn + m + n) work, counting
    each token comparison as one operation. -/
private def argvTable (matchToken : String → String → Bool) : List ArgToken → List String → List Bool
  | [], argv => (suffixes argv).map List.isEmpty
  | .globstar :: pattern, argv => globstarRow (argvTable matchToken pattern argv)
  | .token token :: pattern, argv => tokenRow (matchToken token) argv (argvTable matchToken pattern argv).tail

private def argvMatchTokensDP (matchToken : String → String → Bool) (pattern : List ArgToken)
    (argv : List String) : Bool :=
  (argvTable matchToken pattern argv).headD false

private theorem head_globstarRow (cells : List Bool) :
    headOrFalse (globstarRow cells) = cells.any id := by
  induction cells with
  | nil => rfl
  | cons cell cells ih =>
    change (cell || headOrFalse (globstarRow cells)) = (cell || cells.any id)
    rw [ih]

private theorem globstarRow_suffixes (f : List String → Bool) (argv : List String) :
    globstarRow ((suffixes argv).map f) = (suffixes argv).map (fun xs => (suffixes xs).any f) := by
  induction argv with
  | nil => simp [suffixes, globstarRow, headOrFalse]
  | cons arg argv ih =>
    simp only [suffixes, List.map_cons, globstarRow, List.any_cons]
    rw [head_globstarRow, ih, List.any_map]
    rfl

private theorem tokenRow_suffixes (matchToken : String → Bool) (f : List String → Bool)
    (argv : List String) :
    tokenRow matchToken argv ((suffixes argv).map f).tail =
      (suffixes argv).map (fun xs => match xs with
        | [] => false
        | arg :: rest => matchToken arg && f rest) := by
  induction argv with
  | nil => rfl
  | cons arg argv ih =>
    cases argv with
    | nil => rfl
    | cons next rest =>
      simpa [suffixes, tokenRow] using ih

private theorem argvTable_eq (matchToken : String → String → Bool) (pattern : List ArgToken)
    (argv : List String) :
    argvTable matchToken pattern argv = (suffixes argv).map (argvSpecTokens matchToken pattern) := by
  induction pattern with
  | nil => rfl
  | cons head rest ih =>
    cases head with
    | globstar =>
      rw [argvTable, ih, globstarRow_suffixes]
      rfl
    | token tok =>
      rw [argvTable, ih, tokenRow_suffixes]
      congr 1
      funext xs
      cases xs <;> simp [argvSpecTokens]

private theorem argvMatchTokensDP_eq_spec (matchToken : String → String → Bool) (pattern : List ArgToken)
    (argv : List String) :
    argvMatchTokensDP matchToken pattern argv = argvSpecTokens matchToken pattern argv := by
  cases argv <;> simp [argvMatchTokensDP, argvTable_eq, suffixes]

private def tokenizeArg (pattern : String) : ArgToken :=
  if pattern == "**" then .globstar else .token pattern

def argvSpec (matchToken : String → String → Bool) (pattern argv : List String) : Bool :=
  argvSpecTokens matchToken (pattern.map tokenizeArg) argv

def argvMatchDP (matchToken : String → String → Bool) (pattern argv : List String) : Bool :=
  argvMatchTokensDP matchToken (pattern.map tokenizeArg) argv

theorem argvMatchDP_eq_spec (matchToken : String → String → Bool) (pattern argv : List String) :
    argvMatchDP matchToken pattern argv = argvSpec matchToken pattern argv :=
  argvMatchTokensDP_eq_spec matchToken (pattern.map tokenizeArg) argv

inductive PathComponent where
  | normal (name : String)
  | curDir
  | parentDir
  | rootDir
  | prefix (name : String)
  deriving DecidableEq

def normalizePath : List PathComponent → Option (List String)
  | [] => some []
  | .normal name :: rest => (normalizePath rest).map (name :: ·)
  | .curDir :: rest => normalizePath rest
  | .parentDir :: _ | .rootDir :: _ | .prefix _ :: _ => none

def pathMatch (glob : String → String → Bool) (pattern : String)
    (path : List PathComponent) : Bool :=
  match normalizePath path with
  | none => false
  | some components =>
    let relative := if components.isEmpty then "." else String.intercalate "/" components
    if pattern == "." then true
    else if pattern.endsWith "/**" then
      let base := (pattern.dropEnd 3).toString
      relative == base || relative.startsWith (base ++ "/")
    else if pattern.contains '*' then glob pattern relative
    else relative == pattern || relative.startsWith (pattern ++ "/")

private def Forbidden : PathComponent → Prop
  | .parentDir | .rootDir | .prefix _ => True
  | _ => False

private theorem normalization_rejects (present : component ∈ path)
    (invalid : Forbidden component) : normalizePath path = none := by
  induction path with
  | nil => simp at present
  | cons head tail ih =>
    rcases List.mem_cons.mp present with equal | later
    · subst head
      cases component <;> simp_all [Forbidden, normalizePath]
    · cases head <;> simp [normalizePath, ih later]

theorem pathMatch_rejects_parent_dir (present : .parentDir ∈ path) :
    pathMatch glob pattern path = false := by
  simp [pathMatch, normalization_rejects present (by trivial)]

theorem pathMatch_rejects_root_dir (present : .rootDir ∈ path) :
    pathMatch glob pattern path = false := by
  simp [pathMatch, normalization_rejects present (by trivial)]

theorem pathMatch_rejects_prefix (present : .prefix name ∈ path) :
    pathMatch glob pattern path = false := by
  simp [pathMatch, normalization_rejects present (by trivial)]

structure Restrictions where
  commands : List String
  argv : List (List String)
  paths : List String

def allowGate (patterns : List α) (matchToken : α → Bool) : Bool :=
  patterns.isEmpty || patterns.any matchToken

def allows (glob : String → String → Bool) (selected : List String) (secret command : String)
    (acl : Restrictions) (argv : Option (List String)) (cwd : List PathComponent) : Bool :=
  selected.contains secret &&
    (allowGate acl.commands (fun pattern => glob pattern command) &&
      (allowGate acl.argv (fun pattern => argv.any (argvMatchDP glob pattern)) &&
        allowGate acl.paths (fun pattern => pathMatch glob pattern cwd)))

theorem empty_policy_denies_all : allows glob [] secret command acl argv cwd = false := rfl

/-- An empty restriction list is unconstrained. Narrowing an existing gate must
    retain a nonempty subset, or deny the secret in the command allowlist. -/
def GateNarrows (narrow broad : List α) : Prop :=
  broad = [] ∨ (narrow ≠ [] ∧ ∀ p ∈ narrow, p ∈ broad)

private theorem allowGate_mono (narrows : GateNarrows narrow broad)
    (accepted : allowGate narrow matchToken = true) : allowGate broad matchToken = true := by
  rcases narrows with empty | ⟨nonempty, subset⟩
  · simp [allowGate, empty]
  · have hit : narrow.any matchToken = true := by
      cases narrow <;> simp_all [allowGate]
    obtain ⟨pattern, member, passes⟩ := List.any_eq_true.mp hit
    simp [allowGate, List.any_eq_true.mpr ⟨pattern, subset pattern member, passes⟩]

theorem least_privilege_monotonicity
    (selectedSubset : ∀ name ∈ narrowSelected, name ∈ broadSelected)
    (commands : GateNarrows narrow.commands broad.commands)
    (args : GateNarrows narrow.argv broad.argv)
    (paths : GateNarrows narrow.paths broad.paths)
    (accepted : allows glob narrowSelected secret command narrow argv cwd = true) :
    allows glob broadSelected secret command broad argv cwd = true := by
  simp only [allows, Bool.and_eq_true, List.contains_iff_mem] at accepted ⊢
  exact ⟨selectedSubset secret accepted.1, allowGate_mono commands accepted.2.1,
    allowGate_mono args accepted.2.2.1, allowGate_mono paths accepted.2.2.2⟩

end Locket.Acl
