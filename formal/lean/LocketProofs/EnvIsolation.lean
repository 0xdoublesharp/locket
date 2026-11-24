import Std

namespace LocketProofs.EnvIsolation

inductive EnvMode where
  | strict | minimal | merge | passthrough
  deriving DecidableEq

inductive EnvOverrideMode where
  | locket | preserve | error
  deriving DecidableEq

abbrev Env := List (String × String)
abbrev Lookup := String → Option String

def allowlistMatches (pattern name : String) : Bool :=
  match pattern.toList.reverse with
  | '*' :: stem => stem.reverse.isPrefixOf name.toList
  | _ => pattern == name

def safeAllowlist (rules : List String) (name : String) : Bool :=
  rules.any (allowlistMatches · name)

def parentAllowed (mode : EnvMode) (rules inheritEnv : List String) (name : String) : Bool :=
  inheritEnv.contains name ||
    match mode with
    | .strict => false
    | .minimal => safeAllowlist rules name
    | .merge | .passthrough => true

def baseEnv (mode : EnvMode) (rules inheritEnv : List String) (parent external : Env) : Lookup :=
  fun name => (external.lookup name).orElse fun _ =>
    if parentAllowed mode rules inheritEnv name then parent.lookup name else none

def mergeEnvironment (mode : EnvMode) (overrideMode : EnvOverrideMode) (rules inheritEnv : List String)
    (parent external locket : Env) : Option Lookup :=
  let base := baseEnv mode rules inheritEnv parent external
  match overrideMode with
  | .locket => some fun name => (locket.lookup name).orElse fun _ => base name
  | .preserve => some fun name => (base name).orElse fun _ => locket.lookup name
  | .error =>
    if locket.any (fun entry => (base entry.1).isSome) then none
    else some fun name => (base name).orElse fun _ => locket.lookup name

private theorem absent_key_stays_absent
    (merged : mergeEnvironment mode policy rules inheritEnv parent external locket = some child)
    (noBase : baseEnv mode rules inheritEnv parent external name = none)
    (noLocket : locket.lookup name = none) : child name = none := by
  cases policy <;> simp [mergeEnvironment] at merged
  · rw [← merged]
    simp [noBase, noLocket]
  · rw [← merged]
    simp [noBase, noLocket]
  · rw [← merged.2]
    simp [noBase, noLocket]

theorem strict_mode_no_parent_leak
    (merged : mergeEnvironment .strict policy rules inheritEnv parent external locket = some child)
    (present : child name = some value) :
    name ∈ inheritEnv ∨ (external.lookup name).isSome ∨ (locket.lookup name).isSome := by
  apply Classical.byContradiction
  intro absent
  have hInherit : name ∉ inheritEnv := fun h => absent (Or.inl h)
  have hExternal : ¬(external.lookup name).isSome := fun h => absent (Or.inr (Or.inl h))
  have hLocket : ¬(locket.lookup name).isSome := fun h => absent (Or.inr (Or.inr h))
  have externalNone : external.lookup name = none := by
    cases eq : external.lookup name with
    | none => rfl
    | some v => exact False.elim (hExternal (by rw [eq]; rfl))
  have locketNone : locket.lookup name = none := by
    cases eq : locket.lookup name with
    | none => rfl
    | some v => exact False.elim (hLocket (by rw [eq]; rfl))
  have baseNone : baseEnv .strict rules inheritEnv parent external name = none := by
    simp [baseEnv, parentAllowed, externalNone, hInherit]
  rw [absent_key_stays_absent merged baseNone locketNone] at present
  contradiction

theorem minimal_mode_parent_bounded
    (merged : mergeEnvironment .minimal policy rules inheritEnv parent external locket = some child)
    (present : child name = some value)
    (noExternal : external.lookup name = none) (noLocket : locket.lookup name = none) :
    safeAllowlist rules name ∨ name ∈ inheritEnv := by
  apply Classical.byContradiction
  intro absent
  have hSafe : ¬safeAllowlist rules name := fun h => absent (Or.inl h)
  have hInherit : name ∉ inheritEnv := fun h => absent (Or.inr h)
  have baseNone : baseEnv .minimal rules inheritEnv parent external name = none := by
    simp [baseEnv, parentAllowed, noExternal, hSafe, hInherit]
  rw [absent_key_stays_absent merged baseNone noLocket] at present
  contradiction

theorem override_error_rejects_conflict
    (ext : external.lookup name = some value) (secret : (name, secretValue) ∈ locket) :
    mergeEnvironment mode .error rules inheritEnv parent external locket = none := by
  have conflict : locket.any (fun entry =>
      (baseEnv mode rules inheritEnv parent external entry.1).isSome) = true := by
    rw [List.any_eq_true]
    exact ⟨(name, secretValue), secret, by simp [baseEnv, ext]⟩
  simp [mergeEnvironment, conflict]

theorem override_locket_precedence
    (merged : mergeEnvironment mode .locket rules inheritEnv parent external locket = some child)
    (secret : locket.lookup name = some value) : child name = some value := by
  injection merged with equal
  subst child
  simp [secret]

def lineByte (c : Char) : Prop :=
  c ≠ '\n' ∧ c ≠ '\r' ∧ c ≠ '\x00'

def validateEnv (name value : List Char) : Prop :=
  name ≠ [] ∧ (∀ c ∈ name, lineByte c ∧ c ≠ '=') ∧ ∀ c ∈ value, lineByte c

def serializeLine (name value : List Char) : List Char :=
  name ++ '=' :: value

def splitLine : List Char → Option (List Char × List Char)
  | [] => none
  | c :: tail =>
    if c = '=' then some ([], tail)
    else (splitLine tail).map fun (name, value) => (c :: name, value)

private theorem splitLine_serialize (noEqual : '=' ∉ name) :
    splitLine (serializeLine name value) = some (name, value) := by
  induction name with
  | nil => rfl
  | cons c tail ih =>
    have hc : c ≠ '=' := fun eq => noEqual (by simp [eq])
    have ht : '=' ∉ tail := fun mem => noEqual (by simp [mem])
    simp [serializeLine] at ih ⊢
    simp [splitLine, hc, ih ht]

theorem validated_env_line_no_injection (valid : validateEnv name value) :
    (∀ c ∈ name, lineByte c ∧ c ≠ '=') ∧ (∀ c ∈ value, lineByte c) ∧
    (∀ c ∈ serializeLine name value, lineByte c) ∧
    splitLine (serializeLine name value) = some (name, value) := by
  obtain ⟨_, nameValid, valueValid⟩ := valid
  refine ⟨nameValid, valueValid, ?_, splitLine_serialize (fun mem => (nameValid '=' mem).2 rfl)⟩
  intro c mem
  simp only [serializeLine, List.mem_append, List.mem_cons] at mem
  rcases mem with inName | rfl | inValue
  · exact (nameValid c inName).1
  · simp [lineByte]
  · exact valueValid c inValue

end LocketProofs.EnvIsolation
