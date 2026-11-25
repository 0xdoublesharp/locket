import LocketProofs.AclMatching

namespace LocketProofs.PathScopeAndContract

open Locket.Acl (PathComponent normalizePath)

structure ProjectSelection where
  required : List String
  optional : List String

def ProjectSelection.names (project : ProjectSelection) : List String :=
  project.required ++ project.optional

structure PathScope where
  /-- Normalized relative path components. An empty list denotes the root scope. -/
  path : List String
  profile : Option String
  project : ProjectSelection

def PathScope.depth (scope : PathScope) : Nat := scope.path.length

def scopeMatches (scope : PathScope) (cwd : List PathComponent) : Bool :=
  (normalizePath cwd).any (scope.path.isPrefixOf ·)

private def matchingScopes (scopes : List PathScope) (cwd : List PathComponent) : List PathScope :=
  (scopes.filter (scopeMatches · cwd)).reverse

/-- Rust's max_by_key takes the last maximal entry. Reversing the matching
    list before maxOn? expresses that rule even for unvalidated inputs. -/
def deepestScope (scopes : List PathScope) (cwd : List PathComponent) : Option PathScope :=
  (matchingScopes scopes cwd).maxOn? PathScope.depth

def IsDeepest (scopes : List PathScope) (cwd : List PathComponent) (scope : PathScope) : Prop :=
  scope ∈ scopes ∧ scopeMatches scope cwd = true ∧
    ∀ other ∈ scopes, scopeMatches other cwd = true → other.depth ≤ scope.depth

private theorem mem_matchingScopes :
    scope ∈ matchingScopes scopes cwd ↔ scope ∈ scopes ∧ scopeMatches scope cwd = true := by
  simp [matchingScopes]

private theorem deepestScope_spec (selected : deepestScope scopes cwd = some scope) :
    IsDeepest scopes cwd scope := by
  obtain ⟨member, matched⟩ := mem_matchingScopes.mp (List.maxOn?_mem selected)
  refine ⟨member, matched, fun other present hit => ?_⟩
  have bound := List.le_apply_get_maxOn?_of_mem (f := PathScope.depth)
    (mem_matchingScopes.mpr ⟨present, hit⟩)
  change (matchingScopes scopes cwd).maxOn? PathScope.depth = some scope at selected
  simpa [selected] using bound

private theorem matching_exists (member : scope ∈ scopes) (hit : scopeMatches scope cwd = true) :
    (deepestScope scopes cwd).isSome :=
  List.isSome_maxOn?_of_mem (mem_matchingScopes.mpr ⟨member, hit⟩)

private theorem distinct_paths_injective {scopes : List PathScope}
    (distinct : (scopes.map PathScope.path).Nodup)
    (left : a ∈ scopes) (right : b ∈ scopes) (same : a.path = b.path) : a = b := by
  induction scopes with
  | nil => simp at left
  | cons head rest ih =>
    obtain ⟨fresh, unique⟩ := List.nodup_cons.mp distinct
    rcases List.mem_cons.mp left with rfl | aIn
    · rcases List.mem_cons.mp right with rfl | bIn
      · rfl
      · exact False.elim (fresh (by rw [same]; exact List.mem_map_of_mem bIn))
    · rcases List.mem_cons.mp right with rfl | bIn
      · exact False.elim (fresh (by rw [← same]; exact List.mem_map_of_mem aIn))
      · exact ih unique aIn bIn

private theorem equal_depth_matching_paths
    (left : scopeMatches a cwd = true) (right : scopeMatches b cwd = true)
    (depth : a.depth = b.depth) : a.path = b.path := by
  cases normal : normalizePath cwd with
  | none => simp [scopeMatches, normal] at left
  | some path =>
    have aPrefix : a.path <+: path := by simpa [scopeMatches, normal] using left
    have bPrefix : b.path <+: path := by simpa [scopeMatches, normal] using right
    rw [List.prefix_iff_eq_take.mp aPrefix, List.prefix_iff_eq_take.mp bPrefix]
    exact congrArg (fun n => path.take n) depth

private theorem winner_unique (distinct : (scopes.map PathScope.path).Nodup)
    (left : IsDeepest scopes cwd a) (right : IsDeepest scopes cwd b) : a = b :=
  distinct_paths_injective distinct left.1 right.1
    (equal_depth_matching_paths left.2.1 right.2.1
      (Nat.le_antisymm (right.2.2 a left.1 left.2.1) (left.2.2 b right.1 right.2.1)))

private theorem deepestScope_iff (distinct : (scopes.map PathScope.path).Nodup) :
    deepestScope scopes cwd = some scope ↔ IsDeepest scopes cwd scope := by
  refine ⟨deepestScope_spec, fun winner => ?_⟩
  cases selected : deepestScope scopes cwd with
  | none =>
    have existsMatch := matching_exists winner.1 winner.2.1
    simp [selected] at existsMatch
  | some selectedScope =>
    rw [winner_unique distinct (deepestScope_spec selected) winner]

theorem deepestScope_unique_and_order_independent
    (distinct : (scopes.map PathScope.path).Nodup) (reordered : scopes.Perm other) :
    deepestScope scopes cwd = deepestScope other cwd ∧
      (∀ scope, deepestScope scopes cwd = some scope ↔ IsDeepest scopes cwd scope) ∧
      (deepestScope scopes cwd = none ↔ ∀ scope ∈ scopes, scopeMatches scope cwd = false) := by
  have otherDistinct := (reordered.map PathScope.path).nodup_iff.mp distinct
  have transfer (scope : PathScope) : IsDeepest scopes cwd scope ↔ IsDeepest other cwd scope := by
    simp only [IsDeepest, ← reordered.mem_iff]
  refine ⟨?_, fun _ => deepestScope_iff distinct, ?_⟩
  · cases selected : deepestScope scopes cwd with
    | some scope =>
      exact ((deepestScope_iff otherDistinct).mpr
        ((transfer scope).mp (deepestScope_spec selected))).symm
    | none =>
      cases otherSelected : deepestScope other cwd with
      | none => rfl
      | some scope =>
        have found := (deepestScope_iff distinct).mpr
          ((transfer scope).mpr (deepestScope_spec otherSelected))
        simp [selected] at found
  · constructor
    · intro noMatch scope member
      cases hit : scopeMatches scope cwd with
      | false => rfl
      | true =>
        have found := matching_exists member hit
        simp [noMatch] at found
    · intro noMatch
      cases selected : deepestScope scopes cwd with
      | none => rfl
      | some scope =>
        have found := deepestScope_spec selected
        have matched := found.2.1
        simp [noMatch scope found.1] at matched

private theorem normalize_rejects (present : component ∈ cwd)
    (invalid : normalizePath [component] = none) : normalizePath cwd = none := by
  induction cwd with
  | nil => simp at present
  | cons head rest ih =>
    rcases List.mem_cons.mp present with rfl | later
    · cases component <;> simp_all [normalizePath]
    · cases head <;> simp [normalizePath, ih later]

private theorem normalize_normal_components (path : List String) :
    normalizePath (path.map PathComponent.normal) = some path := by
  induction path with
  | nil => rfl
  | cons head rest ih => simp [normalizePath, ih]

theorem pathScope_rejects_escape :
    (∀ scope cwd, (.parentDir ∈ cwd ∨ .rootDir ∈ cwd ∨ (∃ name, .prefix name ∈ cwd)) →
      scopeMatches scope cwd = false) ∧
    (∀ scope stem expected actual rest, scope.path = stem ++ [expected] → expected ≠ actual →
      scopeMatches scope ((stem ++ actual :: rest).map PathComponent.normal) = false) := by
  constructor
  · intro scope cwd escape
    rcases escape with parent | root | ⟨name, drive⟩
    · simp [scopeMatches, normalize_rejects parent rfl]
    · simp [scopeMatches, normalize_rejects root rfl]
    · simp [scopeMatches, normalize_rejects drive rfl]
  · intro scope stem expected actual rest scopePath different
    simp only [scopeMatches, normalize_normal_components, Option.any_some, scopePath]
    have noPrefix : ¬ (stem ++ [expected]) <+: (stem ++ actual :: rest) := by
      intro isPrefix
      obtain ⟨tail, equal⟩ := List.prefix_iff_exists_append_eq.mp isPrefix
      rw [List.append_assoc] at equal
      have mismatch := List.append_cancel_left equal
      exact different (List.cons.inj mismatch).1
    exact Bool.eq_false_iff.mpr (fun hit => noPrefix (List.isPrefixOf_iff_prefix.mp hit))

structure CommandSelection where
  project : ProjectSelection
  shared : List String

def CommandSelection.names (selection : CommandSelection) : List String :=
  selection.project.names ++ selection.shared

private def mergeProject (command fromScope : ProjectSelection) : ProjectSelection :=
  let required := command.required ++ fromScope.required
  { required, optional := (command.optional ++ fromScope.optional).filter (!required.contains ·) }

private theorem mem_mergeProject :
    name ∈ (mergeProject command fromScope).names ↔
      name ∈ command.names ∨ name ∈ fromScope.names := by
  simp only [mergeProject, ProjectSelection.names, List.mem_append, List.mem_filter,
    Bool.not_eq_true', Bool.eq_false_iff]
  grind

def effectiveProject (command : ProjectSelection) (scopes : List PathScope)
    (cwd : List PathComponent) : ProjectSelection :=
  match deepestScope scopes cwd with
  | none => command
  | some scope => mergeProject command scope.project

private theorem mem_effectiveProject :
    name ∈ (effectiveProject command scopes cwd).names ↔
      name ∈ command.names ∨
        ∃ scope, deepestScope scopes cwd = some scope ∧ name ∈ scope.project.names := by
  cases selected : deepestScope scopes cwd <;>
    simp [effectiveProject, selected, mem_mergeProject]

private def projectNamesInDocument (command : CommandSelection) (scopes : List PathScope) :
    List String :=
  command.project.names ++ scopes.flatMap (·.project.names)

/-- Configuration validation checks shared names against every scope.
    Execution then applies the winning scope and enforces the ACL for all names.
    Lists represent set membership here. Their sort order is irrelevant. -/
def mergeSelections (command : CommandSelection) (scopes : List PathScope)
    (cwd : List PathComponent) (acl : String → Bool) : Option CommandSelection :=
  let selected : CommandSelection := ⟨effectiveProject command.project scopes cwd, command.shared⟩
  if command.shared.any (projectNamesInDocument command scopes).contains then none
  else if selected.names.all acl then some selected else none

theorem sharedSecret_collision_fails_closed
    (command : CommandSelection) (scopes : List PathScope)
    (cwd : List PathComponent) (acl : String → Bool) :
    ((∃ name ∈ command.shared, name ∈ command.project.names ∨
        ∃ scope ∈ scopes, name ∈ scope.project.names) →
      mergeSelections command scopes cwd acl = none) ∧
    (∀ effective, mergeSelections command scopes cwd acl = some effective →
      (∀ name ∈ effective.project.names, acl name = true ∧
        (name ∈ command.project.names ∨
          ∃ scope, deepestScope scopes cwd = some scope ∧ name ∈ scope.project.names)) ∧
      (∀ name ∈ effective.shared, acl name = true ∧ name ∈ command.shared)) := by
  constructor
  · rintro ⟨name, shared, project⟩
    have collision : command.shared.any (projectNamesInDocument command scopes).contains = true :=
      List.any_eq_true.mpr ⟨name, shared, by simpa [projectNamesInDocument] using project⟩
    simp [mergeSelections, collision]
  · intro effective merged
    simp only [mergeSelections] at merged
    split at merged
    · simp at merged
    · split at merged
      · rename_i allowed
        injection merged with equal
        subst effective
        have authorized := List.all_eq_true.mp allowed
        exact ⟨fun name member => ⟨authorized name (List.mem_append_left _ member),
            mem_effectiveProject.mp member⟩,
          fun name member => ⟨authorized name (List.mem_append_right _ member), member⟩⟩
      · simp at merged

inductive VariableContract (Value : Type) where
  | secret
  | publicValue (default : Option Value)

inductive SelectedValue (Value : Type) where
  | resolved (value : Value)
  | publicDefault (value : Value)

/-- Models the caller's ACL check and the contract's fallback step. A resolved
    value represents a value supplied by an earlier authorized source. -/
def evaluateVariable (selection : CommandSelection) (acl : String → Bool) (name : String)
    (resolved : Option Value) (contract : VariableContract Value) : Option (SelectedValue Value) :=
  if selection.names.all acl && selection.names.contains name then
    match resolved with
    | some value => some (.resolved value)
    | none =>
      match contract with
      | .publicValue fallback =>
        if selection.project.names.contains name then fallback.map .publicDefault else none
      | .secret => none
  else none

theorem publicDefault_never_bypasses_secretAcl
    (selection : CommandSelection) (acl : String → Bool) (name : String)
    (resolved : Option Value) (contract : VariableContract Value) :
    ((acl name = false ∨ name ∉ selection.names) →
      evaluateVariable selection acl name resolved contract = none) ∧
    (∀ value, evaluateVariable selection acl name resolved contract = some (.publicDefault value) →
      acl name = true ∧ name ∈ selection.project.names ∧
        resolved = none ∧ contract = .publicValue (some value)) := by
  constructor
  · intro excluded
    unfold evaluateVariable
    split
    · rename_i accepted
      obtain ⟨allowed, member⟩ := Bool.and_eq_true_iff.mp accepted
      have listed := List.contains_iff_mem.mp member
      have authorized := List.all_eq_true.mp allowed name listed
      rcases excluded with denied | unlisted
      · simp [denied] at authorized
      · exact False.elim (unlisted listed)
    · rfl
  · intro value fallback
    unfold evaluateVariable at fallback
    split at fallback
    · rename_i accepted
      obtain ⟨allowed, member⟩ := Bool.and_eq_true_iff.mp accepted
      have authorized := List.all_eq_true.mp allowed name (List.contains_iff_mem.mp member)
      cases resolved <;> cases contract <;> simp_all
    · simp at fallback

end LocketProofs.PathScopeAndContract
