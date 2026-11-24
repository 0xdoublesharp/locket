import Std

namespace Locket.Sources

inductive SecretSource where
  | teamManaged
  | userLocal
  | machineLocal
  deriving DecidableEq

def rank : SecretSource → Nat
  | .teamManaged => 1
  | .userLocal => 2
  | .machineLocal => 3

def precedes (a b : SecretSource) : Prop := rank a < rank b

theorem precedence_irrefl (source : SecretSource) : ¬ precedes source source := Nat.lt_irrefl _

theorem precedence_trans (ab : precedes a b) (bc : precedes b c) : precedes a c :=
  Nat.lt_trans ab bc

private theorem rank_injective (equal : rank a = rank b) : a = b := by
  cases a <;> cases b <;> simp_all [rank]

theorem precedence_trichotomy (a b : SecretSource) :
    precedes a b ∨ a = b ∨ precedes b a := by
  rcases Nat.lt_trichotomy (rank a) (rank b) with lt | eq | gt
  · exact Or.inl lt
  · exact Or.inr (Or.inl (rank_injective eq))
  · exact Or.inr (Or.inr gt)

inductive SecretState where
  | active
  | deleted
  deriving DecidableEq

inductive VersionState where
  | current
  | deprecated (graceUntil : Option Nat)
  | purged

structure Version where
  number : Nat
  state : VersionState

structure SecretRow where
  source : SecretSource
  state : SecretState
  currentVersion : Nat
  versions : List Version

/-- As in the SQL uniqueness constraint, candidates are for one logical secret.
    The resolver's first-on-tie behavior is immaterial with unique sources. -/
def UniqueActiveSources (rows : List SecretRow) : Prop :=
  ∀ a ∈ rows, ∀ b ∈ rows, a.state = .active → b.state = .active → a.source = b.source → a = b

def selectWinner : List SecretRow → Option SecretRow
  | [] => none
  | row :: rows =>
    let best := selectWinner rows
    if row.state = .active then
      match best with
      | none => some row
      | some other => if rank other.source ≤ rank row.source then some row else best
    else best

def IsWinner (rows : List SecretRow) (row : SecretRow) : Prop :=
  row ∈ rows ∧ row.state = .active ∧
    ∀ other ∈ rows, other.state = .active → rank other.source ≤ rank row.source

theorem selectWinner_spec (rows : List SecretRow) :
    match selectWinner rows with
    | none => ∀ row ∈ rows, row.state ≠ .active
    | some row => IsWinner rows row := by
  induction rows with
  | nil => simp [selectWinner]
  | cons head tail ih =>
    cases hbest : selectWinner tail with
    | none =>
      rw [hbest] at ih
      by_cases active : head.state = .active
      · simp only [selectWinner, hbest, ite_eq_left active]
        refine ⟨List.mem_cons_self, active, ?_⟩
        intro row member live
        rcases List.mem_cons.mp member with equal | later
        · simp [equal]
        · exact False.elim (ih row later live)
      · simp only [selectWinner, hbest, ite_eq_right active]
        intro row member
        rcases List.mem_cons.mp member with equal | later
        · simpa [equal] using active
        · exact ih row later
    | some best =>
      rw [hbest] at ih
      obtain ⟨member, live, outranks⟩ := ih
      by_cases active : head.state = .active
      · by_cases higher : rank best.source ≤ rank head.source
        · simp only [selectWinner, hbest, ite_eq_left active, ite_eq_left higher]
          refine ⟨List.mem_cons_self, active, ?_⟩
          intro row inRows rowActive
          rcases List.mem_cons.mp inRows with equal | later
          · simp [equal]
          · exact Nat.le_trans (outranks row later rowActive) higher
        · simp only [selectWinner, hbest, ite_eq_left active, ite_eq_right higher]
          refine ⟨List.mem_cons_of_mem _ member, live, ?_⟩
          intro row inRows rowActive
          rcases List.mem_cons.mp inRows with equal | later
          · rw [equal]
            omega
          · exact outranks row later rowActive
      · simp only [selectWinner, hbest, ite_eq_right active]
        refine ⟨List.mem_cons_of_mem _ member, live, ?_⟩
        intro row inRows rowActive
        rcases List.mem_cons.mp inRows with equal | later
        · exact False.elim (active (equal ▸ rowActive))
        · exact outranks row later rowActive

theorem winner_unique (unique : UniqueActiveSources rows)
    (left : IsWinner rows a) (right : IsWinner rows b) : a = b := by
  obtain ⟨aMember, aActive, aHighest⟩ := left
  obtain ⟨bMember, bActive, bHighest⟩ := right
  exact unique a aMember b bMember aActive bActive
    (rank_injective (Nat.le_antisymm (bHighest a aMember aActive) (aHighest b bMember bActive)))

theorem selectWinner_iff (unique : UniqueActiveSources rows) :
    selectWinner rows = some row ↔ IsWinner rows row := by
  have spec := selectWinner_spec rows
  cases h : selectWinner rows with
  | none =>
    rw [h] at spec
    exact ⟨by simp, fun winner => False.elim (spec row winner.1 winner.2.1)⟩
  | some best =>
    rw [h] at spec
    constructor
    · intro equal
      cases equal
      exact spec
    · intro winner
      rw [winner_unique unique spec winner]

theorem selectWinner_permutation (perm : rows.Perm other) (unique : UniqueActiveSources rows) :
    selectWinner rows = selectWinner other := by
  have otherUnique : UniqueActiveSources other :=
    fun a ha b hb => unique a (perm.mem_iff.mpr ha) b (perm.mem_iff.mpr hb)
  have transfer (row : SecretRow) : IsWinner rows row ↔ IsWinner other row := by
    constructor
    · intro ⟨member, live, higher⟩
      exact ⟨perm.mem_iff.mp member, live, fun r hr => higher r (perm.mem_iff.mpr hr)⟩
    · intro ⟨member, live, higher⟩
      exact ⟨perm.mem_iff.mpr member, live, fun r hr => higher r (perm.mem_iff.mp hr)⟩
  cases h : selectWinner rows with
  | some row => exact ((selectWinner_iff otherUnique).mpr
      ((transfer row).mp ((selectWinner_iff unique).mp h))).symm
  | none =>
    cases hother : selectWinner other with
    | none => rfl
    | some row =>
      have left := (selectWinner_iff unique).mpr
        ((transfer row).mpr ((selectWinner_iff otherUnique).mp hother))
      rw [h] at left
      contradiction

theorem higher_active_source_shadows (winner : IsWinner rows lower)
    (member : higher ∈ rows) (active : higher.state = .active)
    (higherRank : precedes lower.source higher.source) : False :=
  Nat.not_lt_of_ge (winner.2.2 higher member active) higherRank

def selectVersion (now : Nat) (pin : Option Nat) (row : SecretRow) : Option Version :=
  row.versions.find? (fun version =>
    version.number == pin.getD row.currentVersion &&
      match version.state with
      | .current => true
      | .deprecated deadline => pin.isSome && deadline.any (fun deadline => now < deadline)
      | .purged => false)

def resolveSecret (rows : List SecretRow) (now : Nat) (pin : Option Nat) :
    Option (SecretRow × Version) := do
  let row ← selectWinner rows
  let version ← selectVersion now pin row
  pure (row, version)

theorem resolveSecret_permutation (perm : rows.Perm other) (unique : UniqueActiveSources rows) :
    resolveSecret rows now pin = resolveSecret other now pin := by
  unfold resolveSecret
  rw [selectWinner_permutation perm unique]

theorem tombstone_never_shadows (deleted : tombstone.state = .deleted) :
    resolveSecret (tombstone :: rows) now pin = resolveSecret rows now pin := by
  simp [resolveSecret, selectWinner, deleted]

theorem resolveSecret_selects_winner (found : resolveSecret rows now pin = some (row, version)) :
    IsWinner rows row ∧ selectVersion now pin row = some version := by
  cases winner : selectWinner rows with
  | none => simp [resolveSecret, winner] at found
  | some best =>
    cases selected : selectVersion now pin best with
    | none => simp [resolveSecret, winner, selected] at found
    | some chosen =>
      simp [resolveSecret, winner, selected] at found
      obtain ⟨rfl, rfl⟩ := found
      exact ⟨by simpa [winner] using selectWinner_spec rows, selected⟩

theorem unpinned_returns_current (selected : selectVersion now none row = some version) :
    version.state = .current := by
  have yes := List.find?_some selected
  cases state : version.state <;> simp_all

theorem pinned_deprecated_iff (unique : ∀ a ∈ row.versions, ∀ b ∈ row.versions,
      a.number = b.number → a = b)
    (member : version ∈ row.versions) (state : version.state = .deprecated (some deadline)) :
    selectVersion now (some version.number) row = some version ↔ now < deadline := by
  constructor
  · intro found
    simpa [state] using List.find?_some found
  · intro fresh
    have existsFound : (selectVersion now (some version.number) row).isSome = true := by
      unfold selectVersion
      rw [List.isSome_find?, List.any_eq_true]
      exact ⟨version, member, by simp [state, fresh]⟩
    cases found : selectVersion now (some version.number) row with
    | none => simp [found] at existsFound
    | some picked =>
      have yes := List.find?_some found
      simp only [Option.getD_some, Bool.and_eq_true, beq_iff_eq] at yes
      exact congrArg some (unique picked (List.mem_of_find?_eq_some found) version member yes.1)

theorem purged_never_resolves (state : version.state = .purged) :
    selectVersion now pin row ≠ some version := by
  intro found
  simpa [state] using List.find?_some found

end Locket.Sources
