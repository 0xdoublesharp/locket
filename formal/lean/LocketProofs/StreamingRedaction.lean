import Std

namespace LocketProofs.StreamingRedaction

abbrev Bytes := List UInt8

def startsWith (pattern input : Bytes) : Bool :=
  pattern == input.take pattern.length

private theorem startsWith_iff : startsWith pattern input = true ↔ pattern <+: input := by
  rw [startsWith, beq_iff_eq]
  exact List.prefix_iff_eq_take.symm

private theorem startsWith_append (enough : pattern.length ≤ input.length) :
    startsWith pattern (input ++ rest) = startsWith pattern input := by
  simp [startsWith, List.take_append_of_le_length enough]

/-- A scan visits every offset, including offsets inside an earlier match.
A fixed replacement can be emitted at the beginning of each intersecting
span because the other covered offsets emit no bytes. -/
def scanStep (pattern replacement : Bytes) (covered : Nat)
    (byte : UInt8) (tail : Bytes) : Nat × Bytes :=
  let matched := startsWith pattern (byte :: tail)
  let width := if matched then max covered pattern.length else covered
  let emitted := if covered = 0 then (if matched then replacement else [byte]) else []
  (width - 1, emitted)

def scan (pattern replacement : Bytes) (covered : Nat) : Bytes → Bytes
  | [] => []
  | byte :: tail =>
    let (remaining, emitted) := scanStep pattern replacement covered byte tail
    emitted ++ scan pattern replacement remaining tail

structure Stream where
  pending : Bytes
  covered : Nat
  output : Bytes

def initial : Stream := ⟨[], 0, []⟩

def feedByte (pattern replacement : Bytes) (state : Stream) (byte : UInt8) : Stream :=
  let window := state.pending ++ [byte]
  if pattern.length ≤ window.length then
    match window with
    | [] => state
    | first :: tail =>
      let (covered, emitted) := scanStep pattern replacement state.covered first tail
      ⟨tail, covered, state.output ++ emitted⟩
  else {state with pending := window}

def feed (pattern replacement : Bytes) (state : Stream) (chunk : Bytes) : Stream :=
  chunk.foldl (feedByte pattern replacement) state

def flush (pattern replacement : Bytes) (state : Stream) : Bytes :=
  state.output ++ scan pattern replacement state.covered state.pending

def streaming (pattern replacement : Bytes) (chunks : List Bytes) : Bytes :=
  flush pattern replacement (chunks.foldl (feed pattern replacement) initial)

def batch (pattern replacement input : Bytes) : Bytes :=
  scan pattern replacement 0 input

theorem feed_preserves_holdback (nonempty : pattern ≠ [])
    (bounded : state.pending.length ≤ pattern.length - 1) :
    (feedByte pattern replacement state byte).pending.length ≤ pattern.length - 1 := by
  have positive : 0 < pattern.length := List.length_pos_iff.mpr nonempty
  simp only [feedByte]
  generalize windowEq : state.pending ++ [byte] = window
  have windowLength : window.length = state.pending.length + 1 := by
    simp [← windowEq]
  split
  · cases window with
    | nil => simp at windowLength
    | cons first tail =>
      simp
      simp at windowLength
      omega
  · rename_i shorter
    simp
    omega

private theorem feed_flatten (pattern replacement : Bytes) (chunks : List Bytes) (state : Stream) :
    chunks.foldl (feed pattern replacement) state =
      feed pattern replacement state chunks.flatten := by
  induction chunks generalizing state with
  | nil => rfl
  | cons chunk chunks ih =>
    simp [feed, List.foldl_append] at ih ⊢
    exact ih _

private def finishWith (pattern replacement : Bytes) (state : Stream) (future : Bytes) : Bytes :=
  state.output ++ scan pattern replacement state.covered (state.pending ++ future)

private theorem feedByte_correct (pattern replacement : Bytes) (state : Stream)
    (byte : UInt8) (future : Bytes) :
    finishWith pattern replacement (feedByte pattern replacement state byte) future =
      finishWith pattern replacement state (byte :: future) := by
  have windowAppend : state.pending ++ byte :: future = (state.pending ++ [byte]) ++ future := by
    simp
  unfold feedByte finishWith
  rw [windowAppend]
  generalize windowEq : state.pending ++ [byte] = window
  by_cases enough : pattern.length ≤ window.length
  · simp only [ite_eq_left enough]
    cases window with
    | nil => simp at windowEq
    | cons first tail =>
      have same : startsWith pattern (first :: (tail ++ future)) =
          startsWith pattern (first :: tail) := startsWith_append enough
      simp [scan, scanStep, same, List.append_assoc]
  · simp [enough]

private theorem feed_correct (pattern replacement chunk future : Bytes) (state : Stream) :
    finishWith pattern replacement (feed pattern replacement state chunk) future =
      finishWith pattern replacement state (chunk ++ future) := by
  induction chunk generalizing state with
  | nil => rfl
  | cons byte tail ih =>
    rw [show feed pattern replacement state (byte :: tail) =
      feed pattern replacement (feedByte pattern replacement state byte) tail from rfl]
    rw [ih, feedByte_correct]
    rfl

theorem streaming_eq_batch (pattern replacement : Bytes) (chunks : List Bytes) :
    streaming pattern replacement chunks =
      flush pattern replacement (feed pattern replacement initial chunks.flatten) ∧
    streaming pattern replacement chunks = batch pattern replacement chunks.flatten := by
  have sameFeed := feed_flatten pattern replacement chunks initial
  refine ⟨congrArg (flush pattern replacement) sameFeed, ?_⟩
  unfold streaming
  rw [sameFeed]
  simpa [finishWith, flush, initial, batch] using
    feed_correct pattern replacement chunks.flatten [] initial

private theorem infix_cons_iff {pattern : Bytes} {byte : UInt8} {tail : Bytes} :
    pattern <:+: (byte :: tail) ↔ pattern <+: (byte :: tail) ∨ pattern <:+: tail := by
  constructor
  · rintro ⟨left, right, eq⟩
    cases left with
    | nil => exact Or.inl ⟨right, by simpa using eq⟩
    | cons first left =>
      exact Or.inr ⟨left, right, (List.cons.inj eq).2⟩
  · rintro (atStart | ⟨left, right, eq⟩)
    · exact atStart.isInfix
    · exact ⟨byte :: left, right, congrArg (byte :: ·) eq⟩

private theorem clean_scan_identity (clean : ¬pattern <:+: input) :
    scan pattern replacement 0 input = input := by
  induction input with
  | nil => rfl
  | cons byte tail ih =>
    have noStart : startsWith pattern (byte :: tail) = false := by
      cases h : startsWith pattern (byte :: tail)
      · rfl
      · exact False.elim (clean (startsWith_iff.mp h).isInfix)
    have cleanTail : ¬pattern <:+: tail := fun h => clean (infix_cons_iff.mpr (Or.inr h))
    simp [scan, scanStep, noStart, ih cleanTail]

theorem clean_stream_identity (clean : ¬pattern <:+: chunks.flatten) :
    streaming pattern replacement chunks = chunks.flatten :=
  (streaming_eq_batch pattern replacement chunks).2.trans (clean_scan_identity clean)

private theorem marker_blocks_prefix (nonempty : test ≠ []) (disjoint : marker ∉ test) :
    ¬test <+: (marker :: tail) := by
  intro h
  cases test with
  | nil => exact nonempty rfl
  | cons first rest =>
    obtain ⟨suffix, eq⟩ := h
    exact disjoint (by simp [(List.cons.inj eq).1])

-- An output prefix containing no marker consists of the same bytes at the input start.
private theorem unmarked_prefix_preserved (disjoint : marker ∉ test)
    (atStart : test <+: scan pattern [marker] 0 input) :
    test <+: input := by
  induction input generalizing test with
  | nil => exact atStart
  | cons byte tail ih =>
    cases test with
    | nil => exact List.nil_prefix
    | cons first rest =>
      cases matched : startsWith pattern (byte :: tail)
      · simp [scan, scanStep, matched] at atStart
        obtain ⟨same, suffix⟩ := atStart
        have disjointTail : marker ∉ rest := fun mem => disjoint (by simp [mem])
        exact List.cons_prefix_cons.mpr ⟨same, ih disjointTail suffix⟩
      · have marked : (first :: rest) <+: (marker :: scan pattern [marker]
            (pattern.length - 1) tail) := by
          simpa [scan, scanStep, matched] using atStart
        exact False.elim (marker_blocks_prefix (by simp) disjoint marked)

private theorem scan_free_of_pattern (nonempty : pattern ≠ []) (disjoint : marker ∉ pattern) :
    ¬pattern <:+: scan pattern [marker] covered input := by
  induction input generalizing covered with
  | nil =>
    intro occurrence
    exact nonempty (List.infix_nil.mp occurrence)
  | cons byte tail ih =>
    by_cases openSpan : covered = 0
    · subst covered
      cases matched : startsWith pattern (byte :: tail)
      · have scanEq : scan pattern [marker] 0 (byte :: tail) =
            byte :: scan pattern [marker] 0 tail := by simp [scan, scanStep, matched]
        rw [scanEq, infix_cons_iff]
        rintro (starts | later)
        · have inInput := unmarked_prefix_preserved (input := byte :: tail) disjoint
            (by rwa [scanEq])
          rw [startsWith_iff.mpr inInput] at matched
          contradiction
        · exact ih later
      · simp [scan, scanStep, matched, infix_cons_iff,
              marker_blocks_prefix nonempty disjoint, ih]
    · simpa [scan, scanStep, openSpan] using
        ih (covered := (if startsWith pattern (byte :: tail)
                        then max covered pattern.length else covered) - 1)

theorem redacted_output_free_of_pattern (nonempty : pattern ≠ []) (disjoint : marker ∉ pattern) :
    ¬pattern <:+: streaming pattern [marker] chunks := by
  rw [(streaming_eq_batch pattern [marker] chunks).2]
  exact scan_free_of_pattern nonempty disjoint

end LocketProofs.StreamingRedaction
