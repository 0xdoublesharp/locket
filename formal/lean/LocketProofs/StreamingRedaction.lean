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

/-- The marker tests used by the known-pattern selector. Either containment
would make the marker unsafe, as would a proper suffix/prefix overlap in
either direction. -/
def MarkerSafe (patterns : List Bytes) (marker : Bytes) : Prop :=
  marker ≠ [] ∧ ∀ pattern ∈ patterns,
    ¬pattern <:+: marker ∧ ¬marker <:+: pattern ∧
    (∀ overlap : Bytes, overlap ≠ [] → overlap ≠ marker → overlap ≠ pattern →
      ¬(overlap <:+ pattern ∧ overlap <+: marker) ∧
      ¬(overlap <:+ marker ∧ overlap <+: pattern))

open Classical in
noncomputable def chooseReplacement (patterns : List Bytes) : List Bytes → Option Bytes
  | [] => none
  | candidate :: rest =>
    if MarkerSafe patterns candidate then some candidate else chooseReplacement patterns rest

theorem chooseReplacement_safe (selected : chooseReplacement patterns candidates = some marker) :
    MarkerSafe patterns marker := by
  induction candidates with
  | nil => simp [chooseReplacement] at selected
  | cons candidate rest ih =>
    by_cases safe : MarkerSafe patterns candidate
    · simp [chooseReplacement, safe] at selected
      exact selected ▸ safe
    · exact ih (by simpa [chooseReplacement, safe] using selected)

private theorem prefix_at_marker (safe : MarkerSafe patterns marker) (registered : test ∈ patterns)
    (hit : test <+: left ++ (marker ++ right)) : test <+: left := by
  rcases List.prefix_or_prefix_of_prefix hit (List.prefix_append left (marker ++ right)) with
    within | across
  · exact within
  · obtain ⟨tail, tailEq⟩ := across
    by_cases emptyTail : tail = []
    · simp [emptyTail] at tailEq
      exact tailEq ▸ List.prefix_refl left
    have tailAtStart : tail <+: marker ++ right := by
      rw [← tailEq] at hit
      exact (List.prefix_append_right_inj left).mp hit
    obtain ⟨noInner, noWhole, noOverlap⟩ := safe.2 test registered
    rcases List.prefix_or_prefix_of_prefix tailAtStart (List.prefix_append marker right) with
      short | long
    · have suffix : tail <:+ test := tailEq ▸ List.suffix_append left tail
      by_cases whole : tail = marker
      · exact False.elim (noWhole (whole ▸ suffix.isInfix))
      by_cases starts : tail = test
      · exact False.elim (noInner (starts ▸ short.isInfix))
      exact False.elim ((noOverlap tail emptyTail whole starts).1 ⟨suffix, short⟩)
    · have suffix : tail <:+ test := tailEq ▸ List.suffix_append left tail
      exact False.elim (noWhole (long.isInfix.trans suffix.isInfix))

/-- An occurrence in a splice lies entirely in one of the two retained spans. -/
theorem marker_splice (safe : MarkerSafe patterns marker) (registered : test ∈ patterns) :
    test <:+: left ++ (marker ++ right) ↔ test <:+: left ∨ test <:+: right := by
  refine ⟨?_, ?_⟩
  · induction left with
    | nil =>
      simp only [List.nil_append]
      intro hit
      rcases List.infix_append_iff_ne_nil.mp hit with inside | inside | crossing
      · exact False.elim ((safe.2 test registered).1 inside)
      · exact Or.inr inside
      · obtain ⟨stem, tail, stemNe, tailNe, rfl, stemSuffix, _⟩ := crossing
        obtain ⟨_, noWhole, noOverlap⟩ := safe.2 (stem ++ tail) registered
        by_cases whole : stem = marker
        · exact False.elim (noWhole (whole ▸ (List.prefix_append stem tail).isInfix))
        have proper : stem ≠ stem ++ tail := by
          intro eq
          have := congrArg List.length eq
          simp at this
          exact tailNe this
        exact False.elim ((noOverlap stem stemNe whole proper).2
          ⟨stemSuffix, List.prefix_append stem tail⟩)
    | cons byte left ih =>
      intro hit
      rcases infix_cons_iff.mp hit with atStart | later
      · exact Or.inl (prefix_at_marker safe registered atStart).isInfix
      · exact (ih later).imp (fun h => infix_cons_iff.mpr (Or.inr h)) id
  · rintro (inLeft | inRight)
    · exact List.infix_append_of_infix_left inLeft
    · exact List.infix_append_of_infix_right (List.infix_append_of_infix_right inRight)

private def matchWidth (patterns : List Bytes) (input : Bytes) : Nat :=
  patterns.foldr (fun pattern width => if startsWith pattern input then max pattern.length width
      else width) 0

private def maxPatternLength (patterns : List Bytes) : Nat :=
  patterns.foldr (fun pattern width => max pattern.length width) 0

private theorem matchWidth_lower_bound (registered : pattern ∈ patterns)
    (hit : pattern <+: input) : pattern.length ≤ matchWidth patterns input := by
  induction patterns with
  | nil => simp at registered
  | cons first rest ih =>
    simp only [List.mem_cons] at registered
    rcases registered with rfl | later
    · simp only [matchWidth, List.foldr_cons, startsWith_iff.mpr hit, ite_true]
      exact Nat.le_max_left ..
    · have bounded := ih later
      change _ ≤ (if startsWith first input then max first.length (matchWidth rest input)
                  else matchWidth rest input)
      split
      · exact Nat.le_trans bounded (Nat.le_max_right ..)
      · exact bounded

private theorem matchWidth_append (enough : maxPatternLength patterns ≤ input.length) :
    matchWidth patterns (input ++ rest) = matchWidth patterns input := by
  induction patterns with
  | nil => rfl
  | cons pattern patterns ih =>
    have bounds : pattern.length ≤ input.length ∧ maxPatternLength patterns ≤ input.length := by
      exact Nat.max_le.mp (show max pattern.length (maxPatternLength patterns) ≤ input.length from enough)
    change (if startsWith pattern (input ++ rest) then
      max pattern.length (matchWidth patterns (input ++ rest)) else matchWidth patterns (input ++ rest)) = _
    rw [startsWith_append bounds.1, ih bounds.2]
    rfl

private def multiStep (patterns : List Bytes) (marker : Bytes) (covered : Nat)
    (byte : UInt8) (tail : Bytes) : Nat × Bytes :=
  let width := matchWidth patterns (byte :: tail)
  (max covered width - 1, if covered = 0 then (if width = 0 then [byte] else marker) else [])

def multiScan (patterns : List Bytes) (marker : Bytes) (covered : Nat) : Bytes → Bytes
  | [] => []
  | byte :: tail =>
    let (remaining, emitted) := multiStep patterns marker covered byte tail
    emitted ++ multiScan patterns marker remaining tail

private theorem multi_prefix_preserved (safe : MarkerSafe patterns marker) (registered : test ∈ patterns)
    (hit : test <+: kept ++ multiScan patterns marker 0 input) : test <+: kept ++ input := by
  induction input generalizing kept with
  | nil => exact hit
  | cons byte tail ih =>
    by_cases matched : matchWidth patterns (byte :: tail) = 0
    · have nextHit : test <+: (kept ++ [byte]) ++ multiScan patterns marker 0 tail := by
        simpa [multiScan, multiStep, matched, List.append_assoc] using hit
      simpa [List.append_assoc] using ih nextHit
    · have nextHit : test <+: kept ++ (marker ++ multiScan patterns marker
          (matchWidth patterns (byte :: tail) - 1) tail) := by
        simpa [multiScan, multiStep, matched] using hit
      exact (prefix_at_marker safe registered nextHit).trans (List.prefix_append kept (byte :: tail))

private theorem multiScan_free (safe : MarkerSafe patterns marker) (registered : test ∈ patterns)
    (nonempty : test ≠ []) : ¬test <:+: multiScan patterns marker covered input := by
  induction input generalizing covered with
  | nil => intro hit; exact nonempty (List.infix_nil.mp hit)
  | cons byte tail ih =>
    by_cases openSpan : covered = 0
    · subst covered
      by_cases matched : matchWidth patterns (byte :: tail) = 0
      · have outputEq : multiScan patterns marker 0 (byte :: tail) =
            byte :: multiScan patterns marker 0 tail := by simp [multiScan, multiStep, matched]
        rw [outputEq, infix_cons_iff]
        rintro (atStart | later)
        · have hit : test <+: [] ++ multiScan patterns marker 0 (byte :: tail) := by
            simpa [outputEq] using atStart
          have original : test <+: byte :: tail := by
            simpa using multi_prefix_preserved safe registered hit
          have positive := List.length_pos_iff.mpr nonempty
          have bounded := matchWidth_lower_bound registered original
          omega
        · exact ih later
      · have outputEq : multiScan patterns marker 0 (byte :: tail) = marker ++
            multiScan patterns marker (matchWidth patterns (byte :: tail) - 1) tail := by
          simp [multiScan, multiStep, matched]
        rw [outputEq, ← List.nil_append (marker ++ _), marker_splice safe registered]
        exact fun h => h.elim (fun hit => nonempty (List.infix_nil.mp hit)) ih
    · simpa [multiScan, multiStep, openSpan] using
        ih (covered := max covered (matchWidth patterns (byte :: tail)) - 1)

private def multiFeedByte (patterns : List Bytes) (marker : Bytes) (state : Stream)
    (byte : UInt8) : Stream :=
  let window := state.pending ++ [byte]
  if maxPatternLength patterns ≤ window.length then
    match window with
    | [] => state
    | first :: tail =>
      let (covered, emitted) := multiStep patterns marker state.covered first tail
      ⟨tail, covered, state.output ++ emitted⟩
  else {state with pending := window}

private def multiFinishWith (patterns : List Bytes) (marker : Bytes) (state : Stream)
    (future : Bytes) : Bytes :=
  state.output ++ multiScan patterns marker state.covered (state.pending ++ future)

private theorem multiFeedByte_correct (patterns : List Bytes) (marker : Bytes) (state : Stream)
    (byte : UInt8) (future : Bytes) :
    multiFinishWith patterns marker (multiFeedByte patterns marker state byte) future =
      multiFinishWith patterns marker state (byte :: future) := by
  unfold multiFeedByte multiFinishWith
  rw [show state.pending ++ byte :: future = (state.pending ++ [byte]) ++ future by simp]
  generalize windowEq : state.pending ++ [byte] = window
  by_cases enough : maxPatternLength patterns ≤ window.length
  · simp only [ite_eq_left enough]
    cases window with
    | nil => simp at windowEq
    | cons first tail =>
      have same : matchWidth patterns (first :: (tail ++ future)) = matchWidth patterns (first :: tail) :=
        matchWidth_append enough
      simp [multiScan, multiStep, same, List.append_assoc]
  · simp [enough]

def multiStreaming (patterns : List Bytes) (marker : Bytes) (chunks : List Bytes) : Bytes :=
  let final := chunks.foldl (fun state chunk => chunk.foldl (multiFeedByte patterns marker) state) initial
  multiFinishWith patterns marker final []

private theorem multiFeed_correct (patterns : List Bytes) (marker : Bytes) (input future : Bytes)
    (state : Stream) :
    multiFinishWith patterns marker (input.foldl (multiFeedByte patterns marker) state) future =
      multiFinishWith patterns marker state (input ++ future) := by
  induction input generalizing state with
  | nil => rfl
  | cons byte tail ih =>
    rw [List.foldl_cons, ih, multiFeedByte_correct]
    rfl

theorem multiStreaming_eq_batch (patterns : List Bytes) (marker : Bytes) (chunks : List Bytes) :
    multiStreaming patterns marker chunks = multiScan patterns marker 0 chunks.flatten := by
  have flattenFeed (state : Stream) :
      chunks.foldl (fun s chunk => chunk.foldl (multiFeedByte patterns marker) s) state =
        chunks.flatten.foldl (multiFeedByte patterns marker) state := by
    induction chunks generalizing state with
    | nil => rfl
    | cons chunk chunks ih => simp [List.foldl_append, ih]
  unfold multiStreaming
  rw [flattenFeed, multiFeed_correct]
  simp [multiFinishWith, initial]

theorem multiStreaming_free_of_patterns (safe : MarkerSafe patterns marker)
    (nonempty : ∀ pattern ∈ patterns, pattern ≠ []) (registered : test ∈ patterns) :
    ¬test <:+: multiStreaming patterns marker chunks := by
  rw [multiStreaming_eq_batch]
  exact multiScan_free safe registered (nonempty test registered)

theorem selected_marker_redacts_all (selected : chooseReplacement patterns candidates = some marker)
    (nonempty : ∀ pattern ∈ patterns, pattern ≠ []) (registered : test ∈ patterns) :
    ¬test <:+: multiStreaming patterns marker chunks :=
  multiStreaming_free_of_patterns (chooseReplacement_safe selected) nonempty registered

end LocketProofs.StreamingRedaction
