import Std

namespace LocketProofs.AuditWitness

abbrev Project := String
abbrev Digest := Nat
abbrev WitnessKey := Nat
abbrev Nonce := List UInt8

structure WitnessStatement where
  project : Project
  seqNo : Nat
  checkpoint : Digest
  prevReceiptHash : Option Digest
  nonce : Nonce

structure WitnessReceipt where
  statement : WitnessStatement
  witnessKey : WitnessKey
  signature : List UInt8

/-- Signature verification and issuance concern the same pinned key and signed statement. -/
def SigUnforgeable (verify : WitnessKey → WitnessReceipt → Prop)
    (issued : WitnessKey → WitnessStatement → Prop) : Prop :=
  ∀ key receipt, verify key receipt → issued key receipt.statement

def HashInjective (digest : WitnessReceipt → Digest) : Prop :=
  ∀ ⦃left right⦄, digest left = digest right → left = right

def verifyReceipt (verify : WitnessKey → WitnessReceipt → Prop) (digest : WitnessReceipt → Digest)
    (key : WitnessKey) (project : Project) (previous : Option WitnessReceipt)
    (receipt : WitnessReceipt) : Prop :=
  let s := receipt.statement
  s.project = project ∧ receipt.witnessKey = key ∧ verify key receipt ∧
    0 < s.seqNo ∧ s.nonce ≠ [] ∧ s.prevReceiptHash = previous.map digest ∧
    match previous with
    | none => True
    | some prior =>
      prior.statement.project = project ∧ prior.statement.seqNo < s.seqNo ∧
        prior.statement.nonce ≠ s.nonce

/-- Newest receipt first, so each head is checked against its immediate predecessor. -/
def verifyReceiptChain (verify : WitnessKey → WitnessReceipt → Prop)
    (digest : WitnessReceipt → Digest) (key : WitnessKey) (project : Project) :
    List WitnessReceipt → Prop
  | [] => True
  | receipt :: history =>
    verifyReceipt verify digest key project history.head? receipt ∧
      (∀ prior ∈ history, receipt.statement.nonce ≠ prior.statement.nonce) ∧
      verifyReceiptChain verify digest key project history

theorem cross_project_receipt_rejected
    (valid : verifyReceipt verify digest key p₁ previous receipt) (different : p₂ ≠ p₁) :
    ¬verifyReceipt verify digest key p₂ otherPrevious receipt := by
  intro other
  exact different (other.1.symm.trans valid.1)

theorem verified_receipt_was_issued
    (unforgeable : SigUnforgeable verify issued)
    (valid : verifyReceipt verify digest key project previous receipt) :
    issued key receipt.statement :=
  unforgeable key receipt valid.2.2.1

private theorem receipt_chain_pairwise
    (valid : verifyReceiptChain verify digest key project chain) :
    chain.Pairwise (fun later earlier =>
      earlier.statement.seqNo < later.statement.seqNo ∧
      later.statement.nonce ≠ earlier.statement.nonce) := by
  induction chain with
  | nil => exact .nil
  | cons head tail ih =>
    obtain ⟨link, nonce, validTail⟩ := valid
    have ordered := ih validTail
    apply List.pairwise_cons.mpr
    refine ⟨?_, ordered⟩
    intro old mem
    refine ⟨?_, nonce old mem⟩
    cases tail with
    | nil => simp at mem
    | cons previous rest =>
      have advanced : previous.statement.seqNo < head.statement.seqNo :=
        link.2.2.2.2.2.2.2.1
      rcases List.mem_cons.mp mem with rfl | earlier
      · exact advanced
      · exact Nat.lt_trans ((List.pairwise_cons.mp ordered).1 old earlier).1 advanced

/-- In chronological order, every later receipt advances the sequence and uses a distinct nonce. -/
theorem receipt_chain_strictly_monotonic
    (valid : verifyReceiptChain verify digest key project chain)
    (hi : i < chain.reverse.length) (hj : j < chain.reverse.length) (later : i < j) :
    chain.reverse[i].statement.seqNo < chain.reverse[j].statement.seqNo ∧
      chain.reverse[i].statement.nonce ≠ chain.reverse[j].statement.nonce := by
  have ordered := List.pairwise_reverse.mpr (receipt_chain_pairwise valid)
  exact let h := ordered.rel_getElem_of_lt hi hj later; ⟨h.1, Ne.symm h.2⟩

def headDigest (digest : WitnessReceipt → Digest) (chain : List WitnessReceipt) : Option Digest :=
  chain.head?.map digest

theorem receipt_chain_commits_to_history (injective : HashInjective digest)
    (leftValid : verifyReceiptChain verify digest key project left)
    (rightValid : verifyReceiptChain verify digest key project right)
    (sameHead : headDigest digest left = headDigest digest right) : left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp_all [headDigest]
  | cons head tail ih =>
    cases right with
    | nil => simp [headDigest] at sameHead
    | cons otherHead otherTail =>
      have headEq : head = otherHead := injective (Option.some.inj sameHead)
      subst otherHead
      obtain ⟨leftLink, _, leftTail⟩ := leftValid
      obtain ⟨rightLink, _, rightTail⟩ := rightValid
      have samePrevious : headDigest digest tail = headDigest digest otherTail :=
        leftLink.2.2.2.2.2.1.symm.trans rightLink.2.2.2.2.2.1
      rw [ih leftTail rightTail samePrevious]

/-- Compare an authenticated local prefix with the independently verified anchor. -/
def verifyLocalAgainstWitness (tipSeq : Nat) (checkpointAt : Nat → Option Digest)
    (anchor : WitnessStatement) : Prop :=
  anchor.seqNo ≤ tipSeq ∧ checkpointAt anchor.seqNo = some anchor.checkpoint

theorem rollback_below_anchor_rejected (rolledBack : tipSeq < anchor.seqNo) :
    ¬verifyLocalAgainstWitness tipSeq checkpointAt anchor :=
  fun verified => Nat.not_le_of_lt rolledBack verified.1

end LocketProofs.AuditWitness
