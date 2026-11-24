import Std

namespace Locket.Audit

/-- The body represents the canonical encoding of the other authenticated fields. -/
structure RowPayload (Body Digest : Type) where
  seq : Nat
  prev : Digest
  body : Body

structure AuditRow (Body Digest : Type) where
  payload : RowPayload Body Digest
  tag : Digest

structure CheckpointPayload (Digest : Type) where
  project : String
  seq : Nat
  rowTag : Digest

structure Checkpoint (Digest : Type) where
  payload : CheckpointPayload Digest
  tag : Digest

/-- Distinct signing domains for rows and version-1 checkpoints. -/
inductive Payload (Body Digest : Type) where
  | row (fields : RowPayload Body Digest)
  | checkpoint (fields : CheckpointPayload Digest)

variable {Key Body Digest : Type}

/-- An idealized MAC assumption used for symbolic reasoning. It does not assert
    mathematical injectivity of fixed-width HMAC over unrestricted inputs. -/
def MacInjective (mac : Key → Payload Body Digest → Digest) : Prop :=
  ∀ {k₁ k₂ input₁ input₂}, mac k₁ input₁ = mac k₂ input₂ → k₁ = k₂ ∧ input₁ = input₂

def verifyChainFrom (mac : Key → Payload Body Digest → Digest) (key : Key)
    (seq : Nat) (prev : Digest) : List (AuditRow Body Digest) → Prop
  | [] => True
  | row :: rest =>
    row.payload.seq = seq ∧ row.payload.prev = prev ∧
      row.tag = mac key (.row row.payload) ∧ verifyChainFrom mac key (seq + 1) row.tag rest

def verifyChain (mac : Key → Payload Body Digest → Digest) (key : Key) (genesis : Digest)
    (rows : List (AuditRow Body Digest)) : Prop :=
  verifyChainFrom mac key 1 genesis rows

def verifyAgainstCheckpoint (mac : Key → Payload Body Digest → Digest) (key : Key)
    (genesis : Digest) (project : String) (rows : List (AuditRow Body Digest))
    (checkpoint : Checkpoint Digest) : Prop :=
  verifyChain mac key genesis rows ∧ checkpoint.payload.project = project ∧
    checkpoint.tag = mac key (.checkpoint checkpoint.payload) ∧
    0 < checkpoint.payload.seq ∧
    rows[checkpoint.payload.seq - 1]?.map AuditRow.tag = some checkpoint.payload.rowTag

variable {mac : Key → Payload Body Digest → Digest}

private def LinksPrevious (prev : Digest) (rows : List (AuditRow Body Digest))
    (index : Nat) (row : AuditRow Body Digest) : Prop :=
  match index with
  | 0 => row.payload.prev = prev
  | n + 1 => ∃ previous, rows[n]? = some previous ∧ row.payload.prev = previous.tag

private theorem chain_links (verified : verifyChainFrom mac key seq prev rows)
    (found : rows[index]? = some row) :
    row.payload.seq = seq + index ∧ LinksPrevious prev rows index row := by
  induction rows generalizing seq prev index with
  | nil => simp at found
  | cons head rest ih =>
    obtain ⟨headSeq, headPrev, _, restVerifies⟩ := verified
    cases index with
    | zero =>
      simp at found
      subst row
      exact ⟨headSeq, headPrev⟩
    | succ index =>
      have ⟨number, link⟩ := ih restVerifies found
      constructor
      · omega
      · cases index with
        | zero => exact ⟨head, rfl, link⟩
        | succ next => exact link

theorem verifyChain_implies_consecutive_seq
    (verified : verifyChain mac key genesis rows) (found : rows[index]? = some row) :
    row.payload.seq = index + 1 ∧
      (if index = 0 then row.payload.prev = genesis else
        ∃ previous, rows[index - 1]? = some previous ∧ row.payload.prev = previous.tag) := by
  have ⟨number, link⟩ := chain_links verified found
  refine ⟨by omega, ?_⟩
  cases index <;> simpa [LinksPrevious] using link

private theorem row_eq_of_tag_eq {a b : AuditRow Body Digest} (injective : MacInjective mac)
    (left : a.tag = mac key (.row a.payload)) (right : b.tag = mac key (.row b.payload))
    (tags : a.tag = b.tag) : a = b := by
  have inputs := (injective (left.symm.trans (tags.trans right))).2
  cases a
  cases b
  cases Payload.row.inj inputs
  cases tags
  rfl

private theorem anchored_prefix_eq (injective : MacInjective mac)
    (left : verifyChainFrom mac key seq prevA rowsA)
    (right : verifyChainFrom mac key seq prevB rowsB)
    (anchorA : rowsA[index]?.map AuditRow.tag = some anchor)
    (anchorB : rowsB[index]?.map AuditRow.tag = some anchor) :
    rowsA.take (index + 1) = rowsB.take (index + 1) := by
  induction index generalizing seq prevA prevB rowsA rowsB with
  | zero =>
    cases rowsA with
    | nil => simp at anchorA
    | cons headA tailA =>
      cases rowsB with
      | nil => simp at anchorB
      | cons headB tailB =>
        have tags : headA.tag = headB.tag := by simpa using anchorA.trans anchorB.symm
        simp [row_eq_of_tag_eq injective left.2.2.1 right.2.2.1 tags]
  | succ index ih =>
    cases rowsA with
    | nil => simp at anchorA
    | cons headA tailA =>
      cases rowsB with
      | nil => simp at anchorB
      | cons headB tailB =>
        have tailEqual := ih left.2.2.2 right.2.2.2 anchorA anchorB
        cases tailA with
        | nil => simp at anchorA
        | cons nextA restA =>
          cases tailB with
          | nil => simp at anchorB
          | cons nextB restB =>
            have nextEqual : nextA = nextB := by
              have equalHeads := congrArg List.head? tailEqual
              simpa using equalHeads
            have tags : headA.tag = headB.tag :=
              left.2.2.2.2.1.symm.trans (nextEqual ▸ right.2.2.2.2.1)
            have heads := row_eq_of_tag_eq injective left.2.2.1 right.2.2.1 tags
            simpa only [List.take_succ_cons, heads] using congrArg (headB :: ·) tailEqual

theorem checkpoint_commits_to_prefix (injective : MacInjective mac)
    (original : verifyAgainstCheckpoint mac key genesis project rows checkpoint)
    (candidate : verifyAgainstCheckpoint mac key genesis project changed checkpoint) :
    rows.take checkpoint.payload.seq = changed.take checkpoint.payload.seq := by
  have positive := original.2.2.2.1
  have size : checkpoint.payload.seq - 1 + 1 = checkpoint.payload.seq := by omega
  simpa only [size] using anchored_prefix_eq injective original.1 candidate.1
    original.2.2.2.2 candidate.2.2.2.2

/-- A retained checkpoint detects every change through its anchored sequence,
    including replacement and re-signing, and every truncation below it. -/
theorem tamper_detection (injective : MacInjective mac)
    (original : verifyAgainstCheckpoint mac key genesis project rows checkpoint)
    (tampered : changed.length < checkpoint.payload.seq ∨
      changed.take checkpoint.payload.seq ≠ rows.take checkpoint.payload.seq) :
    ¬ verifyAgainstCheckpoint mac key genesis project changed checkpoint := by
  intro verifies
  rcases tampered with short | altered
  · have missing : changed[checkpoint.payload.seq - 1]? = none := by
      apply List.getElem?_eq_none
      omega
    have anchored := verifies.2.2.2.2
    simp [missing] at anchored
  · exact altered (checkpoint_commits_to_prefix injective original verifies).symm

theorem key_separation_rejects_master_key (injective : MacInjective mac)
    (distinct : kMaster ≠ kAudit) (signed : row.tag = mac kMaster (.row row.payload)) :
    ¬ verifyChainFrom mac kAudit seq prev (row :: rest) := by
  intro verifies
  exact distinct (injective (signed.symm.trans verifies.2.2.1)).1

end Locket.Audit
