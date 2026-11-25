import Std

namespace LocketProofs.CryptoDomainSeparation

abbrev Bytes := List UInt8

private def utf8 (value : String) : Bytes := value.toUTF8.data.toList

private def encodeLE : Nat → Nat → Bytes
  | 0, _ => []
  | width + 1, value => UInt8.ofNat value :: encodeLE width (value / 256)

private def decodeLE : Bytes → Nat
  | [] => 0
  | byte :: rest => byte.toNat + 256 * decodeLE rest

private theorem encodeLE_length (width value : Nat) : (encodeLE width value).length = width := by
  induction width generalizing value with
  | zero => rfl
  | succ width ih => simp [encodeLE, ih]

private theorem decodeLE_encodeLE (fits : value < 256 ^ width) :
    decodeLE (encodeLE width value) = value := by
  induction width generalizing value with
  | zero =>
    have zero : value = 0 := by simp at fits; omega
    simp [zero, encodeLE, decodeLE]
  | succ width ih =>
    have quotientFits : value / 256 < 256 ^ width :=
      (Nat.div_lt_iff_lt_mul (by decide)).mpr (by simpa [Nat.pow_succ] using fits)
    simpa only [encodeLE, decodeLE, UInt8.toNat_ofNat', ih quotientFits]
      using Nat.mod_add_div value 256

private theorem encodeLE_injective (leftFits : left < 256 ^ width)
    (rightFits : right < 256 ^ width) (same : encodeLE width left = encodeLE width right) :
    left = right := by
  simpa only [decodeLE_encodeLE leftFits, decodeLE_encodeLE rightFits]
    using congrArg decodeLE same

/-- Values that pass the Rust encoder's checked conversion to a length prefix. -/
abbrev BoundedBytes (width : Nat) := {bytes : Bytes // bytes.length < 256 ^ width}

abbrev Field := BoundedBytes 2 × BoundedBytes 4

private def frame (value : BoundedBytes width) (rest : Bytes) : Bytes :=
  encodeLE width value.val.length ++ (value.val ++ rest)

private theorem frame_injective (left right : BoundedBytes width) (tailA tailB : Bytes)
    (same : frame left tailA = frame right tailB) : left = right ∧ tailA = tailB := by
  have headers := List.append_inj same (by simp [encodeLE_length])
  have lengths := encodeLE_injective left.property right.property headers.1
  have contents := List.append_inj headers.2 lengths
  exact ⟨Subtype.ext contents.1, contents.2⟩

/-- Each field is a u16 little-endian name length, name bytes, u32 little-endian
    value length, and value bytes. Fields concatenate in their supplied order. -/
def encodeFields : List Field → Bytes
  | [] => []
  | (name, value) :: rest => frame name (frame value (encodeFields rest))

theorem encodeLengthPrefixed_injective (same : encodeFields left = encodeFields right) :
    left = right := by
  induction left generalizing right with
  | nil =>
    cases right with
    | nil => rfl
    | cons field rest => simp [encodeFields, frame, encodeLE] at same
  | cons field rest ih =>
    cases right with
    | nil => simp [encodeFields, frame, encodeLE] at same
    | cons other tail =>
      have names := frame_injective field.1 other.1 _ _ same
      have values := frame_injective field.2 other.2 _ _ names.2
      have fields := Prod.ext names.1 values.1
      simp [fields, ih values.2]

inductive Purpose where
  | SecretBlob
  | ProfileKeyWrap
  | AuditRow
  | RecoveryEnvelope
  | TeamPackage
  | BackupBundle
  deriving DecidableEq

/-- Leading bytes of the authenticated inputs. For backups this is the
    archive audit-chain AAD in the sealed bundle. -/
def domainTag : Purpose → Bytes
  | .SecretBlob => utf8 "locket-aad-v1"
  | .ProfileKeyWrap => utf8 "locket-key-wrap-v1"
  | .AuditRow => utf8 "locket-audit-v1"
  | .RecoveryEnvelope => utf8 "locket-recovery-envelope-v1"
  | .TeamPackage => utf8 "locket-team-state-v1" ++ [0]
  | .BackupBundle => utf8 "locket-bundle-audit-chain-v1" ++ [0]

private theorem common_prefix_bytes_differ (left right : Purpose) (distinct : left ≠ right) :
    let width := min (domainTag left).length (domainTag right).length
    (domainTag left).take width ≠ (domainTag right).take width := by
  cases left <;> cases right <;> first | contradiction | decide

theorem domain_tags_disjoint (distinct : left ≠ right) (tailA tailB : Bytes) :
    domainTag left ++ tailA ≠ domainTag right ++ tailB := by
  intro same
  have prefixes := congrArg (List.take (min (domainTag left).length (domainTag right).length)) same
  rw [List.take_append_of_le_length (Nat.min_le_left ..),
    List.take_append_of_le_length (Nat.min_le_right ..)] at prefixes
  exact common_prefix_bytes_differ left right distinct prefixes

/-- The canonical byte fields from SecretBlobAad. Source precedence is resolved
    before encoding. The encoder binds the selected row's secret ID and has
    no separate source label. Rust's v1 entry point always uses schemaVersion 1. -/
structure SecretAad where
  schemaVersion : UInt16
  projectId : BoundedBytes 4
  profileId : BoundedBytes 4
  secretId : BoundedBytes 4
  secretName : BoundedBytes 4
  secretVersion : UInt32

private def secretFields (aad : SecretAad) : List Field :=
  [(⟨utf8 "project_id", by decide⟩, aad.projectId),
    (⟨utf8 "profile_id", by decide⟩, aad.profileId),
    (⟨utf8 "secret_id", by decide⟩, aad.secretId),
    (⟨utf8 "secret_name", by decide⟩, aad.secretName)]

def encodeAad (aad : SecretAad) : Bytes :=
  domainTag .SecretBlob ++
    (encodeLE 2 aad.schemaVersion.toNat ++ encodeFields (secretFields aad)) ++
    encodeLE 4 aad.secretVersion.toNat

/-- Equality recovers each encoded field. In particular, different persisted
    secret IDs distinguish different source rows. -/
theorem encodeAad_injective (same : encodeAad left = encodeAad right) : left = right := by
  have separated := List.append_inj' same (by simp [encodeLE_length])
  have payload := List.append_cancel_left separated.1
  have parts := List.append_inj payload (by simp [encodeLE_length])
  have schema := UInt16.toNat_inj.mp
    (encodeLE_injective left.schemaVersion.toNat_lt_size right.schemaVersion.toNat_lt_size parts.1)
  have fields := encodeLengthPrefixed_injective parts.2
  have version := UInt32.toNat_inj.mp
    (encodeLE_injective left.secretVersion.toNat_lt_size right.secretVersion.toNat_lt_size separated.2)
  cases left
  cases right
  simp [secretFields] at fields
  simp_all

def keyLen : Nat := 32

abbrev AuditKey := {key : Bytes // key.length = keyLen}

inductive AuditError where
  | invalidMetadata
  | invalidKeyLength (actual : Nat)
  deriving DecidableEq

private def checkAuditKey (key : Bytes) : Except AuditError AuditKey :=
  if lengthMatches : key.length = keyLen then
    .ok ⟨key, lengthMatches⟩
  else
    .error (.invalidKeyLength key.length)

def verifyAudit (checkRows : AuditKey → List Row → Except AuditError Result)
    (key : Bytes) (rows : List Row) : Except AuditError Result :=
  match checkAuditKey key with
  | .ok checked => checkRows checked rows
  | .error error => .error error

def writeAudit (appendRow : AuditKey → List Row → Except AuditError Result)
    (metadataValid : Bool) (key : Bytes) (rows : List Row) : Except AuditError Result :=
  if metadataValid then verifyAudit appendRow key rows
  else .error .invalidMetadata

theorem auditKey_rejects_wrong_length (key : Bytes) (rows : List Row)
    (checkRows appendRow : AuditKey → List Row → Except AuditError Result)
    (metadataValid : Bool) (wrongLength : key.length ≠ keyLen) :
    verifyAudit checkRows key rows = .error (.invalidKeyLength key.length) ∧
      writeAudit appendRow metadataValid key rows =
        .error (if metadataValid then .invalidKeyLength key.length else .invalidMetadata) := by
  cases metadataValid <;> simp [verifyAudit, writeAudit, checkAuditKey, wrongLength]

end LocketProofs.CryptoDomainSeparation
