import Std

namespace LocketProofs.PrivacyModeNonInterference

inductive AliasKind where
  | project | profile | policy | device | member | secret
  deriving DecidableEq

def AliasKind.text : AliasKind → String
  | .project => "project"
  | .profile => "profile"
  | .policy => "policy"
  | .device => "device"
  | .member => "member"
  | .secret => "secret"

abbrev Bytes := List UInt8

private def utf8 (text : String) : Bytes := text.toByteArray.data.toList

private def littleEndian (width length : Nat) : Bytes :=
  (List.range width).map fun offset => UInt8.ofNat (length / 256 ^ offset)

private def fieldHeader (field : String) : Bytes :=
  littleEndian 2 (min (utf8 field).length 65535) ++ utf8 field

private def kindPrefix (kind : AliasKind) : Bytes :=
  utf8 "locket-privacy-alias-v1" ++ fieldHeader "kind" ++
    littleEndian 4 (utf8 kind.text).length ++ utf8 kind.text ++ fieldHeader "id"

/-- The version domain and both named fields, encoded with UTF-8 byte lengths.
The identifier length saturates at the same bound as the Rust encoder. -/
def canonicalInput (kind : AliasKind) (name : String) : Bytes :=
  kindPrefix kind ++ littleEndian 4 (min (utf8 name).length 4294967295) ++ utf8 name

private theorem kindPrefix_disjoint (k₁ k₂ : AliasKind) :
    kindPrefix k₁ <+: kindPrefix k₂ → k₁ = k₂ := by
  cases k₁ <;> cases k₂ <;> decide

private theorem eq_of_prefixed_eq (header : AliasKind → List α)
    (disjoint : ∀ a b, header a <+: header b → a = b)
    (same : header k₁ ++ left = header k₂ ++ right) : k₁ = k₂ := by
  have second := List.prefix_append (header k₂) right
  rw [← same] at second
  rcases List.prefix_or_prefix_of_prefix (List.prefix_append (header k₁) left) second with
    forward | backward
  · exact disjoint _ _ forward
  · exact (disjoint _ _ backward).symm

theorem canonicalAliasInput_kind_disjoint (same : canonicalInput k₁ n₁ = canonicalInput k₂ n₂) :
    k₁ = k₂ ∧ n₁ = n₂ := by
  simp only [canonicalInput, List.append_assoc] at same
  have sameKind := eq_of_prefixed_eq kindPrefix kindPrefix_disjoint same
  subst k₂
  refine ⟨rfl, String.toByteArray_inj.mp ?_⟩
  have sameField := List.append_cancel_left same
  have sameBytes := congrArg (List.drop 4) sameField
  have dropLength (name : String) :
      (littleEndian 4 (min (utf8 name).length 4294967295) ++ utf8 name).drop 4 = utf8 name := by
    simp [littleEndian]
  rw [dropLength, dropLength] at sameBytes
  exact ByteArray.ext (Array.toList_inj.mp sameBytes)

abbrev DigestPrefix := {text : String // text.length = 8 ∧
  text.toList.all (fun c => ('0' ≤ c && c ≤ '9') || ('a' ≤ c && c ≤ 'f')) = true}

/-- The displayed digest function encodes the first four SHA-256 bytes as lowercase hex. -/
abbrev DisplayHash := Bytes → DigestPrefix

structure Alias where
  kind : AliasKind
  digestPrefix : DigestPrefix
  deriving DecidableEq

def alias (hash : DisplayHash) (kind : AliasKind) (name : String) : Alias :=
  ⟨kind, hash (canonicalInput kind name)⟩

private def aliasPrefix (kind : AliasKind) : List Char := kind.text.toList ++ ['-']

def Alias.render (label : Alias) : String :=
  String.ofList (aliasPrefix label.kind ++ label.digestPrefix.val.toList)

private theorem aliasPrefix_disjoint (k₁ k₂ : AliasKind) :
    aliasPrefix k₁ <+: aliasPrefix k₂ → k₁ = k₂ := by
  cases k₁ <;> cases k₂ <;> decide

/-- Collision freedom is a hypothesis about the displayed digest on the supplied
identifier set. A full digest without truncation is a different function. -/
def HashInjective (hash : DisplayHash) (names : List (AliasKind × String)) : Prop :=
  ∀ first ∈ names, ∀ second ∈ names,
    hash (canonicalInput first.1 first.2) = hash (canonicalInput second.1 second.2) →
      canonicalInput first.1 first.2 = canonicalInput second.1 second.2

theorem alias_injective_under_hash {hash : DisplayHash} (collisionFree : HashInjective hash names)
    (firstPresent : (k₁, n₁) ∈ names) (secondPresent : (k₂, n₂) ∈ names)
    (same : (alias hash k₁ n₁).render = (alias hash k₂ n₂).render) : k₁ = k₂ ∧ n₁ = n₂ := by
  have sameText := congrArg String.toList same
  simp only [Alias.render, alias, String.toList_ofList] at sameText
  have sameKind := eq_of_prefixed_eq aliasPrefix aliasPrefix_disjoint sameText
  subst k₂
  have sameDigest := Subtype.ext (String.toList_inj.mp (List.append_cancel_left sameText))
  exact canonicalAliasInput_kind_disjoint
    (collisionFree (k₁, n₁) firstPresent (k₁, n₂) secondPresent sameDigest)

structure Identifier where
  realName : String
  opaqueId : Option String

private def Identifier.aliasInput (identifier : Identifier) : String :=
  identifier.opaqueId.getD identifier.realName

private def Identifier.rename (rename : AliasKind → String → String) (kind : AliasKind)
    (identifier : Identifier) : Identifier :=
  { identifier with realName := rename kind identifier.realName }

inductive Expiry where
  | current | expiringSoon | expired
  deriving DecidableEq

structure SecretMetadata (Label : Type) where
  project : Label
  profile : Label
  secret : Label
  expiry : Expiry
  stale : Bool
  deriving DecidableEq

structure StatusMetadata (Label : Type) where
  project : Option Label
  profile : Option Label
  sharedProject : Option Label
  policies : List Label
  secretCount : Nat
  agentRunning : Bool
  vaultUnlocked : Option Bool
  deriving DecidableEq

structure VaultMetadata (Label : Type) where
  status : StatusMetadata Label
  secrets : List (SecretMetadata Label)
  deriving DecidableEq

private def SecretMetadata.mapNames (row : SecretMetadata α) (f : AliasKind → α → β) :
    SecretMetadata β :=
  ⟨f .project row.project, f .profile row.profile, f .secret row.secret, row.expiry, row.stale⟩

private def SecretMetadata.names (row : SecretMetadata α) : List (AliasKind × α) :=
  [(.project, row.project), (.profile, row.profile), (.secret, row.secret)]

private def StatusMetadata.mapNames (status : StatusMetadata α) (f : AliasKind → α → β) :
    StatusMetadata β :=
  ⟨status.project.map (f .project), status.profile.map (f .profile),
    status.sharedProject.map (f .project), status.policies.map (f .policy),
    status.secretCount, status.agentRunning, status.vaultUnlocked⟩

private def StatusMetadata.names (status : StatusMetadata α) : List (AliasKind × α) :=
  status.project.toList.map (fun name => (.project, name)) ++
    status.profile.toList.map (fun name => (.profile, name)) ++
    status.sharedProject.toList.map (fun name => (.project, name)) ++
    status.policies.map (fun name => (.policy, name))

def VaultMetadata.mapNames (vault : VaultMetadata α) (f : AliasKind → α → β) : VaultMetadata β :=
  ⟨vault.status.mapNames f, vault.secrets.map (·.mapNames f)⟩

def VaultMetadata.names (vault : VaultMetadata α) : List (AliasKind × α) :=
  vault.status.names ++ vault.secrets.flatMap SecretMetadata.names

private theorem mapNames_comp (vault : VaultMetadata α)
    (f : AliasKind → α → β) (g : AliasKind → β → γ) :
    (vault.mapNames f).mapNames g = vault.mapNames (fun kind name => g kind (f kind name)) := by
  simp [VaultMetadata.mapNames, StatusMetadata.mapNames, SecretMetadata.mapNames,
    List.map_map, Function.comp_def]

private theorem mapNames_congr (vault : VaultMetadata α) (f g : AliasKind → α → β)
    (same : ∀ kind name, (kind, name) ∈ vault.names → f kind name = g kind name) :
    vault.mapNames f = vault.mapNames g := by
  have statusSame (kind : AliasKind) (name : α) (present : (kind, name) ∈ vault.status.names) :=
    same kind name (List.mem_append_left _ present)
  have secretSame (row : SecretMetadata α) (found : row ∈ vault.secrets) (kind : AliasKind)
      (name : α) (present : (kind, name) ∈ row.names) :=
    same kind name (List.mem_append_right _ (List.mem_flatMap.mpr ⟨row, found, present⟩))
  unfold VaultMetadata.mapNames
  congr 1
  · unfold StatusMetadata.mapNames
    congr 1
    · apply Option.map_congr
      intro name present
      exact statusSame .project name (by simp [StatusMetadata.names, present])
    · apply Option.map_congr
      intro name present
      exact statusSame .profile name (by simp [StatusMetadata.names, present])
    · apply Option.map_congr
      intro name present
      exact statusSame .project name (by simp [StatusMetadata.names, present])
    · apply List.map_congr_left
      intro name present
      exact statusSame .policy name (by simp [StatusMetadata.names, present])
  · apply List.map_congr_left
    intro row found
    simp [SecretMetadata.mapNames, secretSame row found .project row.project (by simp [SecretMetadata.names]),
      secretSame row found .profile row.profile (by simp [SecretMetadata.names]),
      secretSame row found .secret row.secret (by simp [SecretMetadata.names])]

private def aliasIdentifier (hash : DisplayHash) (kind : AliasKind) (identifier : Identifier) : Alias :=
  alias hash kind identifier.aliasInput

def privateMetadata (hash : DisplayHash) (vault : VaultMetadata Identifier) : VaultMetadata Alias :=
  vault.mapNames (aliasIdentifier hash)

def substringMatches (query field : String) : Bool := field.toLower.contains query.toLower

def SecretMetadata.labels (row : SecretMetadata α) : List α := [row.project, row.profile, row.secret]

def matchesAlias (query : String) (row : SecretMetadata Alias) : Bool :=
  row.labels.any (fun label => substringMatches query label.render)

def privacySearch (hash : DisplayHash) (vault : VaultMetadata Identifier) (query : String) :
    List (SecretMetadata Alias) :=
  (privateMetadata hash vault).secrets.filter (matchesAlias query)

structure Views (Label : Type) where
  status : StatusMetadata Label
  searchMatches : List (SecretMetadata Label)
  rotationSuggestions : List (SecretMetadata Label)

inductive Projection where
  | plain (views : Views String)
  | privateView (views : Views Alias)

private def views (metadata : VaultMetadata α) (matched : SecretMetadata α → Bool) : Views α :=
  ⟨metadata.status, metadata.secrets.filter matched,
    metadata.secrets.filter (fun row => row.stale || row.expiry != .current)⟩

def projectViews (privacyMode : Bool) (hash : DisplayHash) (vault : VaultMetadata Identifier)
    (query : String) : Projection :=
  if privacyMode then .privateView (views (privateMetadata hash vault) (matchesAlias query))
  else
    let metadata := vault.mapNames (fun _ identifier => identifier.realName)
    .plain (views metadata (fun row => row.labels.any (substringMatches query)))

def renameNames (vault : VaultMetadata Identifier) (rename : AliasKind → String → String) :
    VaultMetadata Identifier :=
  vault.mapNames (Identifier.rename rename)

/-- Renaming preserves the public shape, row order, and statuses by construction. Stable opaque IDs
preserve their labels automatically. Where a real name supplies the alias input, the
displayed digest must remain equal. Private view name fields carry only aliases. -/
theorem privacyProjection_noninterference (hash : DisplayHash) (vault : VaultMetadata Identifier)
    (rename : AliasKind → String → String)
    (sameAliases : ∀ kind identifier, (kind, identifier) ∈ vault.names → identifier.opaqueId = none →
      hash (canonicalInput kind (rename kind identifier.realName)) =
        hash (canonicalInput kind identifier.realName)) (query : String) :
    ∃ result : Views Alias,
      projectViews true hash vault query = .privateView result ∧
      projectViews true hash (renameNames vault rename) query = .privateView result := by
  have sameMetadata : privateMetadata hash (renameNames vault rename) = privateMetadata hash vault := by
    rw [privateMetadata, renameNames, mapNames_comp, privateMetadata]
    apply mapNames_congr
    intro kind identifier present
    cases id : identifier.opaqueId with
    | none => simp [aliasIdentifier, alias, Identifier.rename, Identifier.aliasInput, id,
        sameAliases kind identifier present id]
    | some value => simp [aliasIdentifier, Identifier.rename, Identifier.aliasInput, id]
  exact ⟨views (privateMetadata hash vault) (matchesAlias query), rfl,
    by simp [projectViews, sameMetadata]⟩

/-- This contract requires projecting before filtering. Rust discovery currently filters
store records before building aliased rows. A query that coincides with part of a public
alias matches that label regardless of its origin. -/
theorem privacySearch_never_matches_unaliased_raw_name (hash : DisplayHash)
    (vault : VaultMetadata Identifier) (query : String) :
    (∀ row, row ∈ privacySearch hash vault query ↔
      row ∈ (privateMetadata hash vault).secrets ∧
        ∃ label ∈ row.labels, substringMatches query label.render = true) ∧
    ((∀ row ∈ (privateMetadata hash vault).secrets, ∀ label ∈ row.labels,
        substringMatches query label.render = false) → privacySearch hash vault query = []) := by
  constructor
  · intro row
    simp [privacySearch, matchesAlias, List.any_eq_true]
  · intro miss
    apply List.filter_eq_nil_iff.mpr
    intro row present hit
    obtain ⟨label, found, matched⟩ := List.any_eq_true.mp hit
    rw [miss row present label found] at matched
    contradiction

end LocketProofs.PrivacyModeNonInterference
