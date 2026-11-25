import Std

namespace LocketProofs.DotenvMetadataNonInterference

structure Entry where
  key : String
  value : String
  line : Nat
  deriving DecidableEq

inductive Message where
  | expectedAssignment | invalidName | unexpectedQuoteTail | unsupportedEscape
  | unterminatedQuote | nulByte | expansionRequiresLiteral | duplicateKey
  deriving DecidableEq

structure Diagnostic where
  line : Nat
  message : Message
  deriving DecidableEq

structure Document where
  entries : List Entry := []
  warnings : List Diagnostic := []
  errors : List Diagnostic := []
  deriving DecidableEq

-- Rust's whitespace predicate, including the Unicode space separators.
private def whitespace (c : Char) : Bool :=
  let n := c.toNat
  (9 ≤ n && n ≤ 13) || (0x2000 ≤ n && n ≤ 0x200A) ||
    [0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000].contains n

private def trimEnd (text : List Char) : List Char :=
  (text.reverse.dropWhile whitespace).reverse

private def nameStart (c : Char) : Bool := ('A' ≤ c && c ≤ 'Z') || c == '_'

private def validName : List Char → Bool
  | [] => false
  | first :: rest => nameStart first && rest.all (fun c => nameStart c || ('0' ≤ c && c ≤ '9'))

private def splitAssignment (text : List Char) : Option (List Char × List Char) :=
  match text.span (· != '=') with
  | (key, _ :: raw) => some (trimEnd (key.dropWhile whitespace), raw)
  | (_, []) => none

private def stripExport (text : List Char) : List Char :=
  match text with
  | 'e' :: 'x' :: 'p' :: 'o' :: 'r' :: 't' :: next :: rest =>
    if whitespace next then rest.dropWhile whitespace else text
  | _ => text

private def beforeComment (precedingSpace : Bool) : List Char → List Char
  | [] => []
  | c :: rest =>
    if c == '#' && precedingSpace then [] else c :: beforeComment (whitespace c) rest

private def doubleEscape : Char → Option Char
  | 'n' => some '\n'
  | 'r' => some '\r'
  | 't' => some '\t'
  | '\\' => some '\\'
  | '"' => some '"'
  | '$' => some '$'
  | _ => none

private def quotedValue (quote : Char) : List Char → Except Message (Option (List Char))
  | [] => .ok none
  | c :: rest =>
    if c == quote then
      match rest.dropWhile whitespace with
      | [] | '#' :: _ => .ok (some [])
      | _ => .error .unexpectedQuoteTail
    else if quote == '"' && c == '\\' then
      match rest with
      | [] => .ok none
      | escaped :: tail =>
        match doubleEscape escaped with
        | none => .error .unsupportedEscape
        | some decoded => (quotedValue quote tail).map (Option.map (decoded :: ·))
    else (quotedValue quote rest).map (Option.map (c :: ·))

private def reject (doc : Document) (line : Nat) (message : Message) : Document :=
  { doc with errors := doc.errors ++ [⟨line, message⟩] }

private def finishValue (literal : Bool) (doc : Document) (line : Nat) (key : String)
    (value : List Char) : Document :=
  if value.contains '\x00' then reject doc line .nulByte
  else if !literal && (value.contains '$' || value.contains '`') then
    reject doc line .expansionRequiresLiteral
  else
    let duplicate := doc.entries.any (fun entry => entry.key == key)
    { doc with
      entries := doc.entries.filter (fun entry => entry.key != key) ++
        [⟨key, String.ofList value, line⟩]
      warnings := if duplicate then doc.warnings ++ [⟨line, .duplicateKey⟩] else doc.warnings }

private structure QuotedAssignment where
  line : Nat
  key : String
  quote : Char
  raw : List Char

private def finishQuoted (literal : Bool) (doc : Document) (pending : QuotedAssignment) :
    Document × Option QuotedAssignment :=
  match quotedValue pending.quote pending.raw with
  | .ok none => (doc, some pending)
  | .error message => (reject doc pending.line message, none)
  | .ok (some value) => (finishValue literal doc pending.line pending.key value, none)

private def parseLine (literal : Bool) (doc : Document) (line : Nat) (text : List Char) :
    Document × Option QuotedAssignment :=
  match text.dropWhile whitespace with
  | [] | '#' :: _ => (doc, none)
  | assignment =>
    match splitAssignment (stripExport assignment) with
    | none => (reject doc line .expectedAssignment, none)
    | some (key, raw) =>
      if !validName key then (reject doc line .invalidName, none)
      else
        let name := String.ofList key
        match raw.dropWhile whitespace with
        | '\'' :: rest => finishQuoted literal doc ⟨line, name, '\'', rest⟩
        | '"' :: rest => finishQuoted literal doc ⟨line, name, '"', rest⟩
        | value =>
          let leadingSpace := raw.head?.any whitespace
          (finishValue literal doc line name (trimEnd (beforeComment leadingSpace value)), none)

private def parseLines (literal : Bool) :
    List (List Char) → Nat → Document → Option QuotedAssignment → Document
  | [], _, doc, none => doc
  | [], _, doc, some pending => reject doc pending.line .unterminatedQuote
  | text :: rest, line, doc, pending =>
    let (nextDoc, nextPending) := match pending with
      | none => parseLine literal doc line text
      | some prior => finishQuoted literal doc { prior with raw := prior.raw ++ '\n' :: text }
    parseLines literal rest (line + 1) nextDoc nextPending

private def stripCarriageReturn (line : List Char) : List Char :=
  match line.reverse with
  | '\r' :: rest => rest.reverse
  | _ => line

private def dotenvLines (text : String) : List (List Char) :=
  match (text.toList.splitOn '\n').reverse with
  | [] => []
  | [] :: before => before.reverse.map stripCarriageReturn
  | last :: before => before.reverse.map stripCarriageReturn ++ [last]

/-- Literal mode accepts expansion markers as data after applying the same quote and
comment syntax. The parser's diagnostics can depend on the input syntax. -/
def parseDotenv (literal : Bool) (text : String) : Document :=
  parseLines literal (dotenvLines text) 1 {} none

private def sortedSet (items : List String) : List String :=
  items.eraseDups.mergeSort (fun left right => left ≤ right)

structure KeyReport where
  keys : List String
  warnings : List Diagnostic
  invalid : Nat
  metadataOnly : Bool
  deriving DecidableEq

def inspectEnvKeys (doc : Document) : KeyReport :=
  ⟨sortedSet (doc.entries.map Entry.key), doc.warnings, doc.errors.length, true⟩

def replaceValues (doc : Document) (f : Entry → String) : Document :=
  { doc with entries := doc.entries.map fun entry => { entry with value := f entry } }

/-- Parsed values can be replaced independently while preserving every report field,
including warning order and the invalid-entry count. -/
theorem inspectEnvKeys_noninterference (es : Document) (f : Entry → String) :
    inspectEnvKeys (replaceValues es f) = inspectEnvKeys es := by
  simp [inspectEnvKeys, replaceValues, List.map_map, Function.comp_def]

structure WorkspaceFile where
  path : String
  projectRoot : String
  hasConfig : Bool
  suggestedProfile : String
  document : Except String Document

structure ScannedFile where
  path : String
  projectRoot : String
  hasConfig : Bool
  suggestedProfile : String
  suggestedSource : String
  keys : List String
  keyCount : Nat
  warningsCount : Nat
  invalid : Nat
  error : Option String
  deriving DecidableEq

structure SharedCandidate where
  key : String
  files : List String
  projects : List String
  deriving DecidableEq

structure ScanReport where
  root : String
  files : List ScannedFile
  sharedCandidates : List SharedCandidate
  totalFiles : Nat
  totalKeys : Nat
  metadataOnly : Bool
  deriving DecidableEq

private def sharedProviderKeys : List String :=
  ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN",
    "GH_TOKEN", "NPM_TOKEN", "CLOUDFLARE_API_TOKEN", "VERCEL_TOKEN", "OPENROUTER_API_KEY",
    "HF_TOKEN", "HUGGINGFACE_API_KEY", "PERPLEXITY_API_KEY", "XAI_API_KEY", "LINEAR_API_KEY"]

private def scanFile (file : WorkspaceFile) : ScannedFile :=
  let (report, error) := match file.document with
    | .ok doc => (inspectEnvKeys doc, none)
    | .error message => (⟨[], [], 1, true⟩, some message)
  ⟨file.path, file.projectRoot, file.hasConfig, file.suggestedProfile, "user-local", report.keys,
    report.keys.length, report.warnings.length, report.invalid, error⟩

private def sharedCandidate (files : List ScannedFile) (key : String) : Option SharedCandidate :=
  let locations := files.filter (fun file => file.keys.contains key)
  let projects := sortedSet (locations.map ScannedFile.projectRoot)
  if projects.length ≥ 2 || sharedProviderKeys.contains key then
    some ⟨key, sortedSet (locations.map ScannedFile.path), projects⟩
  else none

/-- Files carry the path and project-root information obtained by the workspace walker.
Only files among those inputs that contain a key contribute to its locations. -/
def scanSharedCandidates (root : String) (workspace : List WorkspaceFile) : ScanReport :=
  let files := (workspace.map scanFile).mergeSort (fun left right => left.path ≤ right.path)
  let keys := sortedSet (files.flatMap ScannedFile.keys)
  ⟨root, files, keys.filterMap (sharedCandidate files), files.length,
    (files.map ScannedFile.keyCount).sum, true⟩

def replaceWorkspaceValues (workspace : List WorkspaceFile) (f : WorkspaceFile → Entry → String) :
    List WorkspaceFile :=
  workspace.map fun file => { file with document := file.document.map (replaceValues · (f file)) }

theorem scanSharedCandidates_noninterference (root : String) (workspace : List WorkspaceFile)
    (f : WorkspaceFile → Entry → String) :
    scanSharedCandidates root (replaceWorkspaceValues workspace f) =
      scanSharedCandidates root workspace := by
  have sameFiles : (replaceWorkspaceValues workspace f).map scanFile = workspace.map scanFile := by
    simp only [replaceWorkspaceValues, List.map_map, Function.comp_def]
    apply List.map_congr_left
    intro file _
    cases document : file.document <;>
      simp [scanFile, document, Except.map, inspectEnvKeys_noninterference]
  simp only [scanSharedCandidates, sameFiles]

private def keyAdmitted (only exclude : List String) (key : String) : Bool :=
  (only.isEmpty || only.contains key) && !exclude.contains key

def filterKeys (only exclude keys : List String) : List String :=
  keys.filter (keyAdmitted only exclude)

def filterEntries (only exclude : List String) (entries : List Entry) : List Entry :=
  entries.filter (fun entry => keyAdmitted only exclude entry.key)

theorem filterKeys_soundness (admitted : key ∈ filterKeys only exclude keys) :
    key ∈ keys ∧ key ∉ exclude ∧ (only ≠ [] → key ∈ only) := by
  obtain ⟨inKeys, allowed, notExcluded⟩ := by
    simpa [filterKeys, keyAdmitted] using admitted
  exact ⟨inKeys, notExcluded, fun nonempty => allowed.resolve_left nonempty⟩

abbrev Vault := String → Option String

inductive ImportAction where
  | create | rotate | skip
  deriving DecidableEq, BEq

structure ImportPartition where
  created : List String
  rotated : List String
  skipped : List String
  deriving DecidableEq

private abbrev ImportEvent := String × ImportAction

private def partition (events : List ImportEvent) : ImportPartition :=
  let keysFor := fun action => sortedSet ((events.filter (fun event => event.2 == action)).map Prod.fst)
  ⟨keysFor .create, keysFor .rotate, keysFor .skip⟩

private def planAction (vault : Vault) (overwrite : Bool) (key : String) : ImportAction :=
  if (vault key).isSome then (if overwrite then .rotate else .skip) else .create

def dryRun (vault : Vault) (overwrite : Bool) (keys : List String) : ImportPartition × Vault :=
  (partition (keys.map fun key => (key, planAction vault overwrite key)), vault)

private def writeEntry (vault : Vault) (entry : Entry) : Vault :=
  fun key => if entry.key = key then some entry.value else vault key

private def liveStep (vault : Vault) (overwrite : Bool) (entry : Entry) : ImportAction × Vault :=
  match vault entry.key with
  | none => (.create, writeEntry vault entry)
  | some _ => if overwrite then (.rotate, writeEntry vault entry) else (.skip, vault)

private def liveEvents (overwrite : Bool) : List Entry → Vault → List ImportEvent × Vault
  | [], vault => ([], vault)
  | entry :: rest, vault =>
    let (action, nextVault) := liveStep vault overwrite entry
    let (events, finalVault) := liveEvents overwrite rest nextVault
    ((entry.key, action) :: events, finalVault)

def liveImport (vault : Vault) (overwrite : Bool) (entries : List Entry) : ImportPartition × Vault :=
  let (events, finalVault) := liveEvents overwrite entries vault
  (partition events, finalVault)

private theorem liveStep_action (vault : Vault) (overwrite : Bool) (entry : Entry) :
    (liveStep vault overwrite entry).1 = planAction vault overwrite entry.key := by
  cases lookup : vault entry.key <;> cases overwrite <;> simp [liveStep, planAction, lookup]

private theorem liveStep_other_key (different : entry.key ≠ key) :
    (liveStep vault overwrite entry).2 key = vault key := by
  cases lookup : vault entry.key <;> cases overwrite <;> simp [liveStep, writeEntry, lookup, different]

private theorem liveEvents_match_plan (unique : (entries.map Entry.key).Nodup) :
    (liveEvents overwrite entries vault).1 =
      (entries.map Entry.key).map (fun key => (key, planAction vault overwrite key)) := by
  induction entries generalizing vault with
  | nil => rfl
  | cons entry rest ih =>
    obtain ⟨fresh, uniqueRest⟩ := List.nodup_cons.mp unique
    simp only [liveEvents, List.map_cons, liveStep_action, ih uniqueRest]
    congr 1
    apply List.map_congr_left
    intro key inRest
    have different : entry.key ≠ key := fun eq => fresh (eq ▸ inRest)
    simp only [planAction, liveStep_other_key different]

/-- The import scope is one project, profile, and source with active records.
This compares a read-only plan with a successful atomic write on the same snapshot.
The parser resolves duplicates before filtering, so each admitted key occurs once. -/
theorem dryRun_matches_live_partition (vault : Vault) (overwrite : Bool) (entries : List Entry)
    (unique : (entries.map Entry.key).Nodup) (only exclude : List String) :
    (dryRun vault overwrite (filterKeys only exclude (entries.map Entry.key))).1 =
      (liveImport vault overwrite (filterEntries only exclude entries)).1 ∧
    (dryRun vault overwrite (filterKeys only exclude (entries.map Entry.key))).2 = vault := by
  have sameKeys : filterKeys only exclude (entries.map Entry.key) =
      (filterEntries only exclude entries).map Entry.key := List.filter_map
  have filteredUnique : ((filterEntries only exclude entries).map Entry.key).Nodup := by
    rw [← sameKeys]
    exact List.Pairwise.filter _ unique
  rw [sameKeys]
  exact ⟨congrArg partition (liveEvents_match_plan filteredUnique).symm, rfl⟩

end LocketProofs.DotenvMetadataNonInterference
