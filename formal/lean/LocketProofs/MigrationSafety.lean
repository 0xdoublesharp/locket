import LocketProofs.DotenvMetadataNonInterference

namespace LocketProofs.MigrationSafety

open DotenvMetadataNonInterference

structure ArchiveDestInput where
  isSymlink : Bool
  isDirectory : Bool
  inGitWorktree : Bool
  hasLocketConfigAbove : Bool
  -- `none` represents a failed or unavailable Git check.
  gitCheckIgnored : Option Bool

inductive ArchiveGate where
  | allow | symlink | notDirectory | gitIgnoreUnconfirmed
  deriving DecidableEq

/-- Both archive paths use the same destination observations. Worktree membership
comes from Git independently of project configuration discovery. -/
def checkArchiveDestination (input : ArchiveDestInput) : ArchiveGate :=
  if input.isSymlink then .symlink
  else if !input.isDirectory then .notDirectory
  else if input.inGitWorktree && (input.gitCheckIgnored != some true) then .gitIgnoreUnconfirmed
  else .allow

def dryRunArchiveGate (input : ArchiveDestInput) : ArchiveGate := checkArchiveDestination input

def liveArchiveGate (input : ArchiveDestInput) : ArchiveGate := checkArchiveDestination input

theorem archive_blocks_unignored_in_git_worktree (input : ArchiveDestInput)
    (inside : input.inGitWorktree = true) (unconfirmed : input.gitCheckIgnored ≠ some true) :
    checkArchiveDestination input ≠ .allow := by
  cases symlink : input.isSymlink <;> cases directory : input.isDirectory <;>
    simp [checkArchiveDestination, inside, unconfirmed, symlink, directory]

theorem archive_blocks_symlink_or_non_dir (input : ArchiveDestInput)
    (unsafePath : input.isSymlink = true ∨ input.isDirectory = false) :
    checkArchiveDestination input ≠ .allow := by
  rcases unsafePath with symlink | notDirectory
  · simp [checkArchiveDestination, symlink]
  · cases path : input.isSymlink <;> simp [checkArchiveDestination, notDirectory, path]

theorem archive_dryrun_matches_live (input : ArchiveDestInput) :
    dryRunArchiveGate input = liveArchiveGate input := rfl

inductive GitIgnoreCoverage where
  | trackedRepoGitignore | untrackedGitignore | gitInfoExclude | globalExclude | notIgnored | gitError
  deriving DecidableEq, BEq

def shouldWritePatternLocally : GitIgnoreCoverage → Bool
  | .trackedRepoGitignore => false
  | _ => true

/-- Protection is either confirmed by a tracked repository rule or supplied by a
successful local write. Source detection and write failures are outside this model. -/
def effectiveSecretProtected (cov : GitIgnoreCoverage) : Bool :=
  (cov == .trackedRepoGitignore) || shouldWritePatternLocally cov

theorem gitignore_fail_closed_protection (cov : GitIgnoreCoverage) :
    effectiveSecretProtected cov = true ∧
      (cov ≠ .trackedRepoGitignore → shouldWritePatternLocally cov = true) := by
  cases cov <;> decide

inductive IgnoreRule where
  | dotenvWildcard | unignoreExample | unignoreSample | unignoreVariantExample

-- The star in `.env.*.example` may be empty. Match the suffix only after the prefix.
private def isDotenvVariantExample (name : String) : Bool :=
  name.startsWith ".env." && ".example".toList.isSuffixOf (name.toList.drop 5)

def isRecognizedTemplate (name : String) : Bool :=
  (name == ".env.example") || (name == ".env.sample") || isDotenvVariantExample name

private def applyIgnoreRule (name : String) (ignored : Bool) : IgnoreRule → Bool
  | .dotenvWildcard => if name.startsWith ".env." then true else ignored
  | .unignoreExample => if name == ".env.example" then false else ignored
  | .unignoreSample => if name == ".env.sample" then false else ignored
  | .unignoreVariantExample => if isDotenvVariantExample name then false else ignored

/-- Evaluate a basename in rule order. Each match replaces the previous decision. -/
def isIgnored (name : String) (rules : List IgnoreRule) : Bool :=
  rules.foldl (applyIgnoreRule name) false

def dotenvIgnoreRules : List IgnoreRule :=
  [.dotenvWildcard, .unignoreExample, .unignoreSample, .unignoreVariantExample]

theorem template_unignore_after_wildcard_visible (name : String) (previous : List IgnoreRule) :
    let ignored := isIgnored name (previous ++ dotenvIgnoreRules)
    (isRecognizedTemplate name = true → ignored = false) ∧
      (isRecognizedTemplate name = false → name.startsWith ".env." = true → ignored = true) := by
  cases exampleName : name == ".env.example" <;> cases sampleName : name == ".env.sample" <;>
    cases variant : isDotenvVariantExample name <;>
    simp [isIgnored, dotenvIgnoreRules, applyIgnoreRule, List.foldl_append,
      isRecognizedTemplate, exampleName, sampleName, variant] <;>
    exact Or.inl

abbrev Selector := String
abbrev ProjectId := String

structure BatchUnlockPlan where
  selectors : List Selector
  resolve : Selector → Option ProjectId

def maxBatch : Nat := 8

/-- Keep each project's first occurrence in selector order. -/
def dedup (projects : List ProjectId) : List ProjectId := projects.eraseDups

def resolveSelectors (plan : BatchUnlockPlan) : Option (List ProjectId) :=
  plan.selectors.mapM plan.resolve

def prepareBatchUnlock (plan : BatchUnlockPlan) : Option (List ProjectId) := do
  let projects ← resolveSelectors plan
  let unique := dedup projects
  if unique.length ≤ maxBatch then some unique else none

structure BatchUnlockResult where
  attempted : List ProjectId := []
  unlocked : List ProjectId := []

private def executeBatch (authorize : ProjectId → Bool) : List ProjectId → BatchUnlockResult
  | [] => {}
  | project :: rest =>
    if authorize project then
      let result := executeBatch authorize rest
      ⟨project :: result.attempted, project :: result.unlocked⟩
    else ⟨[project], []⟩

/-- Resolution, deduplication, and the cap check finish before authorization begins. -/
def runBatchUnlock (plan : BatchUnlockPlan) (authorize : ProjectId → Bool) : BatchUnlockResult :=
  match prepareBatchUnlock plan with
  | none => {}
  | some projects => executeBatch authorize projects

private theorem resolveSelectors_none {selectors : List Selector} {resolve : Selector → Option ProjectId}
    (missing : selector ∈ selectors) (failed : resolve selector = none) :
    selectors.mapM resolve = none := by
  induction selectors with
  | nil => simp at missing
  | cons first rest ih =>
    rcases List.mem_cons.mp missing with same | later
    · subst first
      simp [failed]
    · cases resolved : resolve first <;> simp [resolved, ih later]

theorem batchUnlock_invalid_selector_zero_prompts (plan : BatchUnlockPlan)
    (authorize : ProjectId → Bool)
    (invalid : (∃ selector ∈ plan.selectors, plan.resolve selector = none) ∨
      (∃ projects, resolveSelectors plan = some projects ∧ maxBatch < (dedup projects).length)) :
    runBatchUnlock plan authorize = ⟨[], []⟩ := by
  rcases invalid with ⟨selector, requested, failed⟩ | ⟨projects, resolved, tooMany⟩
  · have unresolved : resolveSelectors plan = none := resolveSelectors_none requested failed
    simp [runBatchUnlock, prepareBatchUnlock, unresolved]
  · simp [runBatchUnlock, prepareBatchUnlock, resolved, Nat.not_le_of_lt tooMany]

private theorem dedup_nodup (projects : List ProjectId) : (dedup projects).Nodup := by
  cases projects with
  | nil => simp [dedup]
  | cons project rest =>
    rw [dedup, List.eraseDups_cons, List.nodup_cons]
    exact ⟨by simp [List.mem_eraseDups], dedup_nodup _⟩
termination_by projects.length
decreasing_by
  exact Nat.lt_succ_of_le (List.length_filter_le ..)

private theorem executeBatch_attempts_prefix (authorize : ProjectId → Bool)
    (projects : List ProjectId) :
    (executeBatch authorize projects).attempted <+: projects := by
  induction projects with
  | nil => simp [executeBatch]
  | cons project rest ih =>
    by_cases allowed : authorize project = true
    · simpa [executeBatch, allowed] using ih
    · simp [executeBatch, allowed]

theorem batchUnlock_dedup_unique_prompts (plan : BatchUnlockPlan) (authorize : ProjectId → Bool) :
    (runBatchUnlock plan authorize).attempted.Nodup := by
  cases resolved : resolveSelectors plan with
  | none => simp [runBatchUnlock, prepareBatchUnlock, resolved]
  | some projects =>
    by_cases fits : (dedup projects).length ≤ maxBatch
    · simpa [runBatchUnlock, prepareBatchUnlock, resolved, fits] using
        (dedup_nodup projects).sublist (executeBatch_attempts_prefix authorize (dedup projects)).sublist
    · simp [runBatchUnlock, prepareBatchUnlock, resolved, fits]

private theorem executeBatch_first_failure (authorize : ProjectId → Bool) (projects : List ProjectId)
    (k : Nat) (inBounds : k < projects.length)
    (attempted : k < (executeBatch authorize projects).attempted.length)
    (denied : authorize projects[k] = false) :
    (∀ project ∈ projects.take k, authorize project = true) ∧
      executeBatch authorize projects = ⟨projects.take (k + 1), projects.take k⟩ := by
  induction projects generalizing k with
  | nil => simp at inBounds
  | cons first rest ih =>
    cases k with
    | zero =>
      have firstDenied : authorize first = false := denied
      simp [executeBatch, firstDenied]
    | succ k =>
      have allowed : authorize first = true := by
        cases decision : authorize first with
        | true => rfl
        | false => simp [executeBatch, decision] at attempted
      have restBound : k < rest.length := by simpa using inBounds
      have restAttempted : k < (executeBatch authorize rest).attempted.length := by
        simpa [executeBatch, allowed] using attempted
      have restDenied : authorize rest[k] = false := denied
      obtain ⟨earlier, trace⟩ := ih k restBound restAttempted restDenied
      refine ⟨?_, by simp [executeBatch, allowed, trace]⟩
      intro project present
      rw [List.take_succ_cons] at present
      rcases List.mem_cons.mp present with same | remaining
      · simpa [same] using allowed
      · exact earlier project remaining

/-- At the first denied index, execution records the failed attempt and retains only
the individually authorized prefix as unlocked. -/
theorem batchUnlock_stop_on_first_failure (plan : BatchUnlockPlan) (authorize : ProjectId → Bool)
    (projects : List ProjectId) (prepared : prepareBatchUnlock plan = some projects)
    (k : Nat) (inBounds : k < projects.length)
    (attempted : k < (runBatchUnlock plan authorize).attempted.length)
    (denied : authorize projects[k] = false) :
    (∀ project ∈ projects.take k, authorize project = true) ∧
      runBatchUnlock plan authorize = ⟨projects.take (k + 1), projects.take k⟩ := by
  simp only [runBatchUnlock, prepared] at attempted ⊢
  exact executeBatch_first_failure authorize projects k inBounds attempted denied

/-- Apply one authorization decision to the resolved, deduplicated plan. The state
records whether each vault is unlocked. -/
def applyUnlockBatch (approved : Bool) (maxBatch : Nat) (plan : List ProjectId)
    (state : ProjectId → Bool) : ProjectId → Bool :=
  if approved = true ∧ plan.length ≤ maxBatch ∧ plan.isEmpty = false then
    fun project => if project ∈ plan then true else state project
  else state

theorem unlockBatch_cancelled_unlocks_none (maxBatch : Nat) (plan : List ProjectId)
    (state : ProjectId → Bool) : applyUnlockBatch false maxBatch plan state = state := by
  simp [applyUnlockBatch]

theorem unlockBatch_scope_bounded (approved : Bool) (maxBatch : Nat) (plan : List ProjectId)
    (state : ProjectId → Bool) (project : ProjectId) (outside : project ∉ plan) :
    applyUnlockBatch approved maxBatch plan state project = state project := by
  unfold applyUnlockBatch
  split <;> simp [outside]

/-- The Compose scanner supplies referenced keys. The overlap contains the sorted,
unique dotenv keys that Compose references. -/
def composeInterpolationOverlap (referencedKeys : List String) (doc : Document) : List String :=
  (inspectEnvKeys doc).keys.filter referencedKeys.contains

def composeInterpolationWarns (referencedKeys : List String) (doc : Document) : Bool :=
  !(composeInterpolationOverlap referencedKeys doc).isEmpty

theorem composeInterpolation_noninterference (referencedKeys : List String)
    (doc : Document) (replacement : Entry → String) :
    composeInterpolationOverlap referencedKeys (replaceValues doc replacement) =
      composeInterpolationOverlap referencedKeys doc ∧
    composeInterpolationWarns referencedKeys (replaceValues doc replacement) =
      composeInterpolationWarns referencedKeys doc := by
  simp [composeInterpolationWarns, composeInterpolationOverlap, inspectEnvKeys_noninterference]

inductive VerifyOutcome where
  | passed
  | failed (code : Nat)
  | timedOut
  | notRun
  deriving DecidableEq

structure VerifyPolicyInput where
  policyExists : Bool
  policyApproved : Bool
  vaultUnlocked : Bool
  -- `passed` means the command exited with code zero before the deadline.
  outcome : VerifyOutcome

def verifyPolicyAllowsArchive (input : VerifyPolicyInput) : Bool :=
  input.policyExists && input.policyApproved && input.vaultUnlocked &&
    decide (input.outcome = .passed)

theorem verifyPolicy_timeout_blocks_archive (input : VerifyPolicyInput)
    (timeout : input.outcome = .timedOut) :
    verifyPolicyAllowsArchive input = false := by
  simp [verifyPolicyAllowsArchive, timeout]

/-- A passing policy clears this gate. The archive destination and value-matching
checks still apply independently. -/
theorem verifyPolicy_gates_archive_on_approved_unlocked_zero_exit (input : VerifyPolicyInput) :
    verifyPolicyAllowsArchive input = true ↔
      input.policyExists = true ∧ input.policyApproved = true ∧ input.vaultUnlocked = true ∧
        input.outcome = .passed := by
  simp [verifyPolicyAllowsArchive, and_assoc]

structure FleetProgress where
  migrated : Nat
  staged : Nat
  uninitialized : Nat

/-- Discovered dotenv files contribute their project root and configuration status.
Configured roots without dotenv files count as migrated. -/
def envScanProgress (configuredProjects : List String) (workspace : List WorkspaceFile) :
    FleetProgress :=
  let projectFiles := workspace.map fun file => (file.projectRoot, file.hasConfig)
  let (stagedFiles, uninitializedFiles) := projectFiles.partition Prod.snd
  let stagedRoots := (stagedFiles.map Prod.fst).eraseDups
  let uninitializedRoots := (uninitializedFiles.map Prod.fst).eraseDups
  let migratedRoots := configuredProjects.eraseDups.filter fun root => !stagedRoots.contains root
  ⟨migratedRoots.length, stagedRoots.length, uninitializedRoots.length⟩

theorem envScanProgress_noninterference (configuredProjects : List String)
    (workspace : List WorkspaceFile) (replacement : WorkspaceFile → Entry → String) :
    envScanProgress configuredProjects (replaceWorkspaceValues workspace replacement) =
      envScanProgress configuredProjects workspace := by
  simp [envScanProgress, replaceWorkspaceValues, List.map_map, Function.comp_def]

structure PolicyApprovalState where
  sourceDigest : String
  approvedDigest : Option String
  deriving DecidableEq

/-- A CLI policy mutation updates `locket.toml` (`newDigest`), and refreshes the local
SQLite approval index only when running in an interactive human terminal (`!noPrompt ∧ stdinIsTty`). -/
def applyPolicyMutation (noPrompt stdinIsTty : Bool) (newDigest : String)
    (state : PolicyApprovalState) : PolicyApprovalState :=
  let approved := if !noPrompt && stdinIsTty then some newDigest else state.approvedDigest
  ⟨newDigest, approved⟩

def policyIsApproved (state : PolicyApprovalState) : Bool :=
  state.approvedDigest == some state.sourceDigest

/-- Non-interactive policy mutations (when `LOCKET_NO_PROMPT` is set or stdin is not a TTY)
never write or advance the approved digest, so new policies remain unapproved and modified
policies become unapproved until an explicit interactive refresh. -/
theorem noninteractive_policy_mutation_never_approves (noPrompt stdinIsTty : Bool)
    (noninteractive : noPrompt = true ∨ stdinIsTty = false)
    (newDigest : String) (state : PolicyApprovalState) :
    (applyPolicyMutation noPrompt stdinIsTty newDigest state).approvedDigest = state.approvedDigest ∧
      (state.approvedDigest ≠ some newDigest →
        policyIsApproved (applyPolicyMutation noPrompt stdinIsTty newDigest state) = false) := by
  have gateFalse : (!noPrompt && stdinIsTty) = false := by
    cases noninteractive with
    | inl h => simp [h]
    | inr h => simp [h]
  constructor
  · simp [applyPolicyMutation, gateFalse]
  · intro diff
    simp [policyIsApproved, applyPolicyMutation, gateFalse, diff]

end LocketProofs.MigrationSafety
