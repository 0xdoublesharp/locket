// Types mirroring locket-agent::StatusPayload and the Rust-side
// AgentClientError. Kept in sync by the locket-desktop tests/config.rs
// regression and the agent_client integration tests.

import type {
  TeamSyncCredentialMode,
  TeamSyncTransportKind,
  TeamSyncWebDavAuthKind,
} from '../team/sync';

export type LockState = 'locked' | 'unlocked' | 'unknown';

export interface AgentStatus {
  lock_state: LockState;
  project_id: string | null;
  profile_name: string | null;
  live_grant_count: number;
  agent_version: string;
  unlock_ttl_seconds: number | null;
  running_session_count: number;
  scan_warning_count: number;
  scan_warning_count_known?: boolean;
  recent_audit_status: 'unknown' | 'ok' | 'warning';
  pinned_reference_warning_count: number;
  session_monitoring?: string | null;
}

export type AgentStatusEventKind = 'status' | 'heartbeat';

export interface AgentStatusEvent extends AgentStatus {
  kind: AgentStatusEventKind;
  sequence: number;
}

export type AgentClientError =
  | {
      kind: 'unavailable';
      reason: string;
      display_reason: string;
      next_action: string;
      socket_path: string;
    }
  | {
      kind: 'protocol';
      reason: string;
    }
  | {
      kind: 'rejected';
      code: string;
      message: string;
      display_reason: string;
      next_action: string;
      retryable: boolean;
    };

export function isUnavailable(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'unavailable' }> {
  return error.kind === 'unavailable';
}

export function isProtocol(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'protocol' }> {
  return error.kind === 'protocol';
}

export function isRejected(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'rejected' }> {
  return error.kind === 'rejected';
}

// RPC payloads. Mirrors the wire shapes in locket-agent/src/{reveal,scan,resolve,prepare_exec}.rs.
// Names use snake_case to match the agent's serde defaults.

export interface RevealRequest {
  secret_name: string;
  profile_id: string;
  confirm_dangerous_profile?: string;
}

export interface RevealResponse {
  value: string;
  ttl_seconds: number;
}

export type CopyRequest = RevealRequest;
export type CopyResponse = RevealResponse;

export interface ScanInput {
  path: string;
  text: string;
}

export interface ScanRequest {
  inputs: ScanInput[];
  project_id: string;
  profile_id: string;
  store_path: string;
  grant_id: string;
  require_known: boolean;
}

export interface ScanFinding {
  rule: string;
  path: string;
  line: number;
  column: number;
  severity: string;
  redacted_summary: string;
  suppressed_by: string | null;
}

export interface ScanResponse {
  findings: ScanFinding[];
  locked: boolean;
}

export interface ResolveRequest {
  reference: string;
  project_id?: string;
  profile_id?: string;
  store_path?: string;
  grant_id?: string;
  binding?: GrantBinding;
}

export interface ResolveResponse {
  value: string;
  version: number;
  profile_id: string;
}

export interface PrepareExecRequest {
  policy_name: string;
  profile_id: string;
  project_id?: string;
  binding?: GrantBinding;
  confirm_dangerous_profile?: string;
}

export interface GrantBinding {
  pid: number;
  process_start_time: string;
}

export interface PrepareExecResponse {
  allowed_env_names: string[];
  command_kind: string;
  grant_id: string;
  ttl_seconds: number;
}

export type RuntimeSessionState = 'running' | 'completed' | 'failed' | 'stale';

export interface ListRuntimeSessionsRequest {
  project_id: string;
  profile_id: string;
  privacy_redact_names: boolean;
}

export interface RuntimeSessionWireRow {
  session_id: string;
  profile: string;
  profile_alias?: string;
  policy: string;
  policy_alias?: string;
  pid: number;
  process_start_time: number;
  started_at: number;
  ended_at?: number;
  exit_status?: number;
  state: RuntimeSessionState;
  secret_name_count: number;
  spawn_audit_sequence?: number;
  completion_audit_sequence?: number;
}

export interface ListRuntimeSessionsResponse {
  rows: RuntimeSessionWireRow[];
}

export interface ListPoliciesRequest {
  project_id: string;
  privacy_redact_names: boolean;
}

export type CommandKindWire = 'argv' | 'shell';
export type CommandEnvModeWire = 'minimal' | 'inherit' | 'strict';
export type CommandOverrideModeWire = 'locket' | 'preserve' | 'fail';

export interface CommandPolicyWireRow {
  id: string;
  name: string;
  alias?: string;
  command_kind: CommandKindWire;
  command_preview: string;
  required_secrets: string[];
  optional_secrets: string[];
  allowed_secrets: string[];
  confirm: boolean;
  require_user_verification: boolean;
  require_agent: boolean;
  allow_remote_docker: boolean;
  ttl_seconds: number;
  env_mode: CommandEnvModeWire;
  override_mode: CommandOverrideModeWire;
  updated_at_unix_nanos: number;
}

export interface ListPoliciesResponse {
  rows: CommandPolicyWireRow[];
}

/**
 * Wire shape mirroring `locket_agent::CommandPolicySnapshot`. Used by
 * the desktop policy editor when calling `agent_register_command_policies`
 * to replace the agent's in-memory project snapshot. Field set is
 * metadata-only — never includes a secret value.
 */
export interface CommandPolicySnapshotWire {
  project_id: string;
  name: string;
  command_kind: CommandKindWire;
  command_preview: string;
  required_secrets: string[];
  optional_secrets: string[];
  allowed_secrets: string[];
  confirm: boolean;
  require_user_verification: boolean;
  require_agent: boolean;
  allow_remote_docker: boolean;
  ttl_seconds: number;
  env_mode: CommandEnvModeWire;
  override_mode: CommandOverrideModeWire;
  updated_at_unix_nanos: number;
}

export interface RegisterCommandPoliciesRequest {
  project_id: string;
  policies: CommandPolicySnapshotWire[];
  store_path?: string;
  audit_profile_id?: string;
}

export interface PolicyDoctorRequest {
  project_id: string;
  profile_id: string;
  policy: CommandPolicySnapshotWire;
  references?: string[];
  store_path?: string;
}

export interface PolicyDoctorResponse {
  status: 'pass' | 'fail';
  allowed_env_names: string[];
  ttl_seconds: number;
  references_ok: number;
  references_failed: string[];
  env_mode_passthrough: string[];
  env_mode_resolve: string[];
  env_mode_denied: string[];
}

export type BundleExportScope = 'active-profile' | 'all-profiles';
export type BundleConflictMode = 'review' | 'accept-incoming' | 'accept-local';
export type RecoveryVerification = 'platform' | 'current-code';

export interface ExportBundleRequest {
  project_id: string;
  profile_id?: string | null;
  recipient_descriptor: string;
  scope: BundleExportScope;
  include_audit: boolean;
  output_path?: string | null;
  include_personal?: boolean;
  include_history?: boolean;
  preview_only?: boolean;
  confirm_dangerous_profile?: string;
}

export interface ImportBundleRequest {
  project_id: string;
  bundle_path: string;
  include_audit: boolean;
  conflict_mode: BundleConflictMode;
  confirm_dangerous_profile?: string;
}

export interface VerifyBundleRequest {
  bundle_path: string;
  require_decryptable: boolean;
}

export interface RecoveryRotateRequest {
  project_id: string;
  verification: RecoveryVerification;
  acknowledged_one_time_display: boolean;
  clear_after_display: boolean;
}

export interface BackupActionResponse {
  action: string;
  status: string;
  message: string;
}

export interface VerifyBundleResponse {
  structural_valid: boolean;
  schema_version: number;
  project_id: string;
  profile_count: number;
  recipient_count: number;
  payload_digest: string;
  decryptable_by_this_device?: boolean | null;
  message: string;
}

/**
 * Wire shape for `agent_set_active_profile`. Mirrors the desktop's
 * `DesktopSetActiveProfileRequest` so the webview only fills the
 * fields it actually owns; the Tauri command supplies defaults for
 * the rest.
 */
export interface SetActiveProfileRequest {
  config_path?: string;
  store_path?: string;
  project_id: string;
  profile_name: string;
  confirmation?: string;
  privacy_redact_names?: boolean;
  root_hash?: string;
}

export interface SetActiveProfileResponse {
  changed: boolean;
  profile_id: string;
  profile_name: string;
  profile_label: string;
  dangerous: boolean;
  prior_profile_id: string;
  prior_profile_name: string;
  prior_profile_label: string;
  live_grants_revoked: number;
}

export interface ListDeviceMembersRequest {
  store_path?: string;
  project_id: string;
  redact_names: boolean;
  include_revoked_devices?: boolean;
}

export type DeviceMemberKindWire = 'device' | 'member';
export type DeviceMemberStatusWire = 'active' | 'revoked' | 'removed';

export interface DeviceMemberWireRow {
  id: string;
  kind: DeviceMemberKindWire;
  name: string;
  alias?: string;
  role?: 'owner' | 'maintainer' | 'developer' | 'viewer' | 'read-only';
  fingerprint?: string;
  fingerprint_alias?: string;
  trusted_device_count?: number;
  local_device?: boolean;
  status: DeviceMemberStatusWire;
  created_at: number;
  last_seen_at?: number;
}

export interface ListDeviceMembersResponse {
  rows: DeviceMemberWireRow[];
}

export interface ListSecretsRequest {
  store_path?: string;
  project_id: string;
  profile_id: string;
  redact_names: boolean;
}

export type VersionSourceWire = 'team-managed' | 'user-local' | 'machine-local';
export type SecretSourceWire = VersionSourceWire | 'shared-link';

export interface SecretMetadataRecord {
  id: string;
  profile_id: string;
  name: string;
  source: SecretSourceWire;
  source_precedence: number;
  origin: string;
  current_version: number;
  state: string;
  required: boolean;
  optional?: boolean;
  owner?: string;
  tags?: string[];
  created_at: number;
  updated_at: number;
  last_rotated_at: number | null;
  linked_target_secret_id?: string | null;
  linked_target_name?: string | null;
  link_count?: number;
}

export type SecretWireRow = SecretMetadataRecord;

export interface ProjectListRequest {
  store_path?: string;
  redact_names?: boolean;
}

export interface DiscoverSecretsRequest extends ProjectListRequest {
  project?: string;
  profile?: string;
  query?: string;
  name_glob?: string;
  tag?: string;
  owner?: string;
  source?: string;
  include_deleted?: boolean;
  limit?: number;
}

export interface ProjectSummaryWire {
  project_id: string;
  name: string;
  profiles: { id: string; name: string; dangerous: boolean }[];
  trusted_roots: string[];
  active_secret_count: number;
}

export interface DiscoveredSecretWire {
  project_id: string;
  project_name: string;
  trusted_roots: string[];
  profile_id: string;
  profile: string;
  dangerous: boolean;
  secret_id: string;
  name: string;
  source: string;
  source_precedence: number;
  origin: string;
  version: number;
  state: string;
  description: string | null;
  owner: string | null;
  tags: string[];
  required: boolean;
  created_at: number;
  updated_at: number;
  last_rotated_at: number | null;
  reference: string;
  expiry_status?: 'expired' | 'expiring_soon' | null;
  expires_at?: number | null;
  rotate_after_days?: number | null;
  stale?: boolean;
}

export interface DesktopFilePickerOptions {
  title?: string;
  save?: boolean;
  defaultName?: string;
}

export interface DesktopMcpConfigSnippet {
  command: string;
  args: string[];
  json: string;
}

export interface ListSecretsResponse {
  rows: SecretWireRow[];
}

export interface ReadConfigRequest {
  config_path?: string | null;
  store_path?: string | null;
  project_id?: string | null;
  profile_name?: string | null;
}

export interface WriteConfigRequest {
  config_path?: string | null;
  store_path?: string | null;
  project_id: string;
  profile_name?: string | null;
  changes: WriteConfigChanges;
}

export interface WriteConfigChanges {
  privacy_redact_names?: boolean | null;
  agent_unlock_ttl?: string | null;
  user_verification_required_for?: UserVerificationSettings | null;
  dangerous_profile?: boolean | null;
}

export interface UserVerificationSettings {
  unlock?: boolean | null;
  reveal?: boolean | null;
  copy?: boolean | null;
  dangerous_profile_switch?: boolean | null;
  recovery?: boolean | null;
  team_accept?: boolean | null;
  device_register?: boolean | null;
}

export interface EffectiveUserVerificationSettings {
  unlock: boolean;
  reveal: boolean;
  copy: boolean;
  dangerous_profile_switch: boolean;
  recovery: boolean;
  team_accept: boolean;
  device_register: boolean;
}

export interface DangerousProfileSetting {
  profile_id: string;
  profile_name: string;
  profile_label: string;
  dangerous: boolean;
}

export interface AgentConfigSettings {
  privacy_redact_names: boolean;
  agent_unlock_ttl: string | null;
  user_verification_required_for: EffectiveUserVerificationSettings;
  dangerous_profile: DangerousProfileSetting | null;
}

export interface WriteConfigResponse {
  settings: AgentConfigSettings;
  changed_keys: string[];
}

export interface ListAuditRequest {
  store_path?: string | null;
  project_id: string;
  profile_id?: string | null;
  action?: string | null;
  status?: string | null;
  since_unix_nanos?: number | null;
  until_unix_nanos?: number | null;
  limit?: number | null;
  redact_names?: boolean;
}

export interface AuditChainStatus {
  hmac_ok: boolean | null;
  first_break_sequence: number | null;
  rows_verified: number;
  locked: boolean;
}

export interface AuditWireRow {
  sequence: number;
  timestamp: number;
  profile_id: string | null;
  action: string;
  status: string;
  secret_name: string | null;
  command: string | null;
}

export interface ListAuditResponse {
  rows: AuditWireRow[];
  chain_status: AuditChainStatus;
}

export interface VerifyAuditRequest {
  project_id: string;
}

export interface VerifyAuditResponse {
  hmac_ok: boolean | null;
  first_break_sequence: number | null;
  first_break_reason: string | null;
  rows_verified: number;
  locked: boolean;
}

export interface ListVersionsRequest {
  store_path?: string;
  project_id: string;
  profile_id: string;
  secret_name?: string;
  source?: string;
  now_unix_nanos: number;
  redact_names: boolean;
}

export type VersionStateWire = 'current' | 'deprecated' | 'purged';

export interface VersionWireRow {
  secret_id: string;
  profile_id: string;
  name: string;
  source: VersionSourceWire;
  source_precedence: number;
  origin: string;
  secret_state: string;
  current_version: number;
  last_rotated_at: number | null;
  version: number;
  version_state: VersionStateWire;
  created_at: number;
  deprecated_at: number | null;
  grace_until: number | null;
  purged_at: number | null;
  pinned_reference_eligible: boolean;
  scan_included: boolean;
}

export interface ListVersionsResponse {
  rows: VersionWireRow[];
}

export interface DesktopProjectContext {
  root: string;
  project_id: string;
  project_name: string;
  profile_id: string;
  profile_name: string;
  is_shared?: boolean;
}
export interface DesktopFolderInspection {
  path: string;
  has_config: boolean;
  folder_name: string;
}
export interface DesktopImportEnvRequest {
  confirmation?: string;
  project_id: string;
  path: string;
  overwrite: boolean;
  literal: boolean;
  target_confirmation?: string;
  dry_run?: boolean;
  link_to_shared?: Record<string, string>;
  promote_to_shared?: Record<string, string>;
}

export interface ImportDuplicateMatch {
  local_name: string;
  match_kind: 'shared' | 'project';
  matched_project_id: string;
  matched_project_name: string;
  matched_profile_name: string;
  matched_secret_id: string;
  matched_secret_name: string;
  is_shared: boolean;
}

export interface DesktopImportEnvResponse {
  summary: string;
  imported: number;
  overwritten: number;
  skipped: number;
  linked: number;
  promoted: number;
  duplicate_matches: ImportDuplicateMatch[];
}
export interface DesktopCreateProfileRequest {
  project_id: string;
  profile_name: string;
}
export interface DesktopCreateProfileResponse {
  profile_id: string;
  profile_name: string;
  dangerous: boolean;
  created: boolean;
}
export interface DesktopDeleteSecretRequest {
  project_id: string;
  profile_id: string;
  secret_name: string;
  source: VersionSourceWire;
  confirmation?: string;
  unlink_all?: boolean;
  expected_link_ids?: string[];
}
export interface DesktopDeleteSecretResponse {
  secret_name: string;
  source: VersionSourceWire;
  version: number;
  deleted: boolean;
  unlinked_count?: number;
}
export interface DesktopCopySecretToSharedRequest {
  from_project_id: string;
  from_profile_id: string;
  secret_name: string;
  source?: VersionSourceWire;
  overwrite?: boolean;
  target_name?: string;
  replace_with_link?: boolean;
  consolidate_duplicates?: boolean;
  confirmation?: string;
}
export interface DesktopCopySecretToSharedResponse {
  target_project_id: string;
  target_profile_id: string;
  secret_name: string;
  version: number;
  action: 'create' | 'rotate' | 'reuse';
  linked?: boolean;
  consolidated_count?: number;
  skipped_locked_count?: number;
}
export interface DesktopUnlinkSecretRequest {
  project_id: string;
  profile_id: string;
  local_name: string;
  confirmation?: string;
}

export interface DesktopLinkSecretRequest extends DesktopUnlinkSecretRequest {
  target_secret_name: string;
}

export interface DesktopLinkSecretResponse {
  link_id: string;
  local_name: string;
  target_project_id: string;
  target_secret_id: string;
  target_secret_name: string;
}

export interface DesktopUnlinkSecretResponse {
  local_name: string;
  unlinked: boolean;
}

export interface DesktopListSharedUsagesRequest {
  target_secret_id: string;
  redact_names?: boolean;
}

export interface SharedUsageRow {
  link_id: string;
  project_id: string;
  project_name: string;
  profile_id: string;
  profile_name: string;
  profile_dangerous: boolean;
  local_name: string;
  target_secret_id: string;
  target_secret_name: string;
  created_at: number;
  updated_at: number;
}

export interface DesktopListSharedUsagesResponse {
  usages: SharedUsageRow[];
}

export interface DesktopListDuplicatesRequest {
  redact_names?: boolean;
}

export interface DuplicateMemberRow {
  secret_id: string;
  project_id: string;
  project_name: string;
  is_shared: boolean;
  profile_id: string;
  profile_name: string;
  profile_dangerous: boolean;
  name: string;
  source: VersionSourceWire;
  current_version: number;
  updated_at: number;
}

export interface DuplicateGroupRow {
  group_id: string;
  members: DuplicateMemberRow[];
}

export interface DesktopListDuplicatesResponse {
  groups: DuplicateGroupRow[];
}

export interface DesktopDetectCommandsRequest {
  project_id: string;
}
export interface DetectedCommandRow {
  name: string;
  argv: string[];
  command_preview: string;
  source_file: string;
  already_configured: boolean;
}
export interface DesktopSavePolicyRequest {
  project_id: string;
  mode: 'create' | 'edit' | 'delete';
  original_name: string;
  policy: CommandPolicySnapshotWire;
  confirmation?: string;
}
export interface UnlockRequest {
  project_id: string;
  ttl_seconds: number;
  source: { kind: 'os-keychain' } | { kind: 'passphrase'; passphrase: string };
  audit?: { profile_id: string };
}

export interface VariableReadinessRow {
  name: string;
  required: boolean;
  classification: 'secret' | 'public';
  state: 'ready' | 'missing' | 'optional' | 'unverified';
  selected_source?: string | null;
  description?: string | null;
  setup_hint?: string | null;
  next_action?: string | null;
  warning?: string | null;
}
export interface VariableReadinessResponse {
  project_id: string;
  profile_id: string;
  profile_name: string;
  policies: {
    policy_name: string;
    profile_id: string;
    rows: VariableReadinessRow[];
    error?: string | null;
  }[];
}
export type TeamSyncStatus = import('../team/sync').TeamSyncStatus;

export type TeamSyncTransportInput =
  | { kind: 'folder'; path: string }
  | {
      kind: 's3';
      bucket: string;
      region: string;
      prefix?: string;
      endpoint?: string;
      path_style?: boolean;
      credential_mode: 'vault' | 'env';
      access_key_id?: string;
      secret_access_key?: string;
      session_token?: string;
    }
  | {
      kind: 'webdav';
      url: string;
      credential_mode: TeamSyncCredentialMode;
      auth_kind?: TeamSyncWebDavAuthKind;
      username?: string;
      secret?: string;
    };

export interface TeamSyncTestResult {
  ok: boolean;
  transport_kind: TeamSyncTransportKind;
  target: string;
  package_count: number;
  writable_checked: boolean;
  message: string;
}

export interface TeamSyncRenameProfileRequest {
  project_id: string;
  incoming_profile_id: string;
  local_profile_id: string;
  new_name: string;
  confirm_dangerous_profile?: string;
}
export interface TeamSyncPreserveOverrideRequest {
  project_id: string;
  incoming_profile_id: string;
  local_secret_id: string;
  confirm_dangerous_profile?: string;
}
