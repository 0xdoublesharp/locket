import type { DangerousProfileSetting, EffectiveUserVerificationSettings } from '../agent/types';

// Prop types for the metadata-only desktop views in `src/views/`.
// These mirror the Rust descriptor inventory in `crates/locket-app/src/lib.rs`
// and are kept in sync with the desktop UI spec.

export type LockState = 'locked' | 'unlocked' | 'unknown';

export interface SecretRowMeta {
  id: string;
  name: string;
  alias?: string;
  source: 'team' | 'user-local' | 'machine-local';
  required: boolean;
  optional: boolean;
  ownerLabel?: string;
  tags?: string[];
  createdAt: string; // ISO 8601
  rotatedAt?: string;
  currentVersion: number;
  hasDeprecatedGrace: boolean;
  deprecatedReferenceWarnings?: SecretDeprecationWarning[];
}

export type SecretDeprecationWarningStatus = 'active-grace' | 'expired-grace';
export type SecretDeprecationWarningSurface = 'policy' | 'command-preview';

export interface SecretDeprecationWarning {
  version: number;
  status: SecretDeprecationWarningStatus;
  surface: SecretDeprecationWarningSurface;
  graceUntil?: string;
  referenceCount: number;
}

export interface VersionHistoryRow {
  id?: string;
  secretName?: string;
  source?: string;
  version: number;
  state: 'current' | 'deprecated' | 'purged';
  deprecatedAt?: string; // ISO 8601
  graceUntil?: string; // ISO 8601
  pinnedReferenceEligible: boolean;
  scanInclusion: boolean;
  rotationAuditSummary?: string; // metadata-only summary, no values
}

export interface RuntimeSessionRow {
  sessionId: string;
  profile: string;
  profileAlias?: string;
  policy: string;
  policyAlias?: string;
  pid: number;
  processStartTime: string; // ISO 8601
  startedAt: string;
  endedAt?: string;
  exitStatus?: number;
  state: 'running' | 'completed' | 'failed' | 'stale';
  secretNameCount: number;
  spawnAuditSequence?: number;
  completionAuditSequence?: number;
}

export interface CommandPolicyRow {
  id: string;
  name: string;
  alias?: string;
  commandKind: 'argv' | 'shell';
  commandPreview: string;
  requiredSecrets: string[];
  optionalSecrets: string[];
  allowedSecrets: string[];
  confirm: boolean;
  requireUserVerification: boolean;
  requireAgent: boolean;
  allowRemoteDocker: boolean;
  ttlSeconds: number;
  envMode: 'minimal' | 'inherit' | 'strict';
  overrideMode: 'locket' | 'preserve' | 'fail';
  updatedAt: string; // ISO 8601
}

export interface DeviceMemberRow {
  id: string;
  kind: 'device' | 'member';
  name: string;
  alias?: string;
  role?: 'owner' | 'maintainer' | 'developer' | 'viewer';
  fingerprint?: string;
  fingerprintAlias?: string;
  trustedDeviceCount?: number;
  localDevice?: boolean;
  status: 'active' | 'revoked' | 'removed' | 'pending';
  createdAt: string; // ISO 8601
  lastSeenAt?: string;
}

export interface AuditLogRow {
  sequence: number;
  action: string; // e.g. 'REVEAL', 'COPY', 'RUN_POLICY'
  status: 'OK' | 'DENIED' | 'FAILED';
  timestamp: string; // ISO 8601
  profile?: string;
  profileAlias?: string;
  secretName?: string;
  secretAlias?: string;
  metadataJson: string; // pre-serialized, never raw object
  denialReason?: string;
  hmacOk: boolean | null;
}

export interface ScanFindingRow {
  id: string;
  rule: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  path: string;
  line: number;
  column: number;
  redactedSummary: string; // never the value
  suppressedBy?: string; // marker name if locket-allow line is present
}

export interface SettingsState {
  privacyRedactNames: boolean;
  unlockTtlSeconds: number;
  unlockTtl: string | null;
  verification: EffectiveUserVerificationSettings | null;
  dangerousProfile: DangerousProfileSetting | null;
  dangerousProfileFlag: boolean;
  agentVersion: string;
}

export type AppIconName =
  | 'brand-lock'
  | 'lock'
  | 'unlock'
  | 'folder'
  | 'key'
  | 'terminal'
  | 'activity'
  | 'users'
  | 'settings'
  | 'search'
  | 'copy'
  | 'link'
  | 'eye'
  | 'clock'
  | 'fingerprint'
  | 'refresh'
  | 'alert'
  | 'check'
  | 'plus'
  | 'cloud'
  | 'user'
  | 'laptop'
  | 'compass'
  | 'chevron-down'
  | 'x'
  | 'more';

export type PaletteGroup = 'Actions' | 'Views' | 'Projects' | 'Variables';

export interface PaletteAction {
  group?: PaletteGroup;
  icon?: AppIconName;
  badge?: string;
  id: string;
  label: string;
  detail?: string;
  keywords?: string;
}
