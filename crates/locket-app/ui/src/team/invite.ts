// Pure model + validators for the desktop team-invite editor.
//
// The Vue view (`TeamInviteView.vue`) is a thin wrapper that delegates
// validation, payload construction, and dangerous-profile gating to
// these helpers so the form behavior is unit-testable without spinning
// up jsdom.
//
// Desktop invite history is reconstructed from `TEAM_INVITE` audit
// rows. The forms use the same validation rules as the CLI so the user
// gets local feedback before switching to the CLI for invite changes.

import type { AuditWireRow } from '../agent/types';
import { parseCommaList } from '../utils/lists';

export type TeamInviteRole = 'owner' | 'maintainer' | 'developer' | 'read-only';

export interface TeamInviteIssueFormState {
  /** Display label of the recipient member, used only as a metadata label. */
  recipientLabel: string;
  /** Recipient device descriptor, `lkdev2_<base64url>`. */
  deviceDescriptor: string;
  /** Role granted by the invite. */
  role: TeamInviteRole;
  /** Comma-separated profile names that the invite includes. */
  profiles: string;
  /** Comma-separated profile names flagged as dangerous in agent settings. */
  dangerousProfiles: string;
  /** Optional invite expiry, ISO 8601 datetime-local string. */
  expiresAt: string;
}

export interface TeamInviteAcceptFormState {
  /** Pasted invite text — armored payload, no key material exposed in UI state. */
  inviteText: string;
  /** Issuer device fingerprint the user typed for confirmation. */
  fingerprintConfirmation: string;
  /** Whether the user-verification gate is enforced for `team_accept`. */
  requireUserVerification: boolean;
  /** Whether the user provided fresh user verification. */
  userVerified: boolean;
}

export interface TeamInviteRevokeFormState {
  /** Invite id to revoke. */
  inviteId: string;
  /** Issuer typed-confirmation: must match `inviteId` exactly. */
  confirmation: string;
}

export interface TeamInviteIssueValidation {
  errors: Partial<Record<keyof TeamInviteIssueFormState, string>>;
  /** Profiles flagged dangerous that appear in `profiles`. */
  dangerousMatches: string[];
  valid: boolean;
}

export interface TeamInviteAcceptValidation {
  errors: Partial<Record<keyof TeamInviteAcceptFormState, string>>;
  valid: boolean;
}

export interface TeamInviteRevokeValidation {
  errors: Partial<Record<keyof TeamInviteRevokeFormState, string>>;
  valid: boolean;
}

export interface TeamInviteCreatePayload {
  recipient_label: string;
  device_descriptor: string;
  role: TeamInviteRole;
  profiles: string[];
  expires_at_unix_nanos: number | null;
  /** Echoed when one of `profiles` matches a dangerous-profile name. */
  dangerous_profile_confirmation: string[];
}

export interface TeamInviteAcceptPayload {
  invite_text: string;
  fingerprint_confirmation: string;
  user_verified: boolean;
}

export interface TeamInviteRevokePayload {
  invite_id: string;
}

const DEVICE_DESCRIPTOR_PREFIX = 'lkdev2_';
const INVITE_ID_PREFIX = 'lk_invite_';
const PROFILE_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;
const FINGERPRINT_HEX_PATTERN = /^[0-9a-f]{64}$/i;

interface TeamInviteIssueCommandOptions {
  nowMs?: number;
}

export const TEAM_INVITE_DESKTOP_NOTICE =
  'Desktop invite history is reconstructed from metadata-only audit rows. ' +
  'Use the Locket CLI to issue, accept, or revoke team invites.';

export function defaultIssueForm(): TeamInviteIssueFormState {
  return {
    recipientLabel: '',
    deviceDescriptor: '',
    role: 'developer',
    profiles: '',
    dangerousProfiles: '',
    expiresAt: '',
  };
}

export function defaultAcceptForm(): TeamInviteAcceptFormState {
  return {
    inviteText: '',
    fingerprintConfirmation: '',
    requireUserVerification: false,
    userVerified: false,
  };
}

export function defaultRevokeForm(): TeamInviteRevokeFormState {
  return { inviteId: '', confirmation: '' };
}

/** Normalize a `profile, profile2` list into a deduped, trimmed array. */
export function parseProfileList(raw: string): string[] {
  return parseCommaList(raw);
}

export function validateIssueForm(state: TeamInviteIssueFormState): TeamInviteIssueValidation {
  const errors: Partial<Record<keyof TeamInviteIssueFormState, string>> = {};

  const label = state.recipientLabel.trim();
  if (label.length === 0) {
    errors.recipientLabel = 'Recipient label is required.';
  } else if (label.length > 128) {
    errors.recipientLabel = 'Label is too long (max 128).';
  }

  const descriptor = state.deviceDescriptor.trim();
  if (descriptor.length === 0) {
    errors.deviceDescriptor = 'Device descriptor is required.';
  } else if (!descriptor.startsWith(DEVICE_DESCRIPTOR_PREFIX)) {
    errors.deviceDescriptor = `Descriptor must begin with ${DEVICE_DESCRIPTOR_PREFIX}.`;
  } else if (descriptor.length < DEVICE_DESCRIPTOR_PREFIX.length + 16) {
    errors.deviceDescriptor = 'Descriptor body is too short to be valid.';
  }

  const profiles = parseProfileList(state.profiles);
  if (profiles.length === 0) {
    errors.profiles = 'At least one profile is required.';
  } else {
    for (const profile of profiles) {
      if (!PROFILE_NAME_PATTERN.test(profile)) {
        errors.profiles = `Invalid profile name: ${profile}`;
        break;
      }
    }
  }

  const dangerous = new Set(parseProfileList(state.dangerousProfiles));
  const dangerousMatches = profiles.filter((profile) => dangerous.has(profile));

  if (state.expiresAt.trim().length > 0) {
    const parsed = Date.parse(state.expiresAt);
    if (Number.isNaN(parsed)) {
      errors.expiresAt = 'Expiry must be an ISO 8601 datetime.';
    } else if (parsed <= Date.now()) {
      errors.expiresAt = 'Expiry must be in the future.';
    }
  }

  return {
    errors,
    dangerousMatches,
    valid: Object.keys(errors).length === 0,
  };
}

/** Whether the dangerous-profile typed gate must be satisfied before submit. */
export function issueRequiresDangerousConfirmation(validation: TeamInviteIssueValidation): boolean {
  return validation.dangerousMatches.length > 0;
}

/** True when each dangerous profile name was typed in the confirmation list. */
export function issueDangerousConfirmationMatches(
  validation: TeamInviteIssueValidation,
  typed: string,
): boolean {
  if (validation.dangerousMatches.length === 0) {
    return true;
  }
  const typedSet = new Set(parseProfileList(typed));
  return validation.dangerousMatches.every((profile) => typedSet.has(profile));
}

export function issueFormToPayload(state: TeamInviteIssueFormState): TeamInviteCreatePayload {
  const profiles = parseProfileList(state.profiles);
  const dangerous = new Set(parseProfileList(state.dangerousProfiles));
  const dangerousMatches = profiles.filter((profile) => dangerous.has(profile));
  const expiresAt = state.expiresAt.trim();
  const expiresAtUnixNanos = expiresAt.length === 0 ? null : Date.parse(expiresAt) * 1_000_000;
  return {
    recipient_label: state.recipientLabel.trim(),
    device_descriptor: state.deviceDescriptor.trim(),
    role: state.role,
    profiles,
    expires_at_unix_nanos: expiresAtUnixNanos,
    dangerous_profile_confirmation: dangerousMatches,
  };
}

export function validateAcceptForm(state: TeamInviteAcceptFormState): TeamInviteAcceptValidation {
  const errors: Partial<Record<keyof TeamInviteAcceptFormState, string>> = {};

  const text = state.inviteText.trim();
  if (text.length === 0) {
    errors.inviteText = 'Paste the invite text.';
  } else if (text.length < 64) {
    errors.inviteText = 'Invite payload is too short to be valid.';
  }

  const fingerprint = state.fingerprintConfirmation.trim();
  if (fingerprint.length === 0) {
    errors.fingerprintConfirmation =
      'Type the issuer device fingerprint to confirm out-of-band verification.';
  } else if (!FINGERPRINT_HEX_PATTERN.test(fingerprint)) {
    errors.fingerprintConfirmation =
      'Fingerprint must be 64 hexadecimal characters (lowercase or uppercase).';
  }

  if (state.requireUserVerification && !state.userVerified) {
    errors.userVerified = 'Fresh local user verification required for team_accept.';
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

export function acceptFormToPayload(state: TeamInviteAcceptFormState): TeamInviteAcceptPayload {
  return {
    invite_text: state.inviteText.trim(),
    fingerprint_confirmation: state.fingerprintConfirmation.trim().toLowerCase(),
    user_verified: state.userVerified,
  };
}

export function validateRevokeForm(state: TeamInviteRevokeFormState): TeamInviteRevokeValidation {
  const errors: Partial<Record<keyof TeamInviteRevokeFormState, string>> = {};

  const id = state.inviteId.trim();
  if (id.length === 0) {
    errors.inviteId = 'Invite id is required.';
  } else if (hasControlCharacter(id)) {
    errors.inviteId = 'Invite id must not contain control characters.';
  } else if (!id.startsWith(INVITE_ID_PREFIX) || id.length === INVITE_ID_PREFIX.length) {
    errors.inviteId = `Invite id must begin with ${INVITE_ID_PREFIX}.`;
  }

  const confirmation = state.confirmation.trim();
  if (confirmation.length === 0) {
    errors.confirmation = 'Type the invite id to confirm revocation.';
  } else if (confirmation !== id) {
    errors.confirmation = 'Confirmation must match the invite id exactly.';
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

export function revokeFormToPayload(state: TeamInviteRevokeFormState): TeamInviteRevokePayload {
  return { invite_id: state.inviteId.trim() };
}

export function teamInviteIssueCliCommand(
  state: TeamInviteIssueFormState,
  options: TeamInviteIssueCommandOptions = {},
): string {
  return inviteCreateCliCommand('locket team invite', state, options);
}

export function teamInviteAcceptCliCommand(inviteText: string): string {
  return inviteAcceptCliCommand('locket team accept -', inviteText);
}

export function teamInviteRevokeCliCommand(inviteId: string): string {
  return `locket team revoke-invite ${shellQuote(inviteId.trim())}`;
}

export function agentInviteRequestCliCommand(deviceDescriptor: string): string {
  return `locket agent invite request --device ${shellQuote(deviceDescriptor.trim())}`;
}

export function agentInviteCreateCliCommand(
  state: TeamInviteIssueFormState,
  options: TeamInviteIssueCommandOptions = {},
): string {
  return inviteCreateCliCommand('locket agent invite create', state, options);
}

export function agentInviteAcceptCliCommand(inviteText: string): string {
  return inviteAcceptCliCommand('locket agent invite accept -', inviteText, 'LOCKET_AGENT_INVITE');
}

function inviteCreateCliCommand(
  baseCommand: string,
  state: TeamInviteIssueFormState,
  options: TeamInviteIssueCommandOptions,
): string {
  const profiles = parseProfileList(state.profiles)
    .map((profile) => `--profile ${shellQuote(profile)}`)
    .join(' ');
  const expiresIn = expiresAtToDurationArgument(state.expiresAt, options.nowMs ?? Date.now());
  return [
    baseCommand,
    shellQuote(state.recipientLabel.trim()),
    '--device',
    shellQuote(state.deviceDescriptor.trim()),
    profiles,
    '--role',
    state.role,
    expiresIn === null ? '' : '--expires-in',
    expiresIn === null ? '' : shellQuote(expiresIn),
  ]
    .filter((part) => part.length > 0)
    .join(' ');
}

function inviteAcceptCliCommand(
  command: string,
  inviteText: string,
  baseDelimiter = 'LOCKET_INVITE',
): string {
  const text = inviteText.trim();
  const delimiter = heredocDelimiterFor(text, baseDelimiter);
  return `cat <<'${delimiter}' | ${command}\n${text}\n${delimiter}`;
}

export function expiresAtToDurationArgument(
  expiresAt: string,
  nowMs: number = Date.now(),
): string | null {
  const trimmed = expiresAt.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const parsed = Date.parse(trimmed);
  if (Number.isNaN(parsed) || parsed <= nowMs) {
    return null;
  }
  const seconds = Math.max(1, Math.ceil((parsed - nowMs) / 1_000));
  const units: Array<[suffix: string, seconds: number]> = [
    ['w', 604_800],
    ['d', 86_400],
    ['h', 3_600],
    ['m', 60],
  ];
  for (const [suffix, unitSeconds] of units) {
    if (seconds % unitSeconds === 0) {
      return `${(seconds / unitSeconds).toString()}${suffix}`;
    }
  }
  return `${seconds.toString()}s`;
}

function heredocDelimiterFor(text: string, baseDelimiter = 'LOCKET_INVITE'): string {
  const usedLines = new Set(text.split(/\r?\n/));
  let delimiter = baseDelimiter;
  let suffix = 0;
  while (usedLines.has(delimiter)) {
    suffix += 1;
    delimiter = `${baseDelimiter}_${suffix.toString()}`;
  }
  return delimiter;
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) {
    return value;
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export type TeamInviteDirection = 'issued' | 'received' | 'unknown';
export type TeamInviteStatus = 'pending' | 'accepted' | 'revoked' | 'expired' | 'unknown';

export interface TeamInviteRow {
  id: string;
  direction: TeamInviteDirection;
  status: TeamInviteStatus;
  recipientLabel?: string;
  issuerLabel?: string;
  role?: TeamInviteRole;
  profiles: string[];
  /** ISO 8601 timestamp when the invite or audit event was recorded. */
  createdAt: string;
  /** ISO 8601 timestamp parsed from invite metadata when present. */
  expiresAt?: string;
}

export function filterTeamInviteRows(
  rows: readonly TeamInviteRow[],
  query: string,
): readonly TeamInviteRow[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (normalizedQuery.length === 0) {
    return rows;
  }
  return rows.filter((row) => teamInviteSearchText(row).includes(normalizedQuery));
}

function teamInviteSearchText(row: TeamInviteRow): string {
  return [
    row.id,
    row.recipientLabel ?? '',
    row.issuerLabel ?? '',
    row.role ?? '',
    row.status,
    row.direction,
    row.profiles.join(' '),
  ]
    .join(' ')
    .toLowerCase();
}

interface AuditMetadata {
  invite_id?: string;
  recipient_label?: string;
  issuer_label?: string;
  role?: string;
  profiles?: string[];
  expires_at_unix_nanos?: number;
  direction?: string;
  [key: string]: unknown;
}

/**
 * Reconstruct a metadata-only invite row list from `TEAM_INVITE`
 * audit rows.
 */
export function teamInviteRowsFromAudit(
  rows: ReadonlyArray<AuditWireRow>,
  options: { now_unix_nanos: number } = { now_unix_nanos: Date.now() * 1_000_000 },
): TeamInviteRow[] {
  const byId = new Map<string, TeamInviteRow>();
  const orderedIds: string[] = [];

  for (const row of rows) {
    if (row.action !== 'TEAM_INVITE') {
      continue;
    }
    const metadata = parseAuditMetadata(row.command);
    const id = metadata.invite_id ?? `seq-${row.sequence.toString()}`;
    const status = metadataStatus(row.status, metadata, options.now_unix_nanos);
    const existing = byId.get(id);
    const merged: TeamInviteRow = {
      id,
      direction: parseDirection(metadata.direction) ?? existing?.direction ?? 'unknown',
      status,
      recipientLabel: metadata.recipient_label ?? existing?.recipientLabel,
      issuerLabel: metadata.issuer_label ?? existing?.issuerLabel,
      role: parseRole(metadata.role) ?? existing?.role,
      profiles: Array.isArray(metadata.profiles) ? metadata.profiles : (existing?.profiles ?? []),
      createdAt: existing?.createdAt ?? unixNanosToIso(row.timestamp),
      expiresAt:
        typeof metadata.expires_at_unix_nanos === 'number'
          ? unixNanosToIso(metadata.expires_at_unix_nanos)
          : existing?.expiresAt,
    };
    byId.set(id, merged);
    if (existing === undefined) {
      orderedIds.push(id);
    }
  }

  return orderedIds
    .map((id) => byId.get(id))
    .filter((row): row is TeamInviteRow => row !== undefined);
}

function parseAuditMetadata(command: string | null | undefined): AuditMetadata {
  if (typeof command !== 'string' || command.length === 0) {
    return {};
  }
  try {
    const parsed = JSON.parse(command) as unknown;
    if (parsed === null || typeof parsed !== 'object') {
      return {};
    }
    return parsed as AuditMetadata;
  } catch {
    return {};
  }
}

function parseDirection(raw: string | undefined): TeamInviteDirection | undefined {
  switch (raw) {
    case 'issued':
    case 'received':
      return raw;
    default:
      return undefined;
  }
}

function parseRole(raw: string | undefined): TeamInviteRole | undefined {
  switch (raw) {
    case 'owner':
    case 'maintainer':
    case 'developer':
    case 'read-only':
      return raw;
    default:
      return undefined;
  }
}

function metadataStatus(
  rowStatus: string,
  metadata: AuditMetadata,
  nowUnixNanos: number,
): TeamInviteStatus {
  const upper = rowStatus.toUpperCase();
  if (upper === 'REVOKED' || metadata['revoked_at_unix_nanos'] !== undefined) {
    return 'revoked';
  }
  if (upper === 'ACCEPTED' || metadata['accepted_at_unix_nanos'] !== undefined) {
    return 'accepted';
  }
  const expiresAt = metadata.expires_at_unix_nanos;
  if (typeof expiresAt === 'number' && expiresAt < nowUnixNanos) {
    return 'expired';
  }
  if (upper === 'OK' || upper === 'SUCCESS' || upper === 'PENDING') {
    return 'pending';
  }
  return 'unknown';
}

function unixNanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / 1_000_000);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}
