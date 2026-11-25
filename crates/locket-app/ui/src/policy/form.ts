// Pure model + validators for the desktop policy editor form.
//
// Living outside the Vue runtime keeps the create/edit/delete flow
// unit-testable without spinning up jsdom. The Vue component
// (`PolicyEditorForm.vue`) is a thin wrapper that mirrors form state
// into these helpers and surfaces typed validation errors.

import type {
  CommandEnvModeWire,
  CommandKindWire,
  CommandOverrideModeWire,
  CommandPolicySnapshotWire,
} from '../agent/types';
import type { CommandPolicyRow } from '../types/views';
import { parseCommaList } from '../utils/lists';

export interface PolicyFormState {
  /** Saved command policy name (unique within the project). */
  name: string;
  commandKind: CommandKindWire;
  commandPreview: string;
  /** Comma-separated `KEY` list. Trim/dedupe handled in `policyFormToSnapshot`. */
  requiredSecrets: string;
  optionalSecrets: string;
  allowedSecrets: string;
  confirm: boolean;
  requireUserVerification: boolean;
  requireAgent: boolean;
  allowRemoteDocker: boolean;
  ttlSeconds: number;
  envMode: CommandEnvModeWire;
  overrideMode: CommandOverrideModeWire;
}

export type PolicyFormMode = 'create' | 'edit' | 'delete';

export interface PolicyFormValidation {
  /** Field-level errors keyed by `PolicyFormState` field. */
  errors: Partial<Record<keyof PolicyFormState, string>>;
  /** Whether the snapshot can be submitted as-is. */
  valid: boolean;
}

/** Default values for a newly-opened create form. */
export function defaultPolicyForm(): PolicyFormState {
  return {
    name: '',
    commandKind: 'argv',
    commandPreview: '',
    requiredSecrets: '',
    optionalSecrets: '',
    allowedSecrets: '',
    confirm: false,
    requireUserVerification: false,
    requireAgent: false,
    allowRemoteDocker: false,
    ttlSeconds: 60,
    envMode: 'minimal',
    overrideMode: 'fail',
  };
}

/** Hydrate the form from an existing list-view row. */
export function policyFormFromRow(row: CommandPolicyRow): PolicyFormState {
  return {
    name: row.name,
    commandKind: row.commandKind,
    commandPreview: row.commandPreview,
    requiredSecrets: row.requiredSecrets.join(', '),
    optionalSecrets: row.optionalSecrets.join(', '),
    allowedSecrets: row.allowedSecrets.join(', '),
    confirm: row.confirm,
    requireUserVerification: row.requireUserVerification,
    requireAgent: row.requireAgent,
    allowRemoteDocker: row.allowRemoteDocker,
    ttlSeconds: row.ttlSeconds,
    envMode: row.envMode,
    overrideMode: row.overrideMode,
  };
}

const NAME_PATTERN = /^[A-Za-z0-9._:-]+$/;
const SECRET_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const COMMAND_PREVIEW_MAX = 4096;

/** Normalize a `KEY, KEY2` list into a deduped, trimmed array. */
export function parseSecretList(raw: string): string[] {
  return parseCommaList(raw);
}

/** Run the same validation gate the form uses on submit. */
export function validatePolicyForm(state: PolicyFormState): PolicyFormValidation {
  const errors: Partial<Record<keyof PolicyFormState, string>> = {};

  const name = state.name.trim();
  if (name.length === 0) {
    errors.name = 'Name is required.';
  } else if (!NAME_PATTERN.test(name)) {
    errors.name = 'Use letters, digits, dots, underscores, dashes, or colons.';
  } else if (name.length > 128) {
    errors.name = 'Name is too long (max 128).';
  }

  const preview = state.commandPreview.trim();
  if (preview.length === 0) {
    errors.commandPreview = 'Command is required.';
  } else if (preview.length > COMMAND_PREVIEW_MAX) {
    errors.commandPreview = `Command is too long (max ${COMMAND_PREVIEW_MAX}).`;
  }

  const required = parseSecretList(state.requiredSecrets);
  const optional = parseSecretList(state.optionalSecrets);
  const allowed = parseSecretList(state.allowedSecrets);
  for (const [field, list] of [
    ['requiredSecrets', required],
    ['optionalSecrets', optional],
    ['allowedSecrets', allowed],
  ] as const) {
    for (const secret of list) {
      if (!SECRET_NAME_PATTERN.test(secret)) {
        errors[field] = `Invalid secret name: ${secret}`;
        break;
      }
    }
  }

  if (required.some((name) => optional.includes(name))) {
    errors.optionalSecrets = 'A variable cannot be both required and optional.';
  }

  if (!Number.isInteger(state.ttlSeconds) || state.ttlSeconds < 0) {
    errors.ttlSeconds = 'TTL must be a non-negative integer.';
  } else if (state.ttlSeconds > 28_800) {
    errors.ttlSeconds = 'TTL must be at most 28800 seconds (8h).';
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

/** Convert a validated form into the agent wire snapshot. */
export function policyFormToSnapshot(
  state: PolicyFormState,
  projectId: string,
  updatedAtUnixNanos: number,
): CommandPolicySnapshotWire {
  const required = parseSecretList(state.requiredSecrets);
  const optional = parseSecretList(state.optionalSecrets);
  const explicitAllowed = parseSecretList(state.allowedSecrets);
  const allowedSet = new Set<string>([...required, ...optional, ...explicitAllowed]);
  return {
    project_id: projectId,
    name: state.name.trim(),
    command_kind: state.commandKind,
    command_preview: state.commandPreview.trim(),
    required_secrets: required,
    optional_secrets: optional,
    allowed_secrets: Array.from(allowedSet),
    confirm: state.confirm,
    require_user_verification: state.requireUserVerification,
    require_agent: state.requireAgent,
    allow_remote_docker: state.allowRemoteDocker,
    ttl_seconds: Math.trunc(state.ttlSeconds),
    env_mode: state.envMode,
    override_mode: state.overrideMode,
    updated_at_unix_nanos: updatedAtUnixNanos,
  };
}

/** Replace / append / delete a snapshot in an existing snapshot list. */
export function applyPolicyMutation(
  snapshots: CommandPolicySnapshotWire[],
  mode: PolicyFormMode,
  next: CommandPolicySnapshotWire,
  originalName?: string,
): CommandPolicySnapshotWire[] {
  switch (mode) {
    case 'create':
      return [...snapshots.filter((snap) => snap.name !== next.name), next];
    case 'edit': {
      const target = originalName ?? next.name;
      return snapshots
        .filter((snap) => snap.name !== target)
        .concat(next.name === target ? [next] : [next]);
    }
    case 'delete': {
      const target = originalName ?? next.name;
      return snapshots.filter((snap) => snap.name !== target);
    }
    default:
      return snapshots;
  }
}

/**
 * Whether the editor's submit button is gated behind a typed
 * confirmation. Mirrors the desktop spec rule: dangerous-profile
 * mutations require the user to type the profile name.
 */
export function policyFormRequiresTypedConfirmation(
  dangerousProfile: boolean,
  mode: PolicyFormMode,
): boolean {
  if (!dangerousProfile) {
    return false;
  }
  // Every mutation inside a dangerous profile is gated; the spec calls
  // out delete and "destructive" edits explicitly. We gate all three
  // forms so the confirmation modal always surfaces in dangerous mode.
  return mode === 'create' || mode === 'edit' || mode === 'delete';
}
