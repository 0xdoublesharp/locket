// Pure model + validators for the desktop secret editor.
//
// The Vue view (`SecretEditorView.vue`) mirrors form state through
// these helpers so dangerous-typed-confirmation, payload-construction,
// and validation stay testable without spinning up jsdom.
//
// The desktop uses a shared write path for create and rotate. Delete
// remains CLI-directed so the desktop can keep a metadata-only handoff
// without duplicating lifecycle policy in the webview.

export type SecretSource = 'team-managed' | 'user-local' | 'machine-local';

export interface SecretSetFormState {
  /** Secret name in `KEY` form (uppercase letters, digits, underscores). */
  name: string;
  /** Plaintext value, password-masked in the UI; never persisted. */
  value: string;
  /** Optional human description, persisted as metadata only. */
  description: string;
  /** Storage source / precedence band. */
  source: SecretSource;
}

export interface SecretRotateFormState {
  /** Existing secret name to rotate. */
  name: string;
  /** New plaintext value. */
  value: string;
  /** Optional ISO 8601 grace expiry for the deprecated version. */
  graceUntil: string;
}

export interface SecretDeleteFormState {
  /** Existing secret name to delete. */
  name: string;
  /** Typed-confirmation: must match `name` exactly. */
  confirmation: string;
}

export interface FormValidation<T> {
  errors: Partial<Record<keyof T, string>>;
  valid: boolean;
}

const SECRET_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const VALUE_MAX_LENGTH = 65_536;
const DESCRIPTION_MAX_LENGTH = 512;
const NUL_BYTE = '\0';

export function defaultSetForm(): SecretSetFormState {
  return { name: '', value: '', description: '', source: 'user-local' };
}

export function defaultRotateForm(): SecretRotateFormState {
  return { name: '', value: '', graceUntil: '' };
}

export function defaultDeleteForm(): SecretDeleteFormState {
  return { name: '', confirmation: '' };
}

export function validateSetForm(state: SecretSetFormState): FormValidation<SecretSetFormState> {
  const errors: Partial<Record<keyof SecretSetFormState, string>> = {};

  const name = state.name.trim();
  if (name.length === 0) {
    errors.name = 'Secret name is required.';
  } else if (!SECRET_NAME_PATTERN.test(name)) {
    errors.name =
      'Name must match KEY_FORMAT (start with A-Z or underscore, then A-Z, 0-9, underscore).';
  } else if (name.length > 128) {
    errors.name = 'Name is too long (max 128).';
  }

  if (state.value.length === 0) {
    errors.value = 'Value is required.';
  } else if (state.value.length > VALUE_MAX_LENGTH) {
    errors.value = `Value is too long (max ${VALUE_MAX_LENGTH.toString()} bytes).`;
  } else if (state.value.includes(NUL_BYTE)) {
    errors.value = 'Value must not contain NUL bytes.';
  }

  if (state.description.length > DESCRIPTION_MAX_LENGTH) {
    errors.description = `Description is too long (max ${DESCRIPTION_MAX_LENGTH.toString()}).`;
  }

  if (
    state.source !== 'team-managed' &&
    state.source !== 'user-local' &&
    state.source !== 'machine-local'
  ) {
    errors.source = 'Unknown source.';
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

export function validateRotateForm(
  state: SecretRotateFormState,
): FormValidation<SecretRotateFormState> {
  const errors: Partial<Record<keyof SecretRotateFormState, string>> = {};

  const name = state.name.trim();
  if (name.length === 0) {
    errors.name = 'Pick the secret to rotate.';
  } else if (!SECRET_NAME_PATTERN.test(name)) {
    errors.name = 'Name must match KEY_FORMAT.';
  }

  if (state.value.length === 0) {
    errors.value = 'New value is required.';
  } else if (state.value.length > VALUE_MAX_LENGTH) {
    errors.value = `Value is too long (max ${VALUE_MAX_LENGTH.toString()} bytes).`;
  } else if (state.value.includes(NUL_BYTE)) {
    errors.value = 'Value must not contain NUL bytes.';
  }

  if (state.graceUntil.trim().length > 0) {
    const parsed = Date.parse(state.graceUntil);
    if (Number.isNaN(parsed)) {
      errors.graceUntil = 'Grace expiry must be a valid ISO 8601 datetime.';
    } else if (parsed <= Date.now()) {
      errors.graceUntil = 'Grace expiry must be in the future.';
    }
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

export function validateDeleteForm(
  state: SecretDeleteFormState,
): FormValidation<SecretDeleteFormState> {
  const errors: Partial<Record<keyof SecretDeleteFormState, string>> = {};

  const name = state.name.trim();
  if (name.length === 0) {
    errors.name = 'Pick the secret to delete.';
  } else if (!SECRET_NAME_PATTERN.test(name)) {
    errors.name = 'Name must match KEY_FORMAT.';
  }

  const confirmation = state.confirmation.trim();
  if (confirmation.length === 0) {
    errors.confirmation = 'Type the secret name to confirm deletion.';
  } else if (confirmation !== name) {
    errors.confirmation = 'Confirmation must match the secret name exactly.';
  }

  return { errors, valid: Object.keys(errors).length === 0 };
}

export interface SecretSetPayload {
  /** Active project id supplied by the wrapper. */
  project_id: string;
  /** Active profile id supplied by the wrapper. */
  profile_id: string;
  /** Live grant id, if any, supplied by the wrapper. */
  grant_id?: string;
  /** Form-derived fields. */
  secret_name: string;
  value: string;
  source: SecretSource;
}

export interface SecretRotatePayload extends SecretSetPayload {
  /** Optional grace expiry as Unix nanos. */
  grace_until?: number;
}

export interface SecretDeleteRequest {
  project_id: string;
  profile_id: string;
  secret_name: string;
  /** Echo the typed-confirmation so the agent (once available) can re-validate. */
  typed_confirmation: string;
}

export function setFormToPayload(
  state: SecretSetFormState,
  context: { projectId: string; profileId: string; grantId?: string },
): SecretSetPayload {
  return {
    project_id: context.projectId,
    profile_id: context.profileId,
    grant_id: context.grantId,
    secret_name: state.name.trim(),
    value: state.value,
    source: state.source,
  };
}

export function rotateFormToPayload(
  state: SecretRotateFormState,
  context: { projectId: string; profileId: string; grantId?: string; source: SecretSource },
): SecretRotatePayload {
  const trimmed = state.graceUntil.trim();
  const grace = trimmed.length === 0 ? undefined : Math.trunc(Date.parse(trimmed) * 1_000_000);
  return {
    project_id: context.projectId,
    profile_id: context.profileId,
    grant_id: context.grantId,
    secret_name: state.name.trim(),
    value: state.value,
    source: context.source,
    grace_until: grace,
  };
}

export function deleteFormToRequest(
  state: SecretDeleteFormState,
  context: { projectId: string; profileId: string },
): SecretDeleteRequest {
  return {
    project_id: context.projectId,
    profile_id: context.profileId,
    secret_name: state.name.trim(),
    typed_confirmation: state.confirmation.trim(),
  };
}

export function setSecretSuccessNotice(secretName: string, version: number): string {
  return `Created ${secretName} v${version.toString()}.`;
}

export function rotateSecretSuccessNotice(secretName: string, version: number): string {
  return `Rotated ${secretName} to v${version.toString()}.`;
}

export function deleteSecretCliCommand(secretName: string): string {
  return `locket rm ${secretName.trim()}`;
}

export function deleteUnavailableNotice(secretName: string): string {
  return `Run \`${deleteSecretCliCommand(secretName)}\` in the Locket CLI to delete this secret.`;
}
