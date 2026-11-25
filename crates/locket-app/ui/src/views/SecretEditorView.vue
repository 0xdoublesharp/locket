<script setup lang="ts">
import { secretSourceWire } from '../agent/secrets';
import { formatTime } from '../utils/formatTime';
// Desktop view for gated secret set/rotate and TTL-bound reveal.
// Plaintext enters the webview only for an active form
// submission or reveal modal and is cleared when the flow completes.

import { computed, ref } from 'vue';

import RevealModal from '../components/RevealModal.vue';
import {
  defaultRotateForm,
  defaultSetForm,
  rotateSecretSuccessNotice,
  rotateFormToPayload,
  setSecretSuccessNotice,
  setFormToPayload,
  validateRotateForm,
  validateSetForm,
  type SecretRotateFormState,
  type SecretSetFormState,
  type SecretSource,
} from '../secret/editor';
import type { AgentClientError } from '../agent/types';
import type { SetSecretRequest, SetSecretResponse } from '../agent/client';
import type { SecretRowMeta } from '../types/views';

export type SetSecretAction = (
  payload: SetSecretRequest,
) => Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }>;

interface Props {
  rows: SecretRowMeta[];
  privacyMode: boolean;
  loading: boolean;
  metadataLoaded: boolean;
  actionGuidance?: string | null;
  errorMessage?: string | null;
  lastRefreshedAt?: string;
  /** Active project id (required for SetSecret payloads). */
  projectId?: string | null;
  /** Active profile id (required for SetSecret payloads). */
  profileId?: string | null;
  /** Latest live grant id, if any, scoped to set-secret. */
  grantId?: string | null;
  /** Async handler for the create-new path. */
  onSetSecret: SetSecretAction;
  /** Async handler for the rotation path. */
  onRotateSecret: SetSecretAction;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (event: 'refresh' | 'manage'): void;
  (event: 'reveal', row: SecretRowMeta): void;
}>();

const setForm = ref<SecretSetFormState>(defaultSetForm());
const rotateForm = ref<SecretRotateFormState>(defaultRotateForm());

const setSubmitting = ref<boolean>(false);
const rotateSubmitting = ref<boolean>(false);

const setError = ref<string | null>(null);
const rotateError = ref<string | null>(null);

const setNotice = ref<string | null>(null);
const rotateNotice = ref<string | null>(null);

const searchQuery = ref<string>('');

const filteredRows = computed<SecretRowMeta[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return props.rows;
  }
  return props.rows.filter((row) =>
    [
      props.privacyMode ? (row.alias ?? row.name) : row.name,
      row.source,
      row.required ? 'required' : 'optional',
    ]
      .join(' ')
      .toLowerCase()
      .includes(query),
  );
});

const setValidation = computed(() => validateSetForm(setForm.value));
const rotateValidation = computed(() => validateRotateForm(rotateForm.value));

const canSubmitSet = computed<boolean>(
  () => setValidation.value.valid && !setSubmitting.value && hasContext.value,
);
const canSubmitRotate = computed<boolean>(
  () => rotateValidation.value.valid && !rotateSubmitting.value && hasContext.value,
);

const hasContext = computed<boolean>(
  () => props.metadataLoaded && Boolean(props.projectId) && Boolean(props.profileId),
);

function rotateSourceFor(name: string): SecretSource {
  const trimmed = name.trim();
  const row = props.rows.find((entry) => entry.name === trimmed);
  return row ? secretSourceWire(row.source) : 'user-local';
}

function refresh(): void {
  emit('refresh');
}

function displayName(row: SecretRowMeta): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

async function onSet(): Promise<void> {
  if (!canSubmitSet.value) {
    return;
  }
  setError.value = null;
  setNotice.value = null;
  setSubmitting.value = true;
  const payload = setFormToPayload(setForm.value, {
    projectId: props.projectId ?? '',
    profileId: props.profileId ?? '',
    grantId: props.grantId ?? undefined,
  });
  const wire: SetSecretRequest = {
    project_id: payload.project_id,
    profile_id: payload.profile_id,
    secret_name: payload.secret_name,
    value: payload.value,
    source: payload.source,
    grant_id: payload.grant_id,
  };
  const result = await props.onSetSecret(wire);
  setSubmitting.value = false;
  if (!result.ok) {
    setError.value = errorLabel(result.error);
    return;
  }
  setNotice.value = setSecretSuccessNotice(payload.secret_name, result.value.version);
  setForm.value = defaultSetForm();
  refresh();
}

async function onRotate(): Promise<void> {
  if (!canSubmitRotate.value) {
    return;
  }
  rotateError.value = null;
  rotateNotice.value = null;
  rotateSubmitting.value = true;
  const payload = rotateFormToPayload(rotateForm.value, {
    projectId: props.projectId ?? '',
    profileId: props.profileId ?? '',
    grantId: props.grantId ?? undefined,
    source: rotateSourceFor(rotateForm.value.name),
  });
  const wire: SetSecretRequest = {
    project_id: payload.project_id,
    profile_id: payload.profile_id,
    secret_name: payload.secret_name,
    value: payload.value,
    source: payload.source,
    grace_until: payload.grace_until,
    grant_id: payload.grant_id,
  };
  const result = await props.onRotateSecret(wire);
  rotateSubmitting.value = false;
  if (!result.ok) {
    rotateError.value = errorLabel(result.error);
    return;
  }
  rotateNotice.value = rotateSecretSuccessNotice(payload.secret_name, result.value.version);
  rotateForm.value = defaultRotateForm();
  refresh();
}

function onReveal(row: SecretRowMeta): void {
  emit('reveal', row);
}

function errorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Request failed.';
  }
}
</script>

<template>
  <section class="view" aria-labelledby="secret-editor-heading">
    <header class="view__header">
      <h2 id="secret-editor-heading">Variable editor</h2>
      <div class="view__actions">
        <span v-if="lastRefreshedAt" class="view__muted">
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button type="button" class="view__button" :disabled="loading" @click="refresh">
          Refresh
        </button>
      </div>
    </header>

    <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>

    <p v-if="!hasContext" class="view__notice" role="note">
      Select an active project and environment before setting or rotating secrets.
    </p>

    <section aria-labelledby="secret-editor-list-heading" class="view__panel">
      <h3 id="secret-editor-list-heading" class="view__panel-heading">
        Variables in this environment
      </h3>
      <label class="view__search">
        <span class="view__search-label">Search secrets</span>
        <input
          v-model="searchQuery"
          type="search"
          autocomplete="off"
          spellcheck="false"
          placeholder="Filter by name or source"
        />
      </label>
      <p v-if="actionGuidance" class="view__empty" role="status">{{ actionGuidance }}</p>
      <p v-else-if="loading" class="view__loading" role="status">Loading secret metadata…</p>
      <p v-else-if="metadataLoaded && filteredRows.length === 0" class="view__empty">
        No matching secrets.
      </p>
      <table
        v-else-if="metadataLoaded"
        class="view__table"
        aria-describedby="secret-editor-list-heading"
      >
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Source</th>
            <th scope="col">Version</th>
            <th scope="col">Reveal</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in filteredRows" :key="row.id">
            <td>{{ displayName(row) }}</td>
            <td>
              {{
                row.source === 'team'
                  ? 'Shared'
                  : row.source === 'user-local'
                    ? 'My override'
                    : 'This machine'
              }}
            </td>
            <td>v{{ row.currentVersion }}</td>
            <td>
              <button
                type="button"
                class="view__button"
                data-testid="secret-editor-reveal"
                @click="onReveal(row)"
              >
                Reveal (TTL)
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <section aria-labelledby="secret-editor-set-heading" class="view__panel">
      <h3 id="secret-editor-set-heading" class="view__panel-heading" tabindex="-1">Set variable</h3>
      <form @submit.prevent="onSet">
        <label class="view__field">
          <span>Name (KEY_FORMAT)</span>
          <input
            v-model="setForm.name"
            type="text"
            autocomplete="off"
            spellcheck="false"
            data-testid="secret-editor-set-name"
          />
          <span v-if="setValidation.errors.name" class="view__error">
            {{ setValidation.errors.name }}
          </span>
        </label>
        <label class="view__field">
          <span>Value</span>
          <input
            v-model="setForm.value"
            type="password"
            autocomplete="new-password"
            spellcheck="false"
            data-testid="secret-editor-set-value"
          />
          <span v-if="setValidation.errors.value" class="view__error">
            {{ setValidation.errors.value }}
          </span>
        </label>
        <label class="view__field">
          <span>Description (metadata only)</span>
          <input v-model="setForm.description" type="text" autocomplete="off" spellcheck="false" />
          <span v-if="setValidation.errors.description" class="view__error">
            {{ setValidation.errors.description }}
          </span>
        </label>
        <label class="view__field">
          <span>Source</span>
          <select v-model="setForm.source" data-testid="secret-editor-set-source">
            <option value="user-local">My override</option>
            <option value="machine-local">This machine</option>
            <option value="team-managed">Shared</option>
          </select>
        </label>
        <p v-if="setError" class="view__error" role="alert">{{ setError }}</p>
        <p v-if="setNotice" class="view__notice" role="status">{{ setNotice }}</p>
        <div class="view__form-actions">
          <button
            type="submit"
            class="view__button view__button--primary"
            :disabled="!canSubmitSet"
            data-testid="secret-editor-set-submit"
          >
            {{ setSubmitting ? 'Submitting…' : 'Set secret' }}
          </button>
        </div>
      </form>
    </section>

    <section aria-labelledby="secret-editor-rotate-heading" class="view__panel">
      <h3 id="secret-editor-rotate-heading" class="view__panel-heading">Rotate secret</h3>
      <form @submit.prevent="onRotate">
        <label class="view__field">
          <span>Existing secret name</span>
          <input
            v-model="rotateForm.name"
            type="text"
            :list="privacyMode ? undefined : 'secret-editor-known'"
            autocomplete="off"
            spellcheck="false"
            data-testid="secret-editor-rotate-name"
          />
          <datalist v-if="!privacyMode" id="secret-editor-known">
            <option v-for="row in props.rows" :key="row.id" :value="row.name" />
          </datalist>
          <span v-if="rotateValidation.errors.name" class="view__error">
            {{ rotateValidation.errors.name }}
          </span>
        </label>
        <label class="view__field">
          <span>New value</span>
          <input
            v-model="rotateForm.value"
            type="password"
            autocomplete="new-password"
            spellcheck="false"
            data-testid="secret-editor-rotate-value"
          />
          <span v-if="rotateValidation.errors.value" class="view__error">
            {{ rotateValidation.errors.value }}
          </span>
        </label>
        <label class="view__field">
          <span>Grace expiry (optional)</span>
          <input
            v-model="rotateForm.graceUntil"
            type="datetime-local"
            autocomplete="off"
            spellcheck="false"
          />
          <span v-if="rotateValidation.errors.graceUntil" class="view__error">
            {{ rotateValidation.errors.graceUntil }}
          </span>
        </label>
        <p v-if="rotateError" class="view__error" role="alert">{{ rotateError }}</p>
        <p v-if="rotateNotice" class="view__notice" role="status">{{ rotateNotice }}</p>
        <div class="view__form-actions">
          <button
            type="submit"
            class="view__button view__button--primary"
            :disabled="!canSubmitRotate"
            data-testid="secret-editor-rotate-submit"
          >
            {{ rotateSubmitting ? 'Rotating…' : 'Rotate secret' }}
          </button>
        </div>
      </form>
    </section>

    <section aria-labelledby="secret-editor-delete-heading" class="view__panel">
      <h3 id="secret-editor-delete-heading" class="view__panel-heading">Delete secret</h3>
      <p class="view__muted">Open Details for a secret in the list to delete it.</p>
      <button type="button" class="companion-button" @click="emit('manage')">
        Open secret list
      </button>
    </section>

    <RevealModal />
  </section>
</template>

<style scoped>
.view {
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border-radius: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.view__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
}
.view__actions {
  display: inline-flex;
  align-items: center;
  gap: 0.625rem;
  margin-left: auto;
}
.view__panel {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  padding: 0.875rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.view__panel-heading {
  margin: 0;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
}
.view__field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
}
.view__field input,
.view__field select {
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  padding: 0.4rem 0.6rem;
  font: inherit;
  font-size: 0.85rem;
}
.view__form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.view__button {
  min-height: 2rem;
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  cursor: pointer;
  font: inherit;
  font-size: 0.8125rem;
  padding: 0.25rem 0.625rem;
}
.view__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.view__button--primary {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: transparent;
}
.view__button--danger {
  background: var(--danger);
  color: var(--accent-fg);
  border-color: transparent;
}
.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
}
.view__error {
  margin: 0;
  color: var(--danger);
  font-size: 0.8rem;
}
.view__notice {
  margin: 0;
  padding: 0.5rem 0.625rem;
  background: var(--info-soft);
  border: 1px solid var(--border-strong);
  color: var(--info);
  border-radius: 0.375rem;
  font-size: 0.8rem;
}
.view__notice code {
  background: var(--bg-subtle);
  padding: 0 0.25rem;
  border-radius: 0.25rem;
}
.view__muted {
  color: var(--text-secondary);
  font-size: 0.8rem;
}
.view__muted code {
  background: var(--bg-subtle);
  padding: 0 0.25rem;
  border-radius: 0.25rem;
}
.view__search {
  display: grid;
  gap: 0.25rem;
}
.view__search-label {
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
}
.view__search input {
  box-sizing: border-box;
  width: 100%;
  min-height: 2rem;
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  font: inherit;
  padding: 0.375rem 0.625rem;
}
.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.view__table th,
.view__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: top;
}
.view__table th {
  font-weight: 600;
  color: var(--text-secondary);
  font-size: 0.75rem;
  letter-spacing: 0.04em;
}

@media (max-width: 639px) {
  .view__table th,
  .view__table td {
    padding-inline: 0.35rem;
    overflow-wrap: anywhere;
  }
}
</style>
