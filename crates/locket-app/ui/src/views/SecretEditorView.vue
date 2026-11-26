<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue';
import { secretSourceWire } from '../agent/secrets';
import SecretValueInput from '../components/SecretValueInput.vue';
import VariableSourceBadge from '../components/VariableSourceBadge.vue';
import { formatTime } from '../utils/formatTime';
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
} from '../secret/editor';
import type { AgentClientError } from '../agent/types';
import type { SetSecretRequest, SetSecretResponse } from '../agent/client';
import type { SecretRowMeta } from '../types/views';

export type SetSecretAction = (
  payload: SetSecretRequest,
) => Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }>;

interface Props {
  rows: SecretRowMeta[];
  rotationTarget?: SecretRowMeta | null;
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
}>();

const setForm = ref<SecretSetFormState>(defaultSetForm());
const rotateForm = ref<SecretRotateFormState>(newRotateForm());

function newRotateForm(): SecretRotateFormState {
  return { ...defaultRotateForm(), name: props.rotationTarget?.name ?? '' };
}

onBeforeUnmount(() => {
  setForm.value.value = '';
  rotateForm.value.value = '';
});

const setSubmitting = ref<boolean>(false);
const rotateSubmitting = ref<boolean>(false);

const setError = ref<string | null>(null);
const rotateError = ref<string | null>(null);

const setNotice = ref<string | null>(null);
const rotateNotice = ref<string | null>(null);

const setValidation = computed(() => validateSetForm(setForm.value));
const rotateValidation = computed(() => validateRotateForm(rotateForm.value));

const canSubmitSet = computed<boolean>(
  () => setValidation.value.valid && !setSubmitting.value && hasContext.value && !setLink.value,
);
const canSubmitRotate = computed<boolean>(
  () =>
    rotateValidation.value.valid &&
    !rotateSubmitting.value &&
    hasContext.value &&
    !rotateLink.value,
);

const hasContext = computed<boolean>(
  () => props.metadataLoaded && Boolean(props.projectId) && Boolean(props.profileId),
);

function linkedRow(name: string): SecretRowMeta | undefined {
  return props.rows.find((row) => row.name === name.trim() && row.source === 'shared-link');
}

const setLink = computed(() => linkedRow(setForm.value.name));
const rotationRow = computed(
  () => props.rotationTarget ?? props.rows.find((row) => row.name === rotateForm.value.name.trim()),
);
const rotateLink = computed(() =>
  props.rotationTarget?.source === 'shared-link'
    ? props.rotationTarget
    : props.rotationTarget
      ? undefined
      : linkedRow(rotateForm.value.name),
);

function refresh(): void {
  emit('refresh');
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
  setForm.value.value = '';
  const result = await props.onSetSecret(payload);
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
  const source = rotationRow.value?.source;
  if (!canSubmitRotate.value || source === 'shared-link') {
    return;
  }
  rotateError.value = null;
  rotateNotice.value = null;
  rotateSubmitting.value = true;
  const payload = rotateFormToPayload(rotateForm.value, {
    projectId: props.projectId ?? '',
    profileId: props.profileId ?? '',
    grantId: props.grantId ?? undefined,
    source: source ? secretSourceWire(source) : 'user-local',
  });
  rotateForm.value.value = '';
  const result = await props.onRotateSecret(payload);
  rotateSubmitting.value = false;
  if (!result.ok) {
    rotateError.value = errorLabel(result.error);
    return;
  }
  rotateNotice.value = rotateSecretSuccessNotice(payload.secret_name, result.value.version);
  rotateForm.value = newRotateForm();
  refresh();
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
      <h2 id="secret-editor-heading">Add or rotate secret</h2>
      <div class="view__actions">
        <span v-if="lastRefreshedAt" class="view__muted">
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button type="button" class="view__button" :disabled="loading" @click="refresh">
          Refresh
        </button>
        <button type="button" class="companion-button" @click="emit('manage')">
          Back to Secrets
        </button>
      </div>
    </header>

    <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>

    <p v-if="!hasContext" class="view__notice" role="note">
      Select an active project and environment before setting or rotating secrets.
    </p>

    <p v-if="actionGuidance" class="view__empty" role="status">{{ actionGuidance }}</p>
    <p v-else-if="loading" class="view__empty" role="status">Loading secret metadata…</p>

    <section v-if="!rotationTarget" aria-labelledby="secret-editor-set-heading" class="view__panel">
      <h3 id="secret-editor-set-heading" class="view__panel-heading" tabindex="-1">Add secret</h3>
      <form @submit.prevent="onSet">
        <label class="view__field">
          <span>Secret name</span>
          <input
            v-model="setForm.name"
            type="text"
            autocomplete="off"
            spellcheck="false"
            placeholder="DATABASE_URL"
            data-testid="secret-editor-set-name"
          />
          <span v-if="setValidation.errors.name" class="view__error">
            {{ setValidation.errors.name }}
          </span>
        </label>
        <p v-if="setLink" class="view__notice">
          This name is linked. Edit the secret in Global Vault or unlink it in Secrets.
        </p>
        <SecretValueInput
          id="secret-editor-set-value"
          v-model="setForm.value"
          label="Value"
          :error="setValidation.errors.value"
          :disabled="setSubmitting || Boolean(setLink)"
        />
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
            {{ setSubmitting ? 'Submitting…' : 'Add secret' }}
          </button>
        </div>
      </form>
    </section>

    <section aria-labelledby="secret-editor-rotate-heading" class="view__panel">
      <h3 id="secret-editor-rotate-heading" class="view__panel-heading">Rotate secret</h3>
      <form @submit.prevent="onRotate">
        <label class="view__field">
          <span>Secret name</span>
          <input
            v-model="rotateForm.name"
            type="text"
            :list="privacyMode || rotationTarget ? undefined : 'secret-editor-known'"
            :readonly="Boolean(rotationTarget)"
            autocomplete="off"
            spellcheck="false"
            placeholder="DATABASE_URL"
            data-testid="secret-editor-rotate-name"
          />
          <datalist v-if="!privacyMode && !rotationTarget" id="secret-editor-known">
            <option
              v-for="row in props.rows.filter((row) => row.source !== 'shared-link')"
              :key="row.id"
              :value="row.name"
            />
          </datalist>
          <span v-if="rotateValidation.errors.name" class="view__error">
            {{ rotateValidation.errors.name }}
          </span>
        </label>
        <div v-if="rotationTarget" class="view__source">
          Source <VariableSourceBadge :source="rotationTarget.source" />
        </div>
        <p v-if="rotateLink" class="view__notice">
          Rotate this secret in Global Vault to update every linked project.
        </p>
        <SecretValueInput
          id="secret-editor-rotate-value"
          v-model="rotateForm.value"
          label="New value"
          :error="rotateValidation.errors.value"
          :disabled="rotateSubmitting || Boolean(rotateLink)"
        />
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
  flex-wrap: wrap;
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
.view__source {
  display: flex;
  align-items: center;
  gap: 0.5rem;
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
.view__muted {
  color: var(--text-secondary);
  font-size: 0.8rem;
}
</style>
