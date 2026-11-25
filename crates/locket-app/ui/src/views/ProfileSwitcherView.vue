<script setup lang="ts">
import { formatTime } from '../utils/formatTime';
import { computed, ref, watch } from 'vue';

import {
  isValidProfileName,
  profileEntries,
  profileSwitchRequiresTypedConfirmation,
  type ProfileEntry,
  type ProfileSwitchState,
} from '../profile/switcher';

defineOptions({ name: 'ProfileSwitcherView' });

interface Props {
  state: ProfileSwitchState;
  privacyMode: boolean;
  switching: boolean;
  errorMessage?: string | null;
  lastSwitchedAt?: string;
  initialTarget?: Pick<ProfileEntry, 'name' | 'dangerous'> | null;
  canCreate?: boolean;
  creating?: boolean;
  createNotice?: string | null;
  createError?: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (
    event: 'switch',
    payload: { profileName: string; confirmation: string | undefined; dangerous: boolean },
  ): void;
  (event: 'select', entry: ProfileEntry): void;
  (event: 'create', name: string): void;
}>();

const targetName = ref(props.initialTarget?.name ?? '');
const targetDangerous = ref(props.initialTarget?.dangerous ?? false);
const confirmation = ref<string>('');
const createName = ref('');
const validCreateName = computed(() => isValidProfileName(createName.value));
const canSubmitCreate = computed(() => props.canCreate && !props.creating && validCreateName.value);

watch(
  () => props.createNotice,
  (notice) => {
    if (notice) createName.value = '';
  },
);

const entries = computed<ProfileEntry[]>(() => profileEntries(props.state));

const effectiveDangerous = computed<boolean>(() => {
  const name = targetName.value.trim();
  if (name.length === 0) {
    return false;
  }
  // If the typed name matches a listed entry, use its known flag;
  // otherwise honor the user's explicit dangerous-target checkbox.
  const matched = entries.value.find((entry) => entry.name === name);
  if (matched) {
    return matched.dangerous;
  }
  return targetDangerous.value;
});

const requiresConfirmation = computed<boolean>(() =>
  profileSwitchRequiresTypedConfirmation(targetName.value.trim(), effectiveDangerous.value),
);

const validName = computed<boolean>(() => isValidProfileName(targetName.value));

const canSubmit = computed<boolean>(() => {
  if (props.switching || props.creating || !validName.value) {
    return false;
  }
  if (requiresConfirmation.value && confirmation.value.trim() !== targetName.value.trim()) {
    return false;
  }
  return true;
});

function selectEntry(entry: ProfileEntry): void {
  targetName.value = entry.name;
  targetDangerous.value = entry.dangerous;
  confirmation.value = '';
  emit('select', entry);
}

function entryLabel(entry: ProfileEntry): string {
  if (props.privacyMode) {
    return entry.name === props.state.activeProfile ? 'active environment' : 'environment';
  }
  return entry.name;
}

function onSubmit(): void {
  if (!canSubmit.value) {
    return;
  }
  const trimmed = targetName.value.trim();
  emit('switch', {
    profileName: trimmed,
    confirmation: requiresConfirmation.value ? confirmation.value.trim() : undefined,
    dangerous: effectiveDangerous.value,
  });
}

function onCreate(): void {
  if (canSubmitCreate.value) emit('create', createName.value.trim());
}
</script>

<template>
  <section class="view" aria-labelledby="profile-switcher-heading">
    <header class="view__header">
      <h2 id="profile-switcher-heading">Environments</h2>
      <span v-if="props.lastSwitchedAt" class="view__caption">
        Last switch:
        <time :datetime="props.lastSwitchedAt" :title="props.lastSwitchedAt">{{
          formatTime(props.lastSwitchedAt)
        }}</time>
      </span>
    </header>

    <p v-if="entries.length === 0" class="view__empty">No environments tracked yet.</p>

    <ul v-else class="profile-list" data-testid="profile-list">
      <li
        v-for="entry in entries"
        :key="entry.name"
        :class="[
          'profile-list__item',
          { 'profile-list__item--active': entry.name === props.state.activeProfile },
        ]"
      >
        <button
          type="button"
          class="profile-list__btn"
          :aria-current="entry.name === props.state.activeProfile ? 'true' : undefined"
          :data-testid="`profile-entry-${entry.name}`"
          @click="selectEntry(entry)"
        >
          <span class="profile-list__name">{{ entryLabel(entry) }}</span>
          <span v-if="entry.dangerous" class="badge badge--warning">dangerous</span>
          <span v-if="entry.name === props.state.activeProfile" class="badge badge--ok"
            >active</span
          >
        </button>
      </li>
    </ul>

    <details class="create-environment">
      <summary>+ New environment</summary>
      <form class="switcher-form" data-testid="profile-create-form" @submit.prevent="onCreate">
        <h3>Create environment</h3>
        <label class="switcher-form__field">
          <span>Environment name</span>
          <input
            v-model="createName"
            type="text"
            autocomplete="off"
            spellcheck="false"
            :disabled="!canCreate || creating"
            data-testid="profile-create-name"
          />
          <span v-if="createName.length > 0 && !validCreateName" class="switcher-form__error">
            Use 1–128 letters, digits, dots, underscores, or dashes.
          </span>
        </label>
        <p v-if="createError" role="alert" class="switcher-form__error">{{ createError }}</p>
        <p v-if="createNotice" role="status" class="switcher-form__notice">{{ createNotice }}</p>
        <div class="switcher-form__actions">
          <button
            type="submit"
            class="view__button view__button--primary"
            :disabled="!canSubmitCreate"
          >
            {{ creating ? 'Creating…' : 'Create environment' }}
          </button>
        </div>
      </form>
    </details>

    <form class="switcher-form" data-testid="profile-switcher-form" @submit.prevent="onSubmit">
      <h3>Switch environment</h3>

      <label class="switcher-form__field">
        <span>Target environment name</span>
        <input
          v-model="targetName"
          type="text"
          autocomplete="off"
          spellcheck="false"
          data-testid="profile-target-name"
        />
        <span v-if="targetName.length > 0 && !validName" class="switcher-form__error">
          Name may contain letters, digits, dot, underscore, and dash.
        </span>
      </label>

      <label class="switcher-form__check">
        <input
          v-model="targetDangerous"
          type="checkbox"
          :disabled="entries.some((entry) => entry.name === targetName.trim())"
          data-testid="profile-target-dangerous"
        />
        Target environment is flagged dangerous
      </label>

      <label
        v-if="requiresConfirmation"
        class="switcher-form__field"
        data-testid="profile-confirmation"
      >
        <span>Type the target environment name to confirm dangerous switch</span>
        <input v-model="confirmation" type="text" autocomplete="off" spellcheck="false" />
      </label>

      <p v-if="props.errorMessage" role="alert" class="switcher-form__error">
        {{ props.errorMessage }}
      </p>

      <div class="switcher-form__actions">
        <button
          type="submit"
          class="view__button view__button--primary"
          :disabled="!canSubmit"
          data-testid="profile-switch-submit"
        >
          {{ props.switching ? 'Switching...' : 'Switch environment' }}
        </button>
      </div>
    </form>
  </section>
</template>

<style scoped>
.view {
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border-radius: 0.5rem;
}
.view__header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 0.75rem;
}
.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
}
.view__caption {
  color: var(--text-secondary);
  font-size: 0.8rem;
}
.view__empty {
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.profile-list {
  list-style: none;
  margin: 0 0 1rem;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.profile-list__item--active .profile-list__btn {
  background: var(--accent-soft);
}
.profile-list__btn {
  width: 100%;
  text-align: left;
  background: transparent;
  border: 1px solid var(--border-subtle);
  border-radius: 0.375rem;
  padding: 0.5rem 0.75rem;
  color: var(--text-primary);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
}
.profile-list__btn:hover {
  background: var(--bg-subtle);
}
.profile-list__name {
  flex: 1;
}
.create-environment > summary {
  width: fit-content;
  color: var(--accent);
  font-size: 0.875rem;
  cursor: pointer;
}
.switcher-form {
  display: flex;
  flex-direction: column;
  gap: 0.625rem;
  margin-top: 1rem;
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
}
.switcher-form h3 {
  margin: 0 0 0.5rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
  letter-spacing: 0.04em;
}
.switcher-form__field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-size: 0.85rem;
}
.switcher-form__field input {
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  padding: 0.4rem 0.6rem;
  font-size: 0.85rem;
}
.switcher-form__check {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8rem;
}
.switcher-form__error {
  color: var(--danger);
  font-size: 0.75rem;
}
.switcher-form__notice {
  margin: 0;
  color: var(--success);
  font-size: 0.85rem;
}
.switcher-form__actions {
  display: flex;
  justify-content: flex-end;
}
.view__button {
  border: 1px solid var(--border-strong);
  background: var(--bg-subtle);
  color: var(--text-primary);
  border-radius: 0.375rem;
  padding: 0.4rem 0.85rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.view__button--primary {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: transparent;
}
.view__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.7rem;
  letter-spacing: 0.02em;
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
}
.badge--ok {
  background: var(--success-soft);
  border-color: var(--border-strong);
  color: var(--success);
}
.badge--warning {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}
</style>
