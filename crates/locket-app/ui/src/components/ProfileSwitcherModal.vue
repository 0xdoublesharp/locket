<script setup lang="ts">
import { computed, ref } from 'vue';

const props = defineProps<{
  dangerous: boolean;
  currentProfile: string | null;
}>();

const emit = defineEmits<{
  (event: 'submit', profileName: string, confirmation: string | undefined): void;
  (event: 'dismiss'): void;
}>();

const profileName = ref<string>('');
const confirmation = ref<string>('');

const requiresConfirmation = computed<boolean>(() => props.dangerous);

const canSubmit = computed<boolean>(() => {
  if (profileName.value.length === 0) {
    return false;
  }
  if (requiresConfirmation.value && confirmation.value !== profileName.value) {
    return false;
  }
  return true;
});

function onSubmit(): void {
  if (!canSubmit.value) {
    return;
  }
  emit('submit', profileName.value, requiresConfirmation.value ? confirmation.value : undefined);
}

function onDismiss(): void {
  profileName.value = '';
  confirmation.value = '';
  emit('dismiss');
}
</script>

<template>
  <div
    class="modal-backdrop"
    role="dialog"
    aria-modal="true"
    aria-labelledby="profile-switcher-title"
  >
    <form class="modal" @submit.prevent="onSubmit">
      <h2 id="profile-switcher-title">Switch environment</h2>
      <p v-if="currentProfile" class="modal__caption">Active: {{ currentProfile }}</p>
      <label class="modal__field">
        <span>Target environment</span>
        <input v-model="profileName" type="text" required autofocus />
      </label>
      <label v-if="requiresConfirmation" class="modal__field">
        <span>Type the profile name to confirm dangerous switch</span>
        <input v-model="confirmation" type="text" />
      </label>
      <div class="modal__actions">
        <button type="button" class="modal__btn modal__btn--ghost" @click="onDismiss">
          Cancel
        </button>
        <button type="submit" class="modal__btn modal__btn--primary" :disabled="!canSubmit">
          Switch
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: var(--backdrop);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal {
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  padding: 1.5rem 1.75rem;
  min-width: 320px;
  max-width: 480px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.modal h2 {
  margin: 0;
  font-size: 1.15rem;
}
.modal__caption {
  margin: 0;
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.modal__field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  font-size: 0.85rem;
}
.modal__field input {
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  padding: 0.5rem 0.625rem;
  font-size: 0.9rem;
}
.modal__actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.modal__btn {
  border: 0;
  border-radius: 0.375rem;
  padding: 0.4rem 0.85rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.modal__btn--primary {
  background: var(--accent);
  color: var(--accent-fg);
}
.modal__btn--primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.modal__btn--ghost {
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border-strong);
}
</style>
