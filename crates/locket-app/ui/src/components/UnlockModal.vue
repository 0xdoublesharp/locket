<script setup lang="ts">
import { ref, watch } from 'vue';
import type { UnlockRequest } from '../agent/types';
const props = defineProps<{ projectLabel: string; busy: boolean; errorMessage?: string | null }>();
const emit = defineEmits<{ submit: [source: UnlockRequest['source']]; dismiss: [] }>();
const passphrase = ref('');
const usePassphrase = ref(false);
watch(
  () => props.errorMessage,
  () => {
    passphrase.value = '';
  },
);
watch(usePassphrase, () => {
  passphrase.value = '';
});
function onSubmit(): void {
  if (props.busy || (usePassphrase.value && !passphrase.value)) return;
  emit(
    'submit',
    usePassphrase.value
      ? { kind: 'passphrase', passphrase: passphrase.value }
      : { kind: 'os-keychain' },
  );
  passphrase.value = '';
}
function onDismiss(): void {
  if (!props.busy) {
    passphrase.value = '';
    emit('dismiss');
  }
}
</script>
<template>
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="unlock-title">
    <form class="modal" @submit.prevent="onSubmit">
      <h2 id="unlock-title">Unlock vault</h2>
      <p class="modal__caption">Project: {{ projectLabel }}</p>
      <p class="modal__caption">
        Unlocks this project for a limited time. The system may ask for verification.
      </p>
      <label
        ><input v-model="usePassphrase" type="checkbox" :disabled="props.busy" /> Use a passphrase
        instead</label
      >
      <label v-if="usePassphrase" class="modal__field">
        <span>Passphrase</span>
        <input
          v-model="passphrase"
          type="password"
          autocomplete="off"
          :disabled="props.busy"
          required
          autofocus
        />
      </label>
      <p v-if="props.errorMessage" role="alert">{{ props.errorMessage }}</p>
      <div class="modal__actions">
        <button
          type="button"
          class="modal__btn modal__btn--ghost"
          :disabled="props.busy"
          @click="onDismiss"
        >
          Cancel
        </button>
        <button
          type="submit"
          class="modal__btn modal__btn--primary"
          :disabled="props.busy || (usePassphrase && !passphrase)"
        >
          {{
            props.busy
              ? 'Unlocking…'
              : usePassphrase
                ? 'Unlock with passphrase'
                : 'Use system keychain'
          }}
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
