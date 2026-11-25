<script setup lang="ts">
import { ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';

defineProps<{ id: string; label: string; error?: string; disabled: boolean }>();
const value = defineModel<string>({ required: true });
const visible = ref(false);

watch(value, (draft) => {
  if (!draft) visible.value = false;
});

function generate(): void {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  value.value = btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
  bytes.fill(0);
}
</script>

<template>
  <div class="secret-value">
    <label :for="id">{{ label }}</label>
    <div class="secret-value__controls">
      <input
        :id="id"
        v-model="value"
        class="companion-input"
        :type="visible ? 'text' : 'password'"
        :aria-describedby="error ? `${id}-error` : undefined"
        :data-testid="id"
        autocomplete="new-password"
        spellcheck="false"
        :disabled="disabled"
      />
      <button
        class="companion-button icon-label"
        type="button"
        :title="visible ? 'Hide secret value' : 'Show secret value'"
        :aria-label="visible ? 'Hide secret value' : 'Show secret value'"
        :aria-controls="id"
        :disabled="disabled"
        @click="visible = !visible"
      >
        <AppIcon name="eye" />
      </button>
      <button class="companion-button" type="button" :disabled="disabled" @click="generate">
        Generate
      </button>
    </div>
    <span v-if="error" :id="`${id}-error`" class="secret-value__error">{{ error }}</span>
  </div>
</template>

<style scoped>
.secret-value {
  display: grid;
  gap: 0.25rem;
  font-size: 0.85rem;
}
.secret-value__controls {
  display: flex;
  align-items: stretch;
  gap: 0.35rem;
}
.secret-value__controls input {
  flex: 1;
  min-width: 0;
}
.secret-value__error {
  color: var(--danger);
  font-size: 0.8rem;
}
</style>
