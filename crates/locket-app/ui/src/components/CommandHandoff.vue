<script setup lang="ts">
import { computed, ref } from 'vue';

import { copyCommandToClipboard, type CopyCommandResult } from './commandHandoff';

interface Props {
  command: string;
  label: string;
  copyLabel?: string;
}

const props = defineProps<Props>();

const copyStatus = ref<CopyCommandResult | null>(null);

const copyButtonLabel = computed<string>(() => props.copyLabel ?? `Copy ${props.label}`);
const statusClass = computed<string>(() =>
  copyStatus.value?.ok === false ? 'handoff__status--error' : '',
);

async function copyCommand(): Promise<void> {
  copyStatus.value = await copyCommandToClipboard(props.command, navigator.clipboard);
}
</script>

<template>
  <div class="handoff">
    <label class="handoff__label">
      <span>{{ label }}</span>
      <textarea
        class="handoff__command"
        :value="command"
        readonly
        spellcheck="false"
        rows="3"
        :aria-label="label"
      />
    </label>
    <div class="handoff__actions">
      <button
        type="button"
        class="handoff__button"
        :aria-label="copyButtonLabel"
        @click="copyCommand"
      >
        Copy
      </button>
      <p v-if="copyStatus" class="handoff__status" :class="statusClass" role="status">
        {{ copyStatus.message }}
      </p>
    </div>
  </div>
</template>

<style scoped>
.handoff {
  box-sizing: border-box;
  width: min(42rem, 100%);
  display: grid;
  gap: 0.375rem;
}
.handoff__label {
  display: grid;
  gap: 0.25rem;
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.handoff__command {
  box-sizing: border-box;
  width: 100%;
  min-height: 4.75rem;
  resize: vertical;
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  padding: 0.5rem 0.625rem;
  font:
    0.8125rem ui-monospace,
    SFMono-Regular,
    Menlo,
    Monaco,
    Consolas,
    'Liberation Mono',
    monospace;
  line-height: 1.45;
}
.handoff__actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.handoff__button {
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
.handoff__button:focus-visible,
.handoff__command:focus-visible {
  outline: 2px solid var(--info);
  outline-offset: 2px;
}
.handoff__status {
  margin: 0;
  color: var(--success);
  font-size: 0.8rem;
}
.handoff__status--error {
  color: var(--danger);
}
</style>
