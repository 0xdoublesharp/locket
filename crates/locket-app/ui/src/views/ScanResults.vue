<script setup lang="ts">
interface Props {
  actionsEnabled: boolean;
  launching: boolean;
  errorMessage?: string | null;
  launchNotice?: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: 'scan'): void;
}>();

function onScan(): void {
  if (props.actionsEnabled && !props.launching) emit('scan');
}
</script>

<template>
  <section class="view" aria-labelledby="scan-heading">
    <header class="view__header">
      <h2 id="scan-heading">Scan in terminal</h2>
      <button
        type="button"
        class="view__action"
        aria-label="Scan in terminal"
        :disabled="launching || !actionsEnabled"
        @click="onScan"
      >
        {{ launching ? 'Opening terminal…' : 'Scan in terminal' }}
      </button>
    </header>

    <p class="view__help">
      Run <code>locket scan --require-known</code> in this project's trusted folder. The CLI uses
      the project's ignore rules, scan rules, and known values. Complete any unlock or approval in
      the terminal.
    </p>
    <p class="view__help">
      Read the results in the terminal. This app does not receive findings or completion status.
    </p>
    <p v-if="!actionsEnabled" class="view__notice">
      Connect a project and wait for project selection to finish before opening a scan.
    </p>
    <p v-if="launching" class="view__notice" role="status">Opening your terminal…</p>
    <p v-else-if="errorMessage" class="view__error" role="alert">{{ errorMessage }}</p>
    <p v-else-if="launchNotice" class="view__notice" role="status">{{ launchNotice }}</p>
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
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
  gap: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
}

.view__action {
  background: var(--bg-subtle);
  color: var(--text-primary);
  border: 1px solid var(--border-subtle);
  border-radius: 0.375rem;
  padding: 0.25rem 0.75rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover:not(:disabled) {
  background: var(--bg-subtle);
}

.view__action:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.view__action:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.view__help,
.view__notice,
.view__error {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.view__notice {
  color: var(--accent);
}

.view__error {
  color: var(--danger);
}
</style>
