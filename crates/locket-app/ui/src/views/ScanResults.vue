<script setup lang="ts">
import AppIcon from '../components/AppIcon.vue';

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
    <header class="companion-toolbar view__header">
      <h2 id="scan-heading">Scan in terminal</h2>
      <button
        type="button"
        class="companion-button companion-button--primary"
        aria-label="Scan in terminal"
        :disabled="launching || !actionsEnabled"
        @click="onScan"
      >
        {{ launching ? 'Opening terminal…' : 'Scan in terminal' }}
      </button>
    </header>

    <div class="view__callout">
      <span class="view__callout-label">Command</span>
      <code class="view__command">locket scan --require-known</code>
    </div>

    <p class="view__help">
      Run <code>locket scan --require-known</code> in this project's trusted folder. The CLI uses
      the project's ignore rules, scan rules, and known values. Complete any unlock or approval in
      the terminal.
    </p>
    <p class="view__help view__help--note">
      <AppIcon name="alert" :size="14" />
      <span>
        Read the results in the terminal.
        <span>This app does not receive findings or completion status.</span>
      </span>
    </p>
    <p v-if="!actionsEnabled" class="view__notice">
      Connect a project and wait for project selection to finish before opening a scan.
    </p>
    <p v-if="launching" class="view__notice" role="status">Opening your terminal…</p>
    <p v-else-if="errorMessage" class="view__error" role="alert">{{ errorMessage }}</p>
    <p v-else-if="launchNotice" class="view__success" role="status">{{ launchNotice }}</p>
  </section>
</template>

<style scoped>
.view {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
}

.view__callout {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
  padding: 0.6rem 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
}

.view__callout-label {
  color: var(--text-muted);
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.view__command {
  color: var(--text-primary);
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}

.view__help,
.view__notice,
.view__error,
.view__success {
  max-width: 46rem;
  margin: 0;
  font-size: 0.875rem;
  line-height: 1.5;
  color: var(--text-secondary);
}

.view__help code {
  padding: 0 0.25rem;
  border-radius: 0.25rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  font-size: 0.8125rem;
}

.view__help--note {
  display: flex;
  align-items: flex-start;
  gap: 0.4rem;
}

.view__help--note .app-icon {
  flex: none;
  margin-top: 0.2rem;
  color: var(--text-muted);
}

.view__notice {
  color: var(--warn);
}

.view__success {
  color: var(--success);
}

.view__error {
  color: var(--danger);
}
</style>
