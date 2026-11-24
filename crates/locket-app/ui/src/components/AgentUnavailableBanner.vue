<script setup lang="ts">
import { computed } from 'vue';
import type { AgentClientError } from '../agent/types';
import AppIcon from './AppIcon.vue';

const props = defineProps<{
  error: AgentClientError;
  heading?: string;
  retrying?: boolean;
  canStart?: boolean;
  starting?: boolean;
}>();
const emit = defineEmits<{ retry: []; start: [] }>();

const unavailable = computed(
  () =>
    props.error.kind === 'unavailable' ||
    (props.error.kind === 'rejected' && props.error.code === 'AgentUnavailable'),
);
const title = computed(
  () => props.heading ?? (unavailable.value ? 'Locket agent unavailable' : 'Locket agent error'),
);
const code = computed(() =>
  props.error.kind === 'rejected'
    ? props.error.code
    : unavailable.value
      ? 'AgentUnavailable'
      : undefined,
);
const guidance = computed(() => {
  if (props.canStart) return 'Start the local Locket agent or retry the connection.';
  if (unavailable.value) return 'Check that the Locket agent is running, then retry.';
  if (props.error.kind === 'rejected') {
    return props.error.next_action || props.error.display_reason || 'Retry the request.';
  }
  if (props.error.kind === 'protocol') return props.error.reason;
  return props.error.next_action;
});
</script>

<template>
  <section class="agent-banner" role="alert" :aria-label="title">
    <AppIcon name="alert" :size="21" />
    <div class="agent-banner__body">
      <h2>{{ title }}</h2>
      <p>{{ guidance }}</p>
      <code v-if="code">{{ code }}</code>
    </div>
    <div class="agent-banner__actions">
      <button
        v-if="canStart"
        class="companion-button companion-button--primary icon-label"
        type="button"
        :disabled="starting || retrying"
        @click="emit('start')"
      >
        {{ starting ? 'Starting…' : 'Start agent' }}
      </button>
      <button
        class="companion-button icon-label agent-banner__retry"
        type="button"
        :disabled="retrying || starting"
        @click="emit('retry')"
      >
        <AppIcon name="refresh" />
        {{ retrying ? 'Retrying…' : 'Retry' }}
      </button>
    </div>
  </section>
</template>

<style scoped>
.agent-banner {
  display: flex;
  flex-wrap: wrap;
  align-items: start;
  gap: 0.65rem 0.85rem;
  padding: 0.9rem 1rem;
  border: 1px solid color-mix(in srgb, var(--danger) 35%, var(--border-subtle));
  border-radius: var(--radius-md);
  background: var(--danger-soft);
  color: var(--danger);
}
.agent-banner > .app-icon {
  margin-top: 0.1rem;
}
.agent-banner__body {
  flex: 1 1 12rem;
  min-width: 0;
}
.agent-banner h2 {
  margin: 0;
  font-size: 0.95rem;
}
.agent-banner p {
  margin: 0.25rem 0 0.45rem;
  color: var(--text-primary);
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}
.agent-banner code {
  display: inline-block;
  max-width: 100%;
  padding: 0.125rem 0.35rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  font-size: 0.7rem;
  overflow-wrap: anywhere;
}
.agent-banner__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-self: center;
  margin-inline-start: auto;
}
.agent-banner__retry:not(:hover) {
  background: transparent;
}
</style>
