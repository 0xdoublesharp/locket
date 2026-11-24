<script setup lang="ts">
import { computed } from 'vue';

import type { AgentClientError } from '../agent/types';

interface Props {
  error: AgentClientError;
}

const props = defineProps<Props>();

const heading = computed<string>(() => {
  switch (props.error.kind) {
    case 'unavailable':
      return 'Agent unavailable';
    case 'protocol':
      return 'Agent communication error';
    case 'rejected':
      return 'Agent rejected request';
    default:
      return 'Agent error';
  }
});

const detail = computed<string>(() => {
  switch (props.error.kind) {
    case 'unavailable':
      return props.error.display_reason;
    case 'protocol':
      return props.error.reason;
    case 'rejected':
      return props.error.display_reason || `${props.error.code}: ${props.error.message}`;
    default:
      return '';
  }
});

const nextAction = computed<string>(() => {
  switch (props.error.kind) {
    case 'unavailable':
      return props.error.next_action;
    case 'protocol':
      return 'Restart the agent. If the problem persists, file an issue.';
    case 'rejected':
      return props.error.next_action;
    default:
      return '';
  }
});
</script>

<template>
  <section class="agent-banner" role="alert" aria-live="polite" :aria-label="heading">
    <h2 class="agent-banner__heading">
      {{ heading }}
    </h2>
    <p v-if="detail" class="agent-banner__detail">
      {{ detail }}
    </p>
    <p v-if="nextAction" class="agent-banner__action">
      {{ nextAction }}
    </p>
  </section>
</template>

<style>
.agent-banner {
  background: var(--warn-soft);
  border: 1px solid var(--warn);
  color: var(--accent);
  padding: 1rem 1.25rem;
  border-radius: 0.5rem;
  max-width: 420px;
}

.agent-banner__heading {
  margin: 0 0 0.25rem;
  font-size: 0.9rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.agent-banner__detail,
.agent-banner__action {
  margin: 0.25rem 0 0;
  font-size: 0.875rem;
  color: var(--text-primary);
}

.agent-banner__action {
  color: var(--text-secondary);
}
</style>
