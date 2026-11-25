<script setup lang="ts">
import AppIcon from './AppIcon.vue';
import VariableSourceBadge from './VariableSourceBadge.vue';
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { desktopVariableReadiness } from '../agent/client';
import type { VariableReadinessResponse } from '../agent/types';
import {
  readinessBlocksRun,
  readinessPolicyDisplay,
  readinessSummary,
} from '../configuration/readiness';

const props = defineProps<{
  projectId?: string;
  profileId?: string;
  policyName?: string;
  privacyMode?: boolean;
  refreshKey?: string;
  hideRefresh?: boolean;
  collapsible?: boolean;
}>();
const emit = defineEmits<{ blocked: [value: boolean] }>();
const loading = ref(false);
const error = ref<string | null>(null);
const response = ref<VariableReadinessResponse | null>(null);
const openByDefault =
  typeof window !== 'undefined' && window.matchMedia?.('(min-width: 960px)').matches;
let requestSequence = 0;
const checks = computed(
  () =>
    response.value?.policies
      .map((policy, index) => ({ policy, index }))
      .filter(({ policy }) => !props.policyName || policy.policy_name === props.policyName) ?? [],
);
const summary = computed(() =>
  readinessSummary(
    checks.value.flatMap(({ policy }) => (policy.error ? [] : policy.rows)),
    checks.value.filter(({ policy }) => Boolean(policy.error)).length,
  ),
);
const policies = computed(() =>
  checks.value.map(({ policy, index }) => {
    const display = readinessPolicyDisplay(policy, props.privacyMode ?? false, index);
    return { policyName: policy.policy_name, ...display, status: policyStatus(display) };
  }),
);

function policyStatus(policy: ReturnType<typeof readinessPolicyDisplay>): {
  label: string;
  tone: 'ok' | 'warn' | 'danger' | 'neutral';
} {
  if (policy.error) return { label: 'Check failed', tone: 'danger' };
  const total = policy.rows.length;
  if (total === 0) return { label: 'No variables', tone: 'neutral' };
  const missing = policy.rows.filter(
    (row) => row.state === 'missing' && row.requirement === 'Required',
  ).length;
  if (missing > 0) return { label: `${missing} missing`, tone: 'danger' };
  const pending = policy.rows.filter((row) => row.state === 'unverified').length;
  if (pending > 0) return { label: `${pending} to check at launch`, tone: 'warn' };
  const ready = policy.rows.filter((row) => row.state === 'ready').length;
  return {
    label: `${ready} of ${total} ready`,
    tone: ready === total ? 'ok' : 'neutral',
  };
}

async function refresh(): Promise<void> {
  const sequence = ++requestSequence;
  response.value = null;
  error.value = null;
  emit('blocked', false);
  if (!props.projectId) {
    loading.value = false;
    return;
  }
  loading.value = true;
  const projectId = props.projectId;
  const result = await desktopVariableReadiness({
    project_id: projectId,
    policy_name: props.policyName,
  });
  if (sequence !== requestSequence) return;
  loading.value = false;
  if (!result.ok) {
    error.value =
      'Configuration checks are unavailable. Refresh after checking the project and local store.';
    return;
  }
  if (
    result.value.project_id !== projectId ||
    (props.profileId && result.value.profile_id !== props.profileId)
  ) {
    error.value = 'The project or environment changed. Refresh configuration checks.';
    return;
  }
  response.value = result.value;
  emit('blocked', readinessBlocksRun(result.value.policies, props.policyName));
}
watch(
  () => [props.projectId, props.profileId, props.policyName, props.refreshKey],
  () => {
    void refresh();
  },
  { immediate: true },
);
onBeforeUnmount(() => {
  requestSequence += 1;
});
</script>

<template>
  <section class="readiness" aria-label="Configuration checks" data-testid="variable-readiness">
    <header class="readiness__header">
      <h3 class="readiness__title">Configuration checks</h3>
      <button
        v-if="!hideRefresh"
        class="companion-button icon-label"
        type="button"
        :disabled="loading || !projectId"
        @click="refresh"
      >
        <AppIcon name="refresh" /> Refresh
      </button>
    </header>
    <p v-if="!projectId" class="readiness__text">Open a project to check its required variables.</p>
    <p v-else-if="loading" class="readiness__text" role="status">
      Checking variable names and sources…
    </p>
    <p v-else-if="error" class="readiness__text readiness__text--error" role="alert">
      {{ error }}
    </p>
    <template v-else-if="response">
      <p class="readiness__text" role="status">
        {{ summary.label }}. Values are checked when the command starts.
      </p>
      <p v-if="!privacyMode" class="readiness__text readiness__context">
        Environment: {{ response.profile_name }}
      </p>
      <p v-if="summary.unverified" class="readiness__text readiness__context">
        External sources will be checked at launch.
      </p>
      <div class="readiness__policies">
        <component
          :is="collapsible ? 'details' : 'section'"
          v-for="(policy, policyIndex) in policies"
          :key="policyIndex"
          :open="collapsible && policyIndex === 0 && openByDefault ? true : undefined"
          :class="['readiness__policy', { 'readiness__policy--collapsible': collapsible }]"
        >
          <summary v-if="collapsible" class="readiness__summary">
            <AppIcon name="chevron-down" class="readiness__chevron" :size="14" />
            <span class="readiness__policy-name">{{ policy.name }}</span>
            <span :class="['companion-pill', `companion-pill--${policy.status.tone}`]">{{
              policy.status.label
            }}</span>
          </summary>
          <div v-else class="readiness__summary readiness__summary--static">
            <h4 class="readiness__policy-name">{{ policy.name }}</h4>
            <span :class="['companion-pill', `companion-pill--${policy.status.tone}`]">{{
              policy.status.label
            }}</span>
          </div>
          <p v-if="policy.error" class="readiness__text readiness__text--error" role="alert">
            {{ policy.error }}
          </p>
          <p v-else-if="policy.rows.length === 0" class="readiness__text readiness__context">
            This command requests no variables.
          </p>
          <ul v-else class="readiness__rows">
            <li v-for="(row, rowIndex) in policy.rows" :key="rowIndex" class="readiness__item">
              <div class="readiness__row">
                <strong>{{ row.name }}</strong>
                <span class="readiness__metadata">
                  <VariableSourceBadge :source="row.source" />
                  <span class="readiness__requirement"
                    >{{ row.requirement }} · {{ row.classification }}</span
                  >
                  <span class="readiness__state" :data-state="row.state">
                    <AppIcon :name="row.state === 'ready' ? 'check' : 'alert'" :size="14" />
                    {{ row.state }}
                  </span>
                </span>
              </div>
              <p v-for="(guidance, index) in row.guidance" :key="index" class="readiness__note">
                {{ guidance }}
              </p>
              <p v-if="row.warning" class="readiness__note readiness__warning" role="status">
                {{ row.warning }}
              </p>
            </li>
          </ul>
        </component>
      </div>
    </template>
  </section>
</template>

<style scoped>
.readiness {
  container: readiness / inline-size;
  min-width: 0;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 0.9rem 1rem;
  color: var(--text-primary);
}
.readiness__header,
.readiness__row {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}
.readiness__title,
.readiness__policy-name {
  margin: 0;
  font-size: 1rem;
}
.readiness__text {
  margin: 0.4rem 0 0;
  color: var(--text-secondary);
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}
.readiness__text--error {
  color: var(--danger);
}
.readiness__context {
  margin-top: 0.15rem;
  color: var(--text-muted);
  font-size: 0.8125rem;
}
.readiness__policies {
  display: grid;
  gap: 0.4rem;
  margin-top: 0.75rem;
}
.readiness__policy:not(.readiness__policy--collapsible) + .readiness__policy {
  margin-top: 0.6rem;
}
.readiness__policy--collapsible {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
}
.readiness__summary {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  min-width: 0;
}
.readiness__policy--collapsible > .readiness__summary {
  padding: 0.5rem 0.65rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
  list-style: none;
}
.readiness__policy--collapsible > .readiness__summary::-webkit-details-marker {
  display: none;
}
.readiness__policy--collapsible > .readiness__summary:hover {
  background: var(--bg-subtle);
}
.readiness__policy--collapsible[open] > .readiness__summary {
  border-bottom: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm) var(--radius-sm) 0 0;
}
.readiness__summary .readiness__policy-name {
  flex: 1 1 auto;
  min-width: 0;
  font-size: 0.875rem;
  font-weight: 650;
  overflow-wrap: anywhere;
}
.readiness__summary .companion-pill {
  flex: none;
}
.readiness__chevron {
  flex: none;
  color: var(--text-muted);
  transform: rotate(-90deg);
  transition: transform 120ms ease;
}
.readiness__policy[open] .readiness__chevron {
  transform: none;
}
.readiness__summary--static {
  padding-bottom: 0.35rem;
}
.readiness__rows {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
}
.readiness__policy--collapsible .readiness__rows {
  padding: 0 0.65rem;
}
.readiness__item {
  padding: 0.4rem 0;
  border-top: 1px solid var(--border-subtle);
}
.readiness__item:first-child {
  border-top: 0;
}
.readiness__row strong {
  font: 650 0.8125rem var(--font-mono);
  overflow-wrap: anywhere;
}
.readiness__metadata,
.readiness__state {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
}
.readiness__metadata {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.readiness__requirement {
  white-space: nowrap;
}
.readiness__state {
  padding: 0.1rem 0.4rem;
  border-radius: var(--radius-sm);
  color: var(--warn);
  background: var(--warn-soft);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  white-space: nowrap;
}
.readiness__state[data-state='ready'] {
  color: var(--success);
  background: var(--success-soft);
}
.readiness__state[data-state='missing'] {
  color: var(--danger);
  background: var(--danger-soft);
}
.readiness__note {
  margin: 0.25rem 0 0;
  color: var(--text-secondary);
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}
.readiness__warning {
  color: var(--accent);
}
@container readiness (max-width: 30rem) {
  .readiness__row {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.25rem;
  }
}
</style>
