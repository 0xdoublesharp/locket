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
const summary = computed(() =>
  readinessSummary(
    response.value?.policies.filter((policy) => !policy.error).flatMap((policy) => policy.rows) ??
      [],
    response.value?.policies.filter((policy) => Boolean(policy.error)).length ?? 0,
  ),
);
const policies = computed(
  () =>
    response.value?.policies.map((policy, index) =>
      readinessPolicyDisplay(policy, props.privacyMode ?? false, index),
    ) ?? [],
);

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
    <header>
      <h3>Configuration checks</h3>
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
    <p v-if="!projectId">Open a project to check its required variables.</p>
    <p v-else-if="loading" role="status">Checking variable names and sources…</p>
    <p v-else-if="error" role="alert">{{ error }}</p>
    <template v-else-if="response">
      <p role="status">{{ summary.label }}. Values are checked when the command starts.</p>
      <p v-if="!privacyMode" class="readiness__context">Environment: {{ response.profile_name }}</p>
      <p v-if="summary.unverified">External sources will be checked at launch.</p>
      <component
        :is="collapsible ? 'details' : 'section'"
        v-for="(policy, policyIndex) in policies"
        :key="policyIndex"
        :open="collapsible && policyIndex === 0 && openByDefault ? true : undefined"
        class="readiness__policy"
      >
        <summary v-if="collapsible">{{ policy.name }}</summary>
        <h4 v-else>{{ policy.name }}</h4>
        <p v-if="policy.error" role="alert">{{ policy.error }}</p>
        <p v-else-if="policy.rows.length === 0">This command requests no variables.</p>
        <ul v-else>
          <li v-for="(row, rowIndex) in policy.rows" :key="rowIndex">
            <div class="readiness__row">
              <strong>{{ row.name }}</strong>
              <span class="readiness__metadata">
                <VariableSourceBadge :source="row.source" />
                {{ row.requirement }} · {{ row.classification }}
                <span class="readiness__state" :data-state="row.state">
                  <AppIcon :name="row.state === 'ready' ? 'check' : 'alert'" :size="14" />
                  {{ row.state }}
                </span>
              </span>
            </div>
            <p v-for="(guidance, index) in row.guidance" :key="index">{{ guidance }}</p>
            <p v-if="row.warning" class="readiness__warning" role="status">{{ row.warning }}</p>
          </li>
        </ul>
      </component>
    </template>
  </section>
</template>

<style scoped>
.readiness {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  padding: 1rem;
  color: var(--text-primary);
}
header,
.readiness__row {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
}
h3,
h4 {
  margin: 0;
  font-size: 1rem;
}
p {
  margin: 0.4rem 0;
  overflow-wrap: anywhere;
}
ul {
  list-style: none;
  padding: 0;
  margin: 0.5rem 0;
  display: grid;
  gap: 0.35rem;
}
li {
  border-top: 1px solid var(--border-subtle);
  padding-top: 0.35rem;
}
.readiness__metadata,
.readiness__context {
  color: var(--text-secondary);
  font-size: 0.85rem;
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
.readiness__state {
  padding: 0.125rem 0.4rem;
  border-radius: var(--radius-sm);
  color: var(--warn);
  background: var(--warn-soft);
  text-transform: capitalize;
}
.readiness__state[data-state='ready'] {
  color: var(--success);
  background: var(--success-soft);
}
.readiness__state[data-state='missing'] {
  color: var(--danger);
  background: var(--danger-soft);
}
.readiness li p {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.readiness li .readiness__warning {
  color: var(--accent);
}
.readiness__policy {
  margin-top: 1rem;
}
details.readiness__policy {
  margin-top: 0.4rem;
  padding-inline: 0.65rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
}
.readiness__policy summary {
  padding-block: 0.45rem;
  overflow-wrap: anywhere;
  font-size: 0.85rem;
  font-weight: 650;
  cursor: pointer;
}
</style>
