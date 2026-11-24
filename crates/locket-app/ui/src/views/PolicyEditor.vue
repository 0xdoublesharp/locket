<script setup lang="ts">
import { formatTime } from '../utils/formatTime';
import { computed, ref, watch } from 'vue';
import VariableReadinessPanel from '../components/VariableReadinessPanel.vue';

import type { CommandPolicyRow } from '../types/views';

defineOptions({ name: 'PolicyEditor' });

interface Props {
  projectId?: string;
  profileId?: string;
  rows: CommandPolicyRow[];
  privacyMode: boolean;
  loading: boolean;
  metadataLoaded: boolean;
  actionGuidance?: string | null;
  errorMessage?: string | null;
  actionsEnabled: boolean;
  running?: boolean;
  runError?: string | null;
  runNotice?: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  refresh: [];
  create: [];
  edit: [row: CommandPolicyRow];
  delete: [row: CommandPolicyRow];
  run: [row: CommandPolicyRow];
}>();

const configurationMissing = ref(false);
const selectedId = ref<string | null>(null);
const searchQuery = ref<string>('');

const sortedRows = computed<CommandPolicyRow[]>(() =>
  [...props.rows].sort((left, right) => left.name.localeCompare(right.name)),
);

const filteredRows = computed<CommandPolicyRow[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return sortedRows.value;
  }
  return sortedRows.value.filter((row) => searchText(row).includes(query));
});

const selectedPolicy = computed<CommandPolicyRow | null>(() => {
  if (filteredRows.value.length === 0) {
    return null;
  }
  return filteredRows.value.find((row) => row.id === selectedId.value) ?? filteredRows.value[0];
});

watch(
  () => [props.projectId, props.profileId, selectedPolicy.value?.name],
  () => {
    configurationMissing.value = false;
  },
);

const isEmpty = computed<boolean>(
  () => props.metadataLoaded && !props.loading && sortedRows.value.length === 0,
);
const isFilteredEmpty = computed<boolean>(
  () => !props.loading && sortedRows.value.length > 0 && filteredRows.value.length === 0,
);

function policyLabel(row: CommandPolicyRow): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

function secretCount(row: CommandPolicyRow): number {
  return new Set([...row.requiredSecrets, ...row.optionalSecrets, ...row.allowedSecrets]).size;
}

function gateLabels(row: CommandPolicyRow): string[] {
  const labels: string[] = [];
  if (row.confirm) {
    labels.push('confirm');
  }
  if (row.requireUserVerification) {
    labels.push('verify user');
  }
  if (row.requireAgent) labels.push('agent required');
  if (row.allowRemoteDocker) {
    labels.push('remote docker');
  }
  return labels;
}

function secretSearchLabels(row: CommandPolicyRow): string[] {
  if (props.privacyMode) {
    return [];
  }
  return [...row.requiredSecrets, ...row.optionalSecrets, ...row.allowedSecrets];
}

function searchText(row: CommandPolicyRow): string {
  return [
    policyLabel(row),
    row.commandKind,
    row.commandPreview,
    row.envMode,
    row.overrideMode,
    ...gateLabels(row),
    ...secretSearchLabels(row),
    `${secretCount(row)} secrets`,
    ttlLabel(row.ttlSeconds),
    row.updatedAt,
  ]
    .join(' ')
    .toLowerCase();
}

function ttlLabel(seconds: number): string {
  if (seconds <= 0) {
    return '0s';
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes === 0) {
    return `${seconds}s`;
  }
  if (remainder === 0) {
    return `${minutes}m`;
  }
  return `${minutes}m ${remainder}s`;
}

function selectPolicy(row: CommandPolicyRow): void {
  selectedId.value = row.id;
}

function refreshPolicies(): void {
  emit('refresh');
}

function startCreate(): void {
  emit('create');
}

function startEdit(): void {
  if (selectedPolicy.value) {
    emit('edit', selectedPolicy.value);
  }
}

function startDelete(): void {
  if (selectedPolicy.value) {
    emit('delete', selectedPolicy.value);
  }
}
</script>

<template>
  <section class="view" aria-labelledby="policy-editor-heading">
    <header class="view__header">
      <h2 id="policy-editor-heading">Commands</h2>
      <div class="view__actions">
        <label class="view__search">
          <span class="view__search-label">Search commands</span>
          <input
            v-model="searchQuery"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search metadata"
          />
        </label>
        <button type="button" class="view__button" :disabled="!actionsEnabled" @click="startCreate">
          New command
        </button>
        <button
          type="button"
          class="view__button"
          :disabled="!actionsEnabled || !selectedPolicy"
          @click="startEdit"
        >
          Edit
        </button>
        <button
          type="button"
          class="view__button view__button--danger"
          :disabled="!actionsEnabled || !selectedPolicy"
          @click="startDelete"
        >
          Delete
        </button>
        <button type="button" class="view__button" @click="refreshPolicies">Refresh</button>
      </div>
    </header>

    <p v-if="runError" role="alert">{{ runError }}</p>
    <p v-if="runNotice" role="status">{{ runNotice }}</p>
    <p v-if="actionGuidance" class="view__empty" role="status">{{ actionGuidance }}</p>
    <p v-else-if="loading" class="view__loading" role="status">Loading policy metadata...</p>

    <p v-else-if="errorMessage" class="view__empty">{{ errorMessage }}</p>

    <p v-else-if="isEmpty" class="view__empty">
      No commands yet. Choose New command to approve a command and its variable access.
    </p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching policies.</p>

    <div v-else class="policy-layout">
      <div
        class="companion-table-scroll"
        role="region"
        aria-labelledby="policy-editor-heading"
        tabindex="0"
      >
        <table class="view__table" aria-describedby="policy-editor-heading">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Mode</th>
              <th scope="col">Secrets</th>
              <th scope="col">TTL</th>
              <th scope="col">Gates</th>
              <th scope="col">Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in filteredRows"
              :key="row.id"
              :class="['view__row', { 'view__row--selected': selectedPolicy?.id === row.id }]"
              tabindex="0"
              :aria-label="`Inspect policy ${policyLabel(row)}`"
              @click="selectPolicy(row)"
              @keydown.enter.prevent="selectPolicy(row)"
              @keydown.space.prevent="selectPolicy(row)"
            >
              <td>
                <span class="view__name">{{ policyLabel(row) }}</span>
              </td>
              <td>
                <span
                  :class="['badge', row.commandKind === 'shell' ? 'badge--warning' : 'badge--ok']"
                >
                  {{ row.commandKind }}
                </span>
              </td>
              <td>{{ secretCount(row) }}</td>
              <td>{{ ttlLabel(row.ttlSeconds) }}</td>
              <td>
                <span v-if="gateLabels(row).length > 0" class="view__badges">
                  <span v-for="gate in gateLabels(row)" :key="gate" class="badge badge--gate">
                    {{ gate }}
                  </span>
                </span>
                <span v-else class="view__muted">none</span>
              </td>
              <td>
                <time :datetime="row.updatedAt" :title="row.updatedAt">{{
                  formatTime(row.updatedAt)
                }}</time>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <aside v-if="selectedPolicy" class="policy-detail" aria-labelledby="policy-detail-heading">
        <VariableReadinessPanel
          :project-id="projectId"
          :profile-id="profileId"
          :policy-name="selectedPolicy.name"
          :privacy-mode="privacyMode"
          :refresh-key="selectedPolicy.updatedAt"
          @blocked="configurationMissing = $event"
        />
        <p v-if="configurationMissing" role="status">
          Resolve this command’s configuration checks before running it.
        </p>
        <button
          type="button"
          class="view__button"
          :disabled="!actionsEnabled || running || configurationMissing"
          @click="emit('run', selectedPolicy)"
        >
          {{ running ? 'Opening terminal…' : 'Run in terminal' }}
        </button>
        <h3 id="policy-detail-heading">{{ policyLabel(selectedPolicy) }}</h3>

        <dl class="policy-detail__grid">
          <div>
            <dt>Command kind</dt>
            <dd>{{ selectedPolicy.commandKind }}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>{{ selectedPolicy.envMode }}</dd>
          </div>
          <div>
            <dt>Override</dt>
            <dd>{{ selectedPolicy.overrideMode }}</dd>
          </div>
          <div>
            <dt>TTL</dt>
            <dd>{{ ttlLabel(selectedPolicy.ttlSeconds) }}</dd>
          </div>
        </dl>

        <section class="policy-detail__section" aria-labelledby="policy-command-heading">
          <h4 id="policy-command-heading">Command</h4>
          <code class="policy-detail__command">{{ selectedPolicy.commandPreview }}</code>
        </section>

        <section class="policy-detail__section" aria-labelledby="policy-secret-heading">
          <h4 id="policy-secret-heading">Secret access</h4>
          <dl class="policy-detail__secrets">
            <div>
              <dt>Required</dt>
              <dd>{{ selectedPolicy.requiredSecrets.length }}</dd>
            </div>
            <div>
              <dt>Optional</dt>
              <dd>{{ selectedPolicy.optionalSecrets.length }}</dd>
            </div>
            <div>
              <dt>Allowed</dt>
              <dd>{{ selectedPolicy.allowedSecrets.length }}</dd>
            </div>
          </dl>
        </section>

        <section class="policy-detail__section" aria-labelledby="policy-gates-heading">
          <h4 id="policy-gates-heading">Gates</h4>
          <div class="view__badges">
            <span v-if="selectedPolicy.requireAgent" class="badge badge--gate">agent required</span>
            <span v-if="selectedPolicy.confirm" class="badge badge--gate">confirm</span>
            <span v-if="selectedPolicy.requireUserVerification" class="badge badge--gate">
              verify user
            </span>
            <span v-if="selectedPolicy.allowRemoteDocker" class="badge badge--warning">
              remote docker
            </span>
            <span
              v-if="
                !selectedPolicy.requireAgent &&
                !selectedPolicy.confirm &&
                !selectedPolicy.requireUserVerification &&
                !selectedPolicy.allowRemoteDocker
              "
              class="view__muted"
            >
              none
            </span>
          </div>
        </section>
      </aside>
    </div>
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
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
}

.view__actions {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.view__search {
  display: grid;
  gap: 0.25rem;
  min-width: min(18rem, 100%);
}

.view__search-label {
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.view__search input {
  box-sizing: border-box;
  width: 100%;
  min-height: 2rem;
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  font: inherit;
  padding: 0.375rem 0.625rem;
}

.view__search input:focus {
  border-color: var(--accent);
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}

.view__search input::placeholder {
  color: var(--text-muted);
}

.view__button {
  min-height: 2rem;
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  cursor: pointer;
  font: inherit;
  padding: 0.375rem 0.625rem;
}

.view__button:focus {
  border-color: var(--accent);
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}

.view__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.view__button--danger {
  border-color: var(--danger);
  color: var(--danger);
}

.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.view__empty code,
.policy-detail__command {
  background: var(--bg-subtle);
  border-radius: 0.25rem;
  color: var(--text-primary);
  font-size: 0.8125rem;
}

.view__empty code {
  padding: 0.125rem 0.25rem;
}

.policy-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(18rem, 24rem);
  gap: 1rem;
  align-items: start;
}

.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.view__table th,
.view__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: top;
}

.view__table th {
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
}

.view__row {
  cursor: pointer;
}

.view__row:hover,
.view__row--selected {
  background: var(--bg-subtle);
}

.view__row:focus {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}

.view__name {
  font-weight: 600;
}

.view__muted {
  color: var(--text-secondary);
}

.view__badges {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  letter-spacing: 0.02em;
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
  white-space: nowrap;
}

.badge--ok {
  background: var(--success-soft);
  border-color: var(--border-strong);
  color: var(--success);
}

.badge--warning {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}

.badge--gate,
.badge--neutral {
  color: var(--text-secondary);
}

.policy-detail {
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
  padding: 0.875rem;
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
}

.policy-detail h3,
.policy-detail h4 {
  margin: 0;
}

.policy-detail h3 {
  font-size: 0.9375rem;
}

.policy-detail h4 {
  font-size: 0.75rem;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
}

.policy-detail__grid,
.policy-detail__secrets {
  margin: 0;
  display: grid;
  gap: 0.5rem;
}

.policy-detail__grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.policy-detail__secrets {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.policy-detail__grid div,
.policy-detail__secrets div {
  min-width: 0;
}

.policy-detail dt {
  color: var(--text-secondary);
  font-size: 0.75rem;
}

.policy-detail dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
}

.policy-detail__section {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.policy-detail__command {
  display: block;
  padding: 0.5rem;
  overflow-wrap: anywhere;
}

@media (max-width: 960px) {
  .policy-layout {
    grid-template-columns: 1fr;
  }
}
</style>
