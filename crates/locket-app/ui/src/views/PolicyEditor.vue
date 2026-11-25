<script setup lang="ts">
import { formatTime } from '../utils/formatTime';
import { computed, onScopeDispose, ref, watch } from 'vue';
import { desktopCopyTextPlain } from '../agent/client';
import AppIcon from '../components/AppIcon.vue';
import VariableReadinessPanel from '../components/VariableReadinessPanel.vue';
import { createRequestLifetime } from '../utils/requestLifetime';
import { shellQuote } from '../utils/shellQuote';

import type { CommandPolicyRow } from '../types/views';
import type { DetectedCommandRow } from '../agent/types';

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
  detectedCommands?: DetectedCommandRow[];
  detectingCommands?: boolean;
  detectionError?: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  refresh: [];
  create: [];
  addDetected: [row: DetectedCommandRow];
  edit: [row: CommandPolicyRow];
  delete: [row: CommandPolicyRow];
  run: [row: CommandPolicyRow];
}>();

const configurationMissing = ref(false);
const refreshCount = ref(0);
const selectedId = ref<string | null>(null);
const searchQuery = ref<string>('');
const policyDetail = ref<HTMLElement | null>(null);

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

const invocation = computed(() => {
  const name = selectedPolicy.value?.name;
  return !props.privacyMode && name ? `locket run ${shellQuote(name)}` : '';
});
const copyStatus = ref('');
const copyRequests = createRequestLifetime();
let copyTimer: ReturnType<typeof setTimeout> | undefined;

function resetCopyStatus(): void {
  clearTimeout(copyTimer);
  copyStatus.value = '';
}

watch(
  [invocation, () => props.projectId, () => props.profileId],
  () => {
    copyRequests.invalidate();
    resetCopyStatus();
  },
  { flush: 'sync' },
);
onScopeDispose(() => {
  copyRequests.dispose();
  clearTimeout(copyTimer);
});

async function copyInvocation(): Promise<void> {
  const command = invocation.value;
  if (!command) return;
  resetCopyStatus();
  const isCurrent = copyRequests.begin();
  const result = await desktopCopyTextPlain(command);
  if (!isCurrent()) return;
  copyStatus.value = result.ok ? 'Copied' : 'Could not copy command.';
  copyTimer = setTimeout(resetCopyStatus, 2000);
}

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
const unconfiguredCommands = computed(() =>
  (props.detectedCommands ?? []).filter((row) => !row.already_configured),
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
    ...(props.privacyMode ? [] : [row.commandPreview]),
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

function focusPolicyDetail(): void {
  policyDetail.value?.focus();
}

function refreshPolicies(): void {
  refreshCount.value += 1;
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
    <header class="companion-toolbar view__header">
      <h2 id="policy-editor-heading">Commands</h2>
      <div class="companion-toolbar__controls">
        <label class="companion-toolbar__search">
          <span class="visually-hidden">Search commands</span>
          <AppIcon name="search" :size="14" />
          <input
            v-model="searchQuery"
            class="companion-input"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search commands…"
          />
        </label>
        <div class="view__button-group">
          <button
            type="button"
            class="companion-button icon-label"
            :class="{ 'companion-button--primary': filteredRows.length === 0 }"
            :disabled="!actionsEnabled"
            @click="startCreate"
          >
            <AppIcon name="plus" />
            New command
          </button>
          <button
            type="button"
            class="companion-button"
            :disabled="!actionsEnabled || !selectedPolicy"
            @click="startEdit"
          >
            Edit
          </button>
          <button
            type="button"
            class="companion-button companion-button--danger"
            :disabled="!actionsEnabled || !selectedPolicy"
            @click="startDelete"
          >
            Delete
          </button>
          <button
            type="button"
            class="companion-button icon-label"
            aria-label="Refresh commands"
            title="Refresh commands"
            @click="refreshPolicies"
          >
            <AppIcon name="refresh" />
            Refresh
          </button>
        </div>
      </div>
    </header>

    <p v-if="runError" role="alert">{{ runError }}</p>
    <p v-if="runNotice" role="status">{{ runNotice }}</p>
    <p v-if="actionGuidance" class="view__empty" role="status">{{ actionGuidance }}</p>
    <p v-else-if="loading" class="view__loading" role="status">Loading policy metadata...</p>

    <p v-else-if="errorMessage" class="view__empty">{{ errorMessage }}</p>

    <p v-else-if="isEmpty" class="view__empty">
      No commands yet.<template v-if="!detectingCommands && unconfiguredCommands.length === 0">
        Choose New command to approve a command and its variable access.</template
      >
    </p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching policies.</p>

    <div v-else class="policy-layout">
      <div
        class="companion-table-scroll policy-table"
        role="region"
        aria-labelledby="policy-editor-heading"
        tabindex="0"
      >
        <table class="view__table" role="table" aria-describedby="policy-editor-heading">
          <thead role="rowgroup">
            <tr role="row">
              <th scope="col" role="columnheader">Name</th>
              <th scope="col" role="columnheader">Mode</th>
              <th scope="col" role="columnheader">Secrets</th>
              <th scope="col" role="columnheader">TTL</th>
              <th scope="col" role="columnheader">Updated</th>
              <th scope="col" role="columnheader">Gates</th>
            </tr>
          </thead>
          <tbody role="rowgroup">
            <tr
              v-for="row in filteredRows"
              :key="row.id"
              role="row"
              :class="['view__row', { 'view__row--selected': selectedPolicy?.id === row.id }]"
              tabindex="0"
              :aria-label="`Inspect policy ${policyLabel(row)}`"
              :aria-current="selectedPolicy?.id === row.id ? 'true' : undefined"
              @click="selectPolicy(row)"
              @keydown.enter.self.prevent="selectPolicy(row)"
              @keydown.space.self.prevent="selectPolicy(row)"
            >
              <td class="view__cell--name" data-label="Name" role="cell">
                <span class="view__name">{{ policyLabel(row) }}</span>
              </td>
              <td class="view__cell--mode" data-label="Mode" role="cell">
                <span
                  :class="['badge', row.commandKind === 'shell' ? 'badge--warning' : 'badge--ok']"
                >
                  {{ row.commandKind }}
                </span>
              </td>
              <td data-label="Secrets" role="cell">{{ secretCount(row) }}</td>
              <td data-label="TTL" role="cell">{{ ttlLabel(row.ttlSeconds) }}</td>
              <td data-label="Updated" role="cell">
                <time :datetime="row.updatedAt" :title="row.updatedAt">{{
                  formatTime(row.updatedAt)
                }}</time>
              </td>
              <td class="view__cell--gates" data-label="Gates" role="cell">
                <span v-if="gateLabels(row).length > 0" class="view__badges">
                  <span v-for="gate in gateLabels(row)" :key="gate" class="badge badge--gate">
                    {{ gate }}
                  </span>
                </span>
                <span v-else class="view__muted">none</span>
                <button
                  v-if="selectedPolicy?.id === row.id"
                  type="button"
                  class="companion-button view__detail-button"
                  aria-label="Show selected command details"
                  aria-controls="policy-detail"
                  @click.stop="focusPolicyDetail"
                >
                  Details
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <aside
        v-if="selectedPolicy"
        id="policy-detail"
        ref="policyDetail"
        class="policy-detail"
        aria-labelledby="policy-detail-heading"
        tabindex="-1"
      >
        <header class="policy-detail__head">
          <div class="policy-detail__title">
            <span class="policy-detail__eyebrow">Selected command</span>
            <h3 id="policy-detail-heading">{{ policyLabel(selectedPolicy) }}</h3>
          </div>
          <button
            type="button"
            class="companion-button companion-button--primary icon-label"
            :disabled="!actionsEnabled || running || configurationMissing"
            @click="emit('run', selectedPolicy)"
          >
            <AppIcon name="terminal" />
            {{ running ? 'Opening terminal…' : 'Run in terminal' }}
          </button>
          <div v-if="invocation" class="policy-detail__invocation">
            <code class="policy-detail__command">{{ invocation }}</code>
            <button
              type="button"
              class="companion-button icon-label"
              aria-label="Copy command"
              @click="copyInvocation"
            >
              <AppIcon :name="copyStatus === 'Copied' ? 'check' : 'copy'" />
              {{ copyStatus === 'Copied' ? 'Copied' : 'Copy' }}
            </button>
          </div>
          <p
            class="view__empty"
            :class="{ 'visually-hidden': !copyStatus || copyStatus === 'Copied' }"
            role="status"
          >
            {{ copyStatus }}
          </p>
        </header>
        <p v-if="configurationMissing" class="policy-detail__blocked" role="status">
          <AppIcon name="alert" :size="14" />
          Resolve this command’s configuration checks before running it.
        </p>

        <section class="policy-detail__section" aria-labelledby="policy-command-heading">
          <h4 id="policy-command-heading">Command</h4>
          <p v-if="privacyMode" class="policy-detail__command policy-detail__command--muted">
            Hidden in privacy mode
          </p>
          <code v-else class="policy-detail__command">{{ selectedPolicy.commandPreview }}</code>
        </section>

        <dl class="policy-detail__grid">
          <div>
            <dt>Command kind</dt>
            <dd>{{ selectedPolicy.commandKind }}</dd>
          </div>
          <div>
            <dt>Env mode</dt>
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
            <span v-if="selectedPolicy.confirm" class="badge badge--gate">confirm</span>
            <span v-if="selectedPolicy.requireUserVerification" class="badge badge--gate">
              verify user
            </span>
            <span v-if="selectedPolicy.requireAgent" class="badge badge--gate">agent required</span>
            <span v-if="selectedPolicy.allowRemoteDocker" class="badge badge--warning">
              remote docker
            </span>
            <span v-if="gateLabels(selectedPolicy).length === 0" class="view__muted"> none </span>
          </div>
        </section>

        <VariableReadinessPanel
          class="policy-detail__readiness"
          :project-id="projectId"
          :profile-id="profileId"
          :policy-name="selectedPolicy.name"
          :privacy-mode="privacyMode"
          :refresh-key="`${selectedPolicy.updatedAt}:${refreshCount}`"
          :hide-refresh="true"
          @blocked="configurationMissing = $event"
        />
      </aside>
    </div>

    <p v-if="!privacyMode && detectingCommands" class="view__loading" role="status">
      Looking for commands in this folder…
    </p>
    <p v-else-if="!privacyMode && detectionError" class="view__empty" role="status">
      {{ detectionError }}
    </p>
    <details
      v-else-if="!privacyMode && unconfiguredCommands.length"
      :key="String(isEmpty)"
      class="detected-commands"
      :open="isEmpty"
    >
      <summary>
        Detected commands <span class="badge">{{ unconfiguredCommands.length }}</span>
      </summary>
      <ul class="detected-commands__list">
        <li
          v-for="row in unconfiguredCommands"
          :key="`${row.source_file}:${row.name}:${row.command_preview}`"
          class="detected-commands__row"
        >
          <div class="detected-commands__body">
            <strong>{{ row.name }}</strong>
            <span class="badge">{{ row.source_file }}</span>
            <code>{{ row.command_preview }}</code>
          </div>
          <button
            type="button"
            class="companion-button"
            :disabled="!actionsEnabled"
            :aria-label="`Add command ${row.name}`"
            @click="emit('addDetected', row)"
          >
            Add command
          </button>
        </li>
      </ul>
    </details>
  </section>
</template>

<style scoped>
.view {
  container: commands / inline-size;
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}
.detected-commands {
  margin-top: 1rem;
  padding: 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-app);
  font-size: 0.875rem;
}
.detected-commands summary {
  width: fit-content;
  font-weight: 600;
  cursor: pointer;
}
.detected-commands__list {
  display: grid;
  gap: 0.5rem;
  margin: 0.75rem 0 0;
  padding: 0;
  list-style: none;
}
.detected-commands__row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid var(--border-subtle);
}
.detected-commands__body {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.25rem 0.5rem;
  min-width: 0;
  overflow-wrap: anywhere;
}
.detected-commands__body code {
  flex-basis: 100%;
  color: var(--text-secondary);
}

.view__header {
  margin-bottom: 0.875rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
}

.view__header .companion-toolbar__search {
  flex-basis: 10rem;
}

.view__button-group {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.view__empty code,
.policy-detail__command {
  background: var(--bg-app);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-size: 0.8125rem;
}

.view__empty code {
  padding: 0.125rem 0.25rem;
}

.policy-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(19rem, 25rem);
  gap: 1rem;
  align-items: start;
}

.policy-table {
  container: policies / inline-size;
}

.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8125rem;
}

.view__table th,
.view__table td {
  text-align: left;
  padding: 0.55rem 0.65rem;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: middle;
}

.view__table th {
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-muted);
  white-space: nowrap;
}

.view__row {
  cursor: pointer;
}

.view__row:hover {
  background: var(--bg-subtle);
}

.view__row--selected,
.view__row--selected:hover {
  background: var(--accent-soft);
  box-shadow: inset 3px 0 0 var(--accent);
}

.view__row:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}

.view__name {
  font-weight: 650;
  white-space: nowrap;
}

.view__muted {
  color: var(--text-secondary);
}

.view__detail-button {
  display: none;
}

.view__badges {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.badge {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.02em;
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
  white-space: nowrap;
}

.badge--ok {
  background: var(--success-soft);
  border-color: transparent;
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
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
}

.policy-detail:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.policy-detail__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border-subtle);
}

.policy-detail__title {
  min-width: 0;
}

.policy-detail__invocation {
  display: flex;
  align-items: stretch;
  gap: 0.375rem;
  flex-basis: 100%;
  min-width: 0;
}

.policy-detail__invocation code {
  flex: 1;
  min-width: 0;
}

.policy-detail__eyebrow {
  display: block;
  color: var(--text-muted);
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.policy-detail h3,
.policy-detail h4 {
  margin: 0;
}

.policy-detail h3 {
  margin-top: 0.15rem;
  font-size: 1.0625rem;
  overflow-wrap: anywhere;
}

.policy-detail h4 {
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.policy-detail__blocked {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin: 0;
  padding: 0.45rem 0.65rem;
  border-radius: var(--radius-sm);
  background: var(--warn-soft);
  color: var(--warn);
  font-size: 0.8125rem;
}

.policy-detail__grid,
.policy-detail__secrets {
  margin: 0;
  display: grid;
  gap: 0.625rem 0.75rem;
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
  color: var(--text-muted);
  font-size: 0.75rem;
}

.policy-detail dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
  font-weight: 600;
}

.policy-detail__section {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.policy-detail__command {
  display: block;
  padding: 0.55rem 0.65rem;
  border: 1px solid var(--border-subtle);
  overflow-wrap: anywhere;
}

.policy-detail__command--muted {
  margin: 0;
  color: var(--text-secondary);
  font-family: var(--font-sans);
}

.policy-detail__readiness {
  padding: 0.875rem 0 0;
  border: 0;
  border-top: 1px solid var(--border-subtle);
  border-radius: 0;
  background: transparent;
}

@media (max-width: 1100px) {
  .policy-layout {
    grid-template-columns: 1fr;
  }
}

@container commands (max-width: 40rem) {
  .companion-toolbar__controls {
    width: 100%;
    justify-content: flex-start;
  }

  .view__header .companion-toolbar__search {
    flex-basis: 100%;
    max-width: none;
  }
}

/* Stack table rows as cards when the list column is narrow. */
@container policies (max-width: 34rem) {
  .view__table,
  .view__table tbody {
    display: block;
  }

  .view__table thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }

  .view__table tbody tr {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.375rem 0.75rem;
    margin-bottom: 0.5rem;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  .view__table td {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2rem;
    min-width: 0;
    padding: 0;
    border: 0;
  }

  .view__table td::before {
    content: attr(data-label);
    color: var(--text-muted);
    font-size: 0.6875rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  .view__table td.view__cell--name {
    grid-column: 1 / 3;
  }

  .view__table td.view__cell--mode {
    align-items: flex-end;
  }

  .view__table td.view__cell--gates {
    grid-column: 1 / -1;
    flex-direction: row;
    align-items: center;
    gap: 0.4rem;
  }

  .view__detail-button {
    display: inline-block;
    flex: none;
    margin-inline-start: auto;
  }

  .view__table td.view__cell--name::before,
  .view__table td.view__cell--mode::before {
    content: none;
  }

  .view__name {
    white-space: normal;
    overflow-wrap: anywhere;
  }
}
</style>
