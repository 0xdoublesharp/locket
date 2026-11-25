<script setup lang="ts">
import AppIcon from '../components/AppIcon.vue';
import { formatTime } from '../utils/formatTime';
import { computed } from 'vue';

import type { RuntimeSessionRow } from '../types/views';

interface Props {
  rows: RuntimeSessionRow[];
  privacyMode: boolean;
  loading: boolean;
  errorMessage?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  refresh: [];
}>();

const isEmpty = computed<boolean>(() => props.rows.length === 0);

function profileLabel(row: RuntimeSessionRow): string {
  if (props.privacyMode) {
    return row.profileAlias ?? row.profile;
  }
  return row.profile;
}

function policyLabel(row: RuntimeSessionRow): string {
  if (props.privacyMode) {
    return row.policyAlias ?? row.policy;
  }
  return row.policy;
}

function stateLabel(state: RuntimeSessionRow['state']): string {
  switch (state) {
    case 'running':
      return 'running';
    case 'completed':
      return 'completed';
    case 'failed':
      return 'failed';
    case 'stale':
      return 'stale';
    default:
      return state;
  }
}

function auditLabel(row: RuntimeSessionRow): string {
  if (typeof row.spawnAuditSequence !== 'number') {
    return '—';
  }
  if (typeof row.completionAuditSequence === 'number') {
    return `${row.spawnAuditSequence} → ${row.completionAuditSequence}`;
  }
  return `${row.spawnAuditSequence} → —`;
}

function stateTone(state: RuntimeSessionRow['state']): string {
  switch (state) {
    case 'running':
      return 'ok';
    case 'failed':
      return 'danger';
    case 'stale':
      return 'warn';
    default:
      return 'neutral';
  }
}

function secretsLabel(count: number): string {
  return `${count} ${count === 1 ? 'secret' : 'secrets'}`;
}

function refresh(): void {
  emit('refresh');
}
</script>

<template>
  <section class="view" aria-labelledby="execution-monitor-heading">
    <header class="companion-toolbar view__header">
      <h2 id="execution-monitor-heading">Runtime sessions</h2>
      <div class="companion-toolbar__controls">
        <span v-if="lastRefreshedAt" class="companion-toolbar__meta">
          Updated
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button
          type="button"
          class="companion-button icon-label"
          :disabled="loading"
          @click="refresh"
        >
          <AppIcon name="refresh" />
          Refresh
        </button>
      </div>
    </header>

    <p v-if="errorMessage" class="view__error" role="alert">{{ errorMessage }}</p>
    <p v-else-if="loading && isEmpty" class="view__empty" role="status">
      Loading runtime sessions…
    </p>
    <p v-else-if="isEmpty" class="view__empty">No runtime sessions yet.</p>

    <div
      v-else
      class="companion-table-scroll view__scroll"
      role="region"
      aria-labelledby="execution-monitor-heading"
      tabindex="0"
    >
      <table class="view__table" role="table" aria-describedby="execution-monitor-heading">
        <thead role="rowgroup">
          <tr role="row">
            <th scope="col" role="columnheader">State</th>
            <th scope="col" role="columnheader">Command &amp; session</th>
            <th scope="col" role="columnheader">Process</th>
            <th scope="col" role="columnheader">Started</th>
            <th scope="col" role="columnheader">Ended</th>
            <th scope="col" role="columnheader">Exit</th>
            <th scope="col" role="columnheader">Secrets</th>
            <th scope="col" role="columnheader">Audit</th>
          </tr>
        </thead>
        <tbody role="rowgroup">
          <tr v-for="row in rows" :key="row.sessionId" role="row">
            <td class="view__cell view__cell--state" data-label="State" role="cell">
              <span :class="['companion-pill', `companion-pill--${stateTone(row.state)}`]">
                <span :class="['view__dot', `view__dot--${row.state}`]" aria-hidden="true"></span>
                <span class="view__state-label">{{ stateLabel(row.state) }}</span>
              </span>
            </td>
            <td class="view__cell view__cell--command" data-label="Command" role="cell">
              <span class="view__command">
                <strong class="view__policy">{{ policyLabel(row) }}</strong>
                <span class="view__session-meta">
                  <code class="view__session-id">{{ row.sessionId }}</code>
                  <span class="view__chip">{{ profileLabel(row) }}</span>
                </span>
              </span>
            </td>
            <td class="view__cell view__cell--process" data-label="Process" role="cell">
              <details
                v-if="row.processStartTime !== row.startedAt"
                class="view__process view__muted"
              >
                <summary>pid {{ row.pid }}</summary>
                <p>
                  Process started
                  <time :datetime="row.processStartTime">{{ row.processStartTime }}</time>
                </p>
              </details>
              <span v-else class="view__muted view__pid">pid {{ row.pid }}</span>
            </td>
            <td class="view__cell view__cell--time" data-label="Started" role="cell">
              <time class="view__timestamp" :datetime="row.startedAt" :title="row.startedAt">{{
                formatTime(row.startedAt, 'datetime')
              }}</time>
            </td>
            <td class="view__cell view__cell--time" data-label="Ended" role="cell">
              <time
                v-if="row.endedAt"
                class="view__timestamp"
                :datetime="row.endedAt"
                :title="row.endedAt"
                >{{ formatTime(row.endedAt, 'datetime') }}</time
              >
              <span v-else class="view__muted">—</span>
            </td>
            <td class="view__cell view__cell--exit" data-label="Exit" role="cell">
              <span
                v-if="typeof row.exitStatus === 'number'"
                :class="[
                  'companion-pill',
                  row.exitStatus === 0 ? 'companion-pill--ok' : 'companion-pill--danger',
                  'view__exit',
                ]"
              >
                {{ row.exitStatus }}
              </span>
              <span v-else class="view__muted">—</span>
            </td>
            <td class="view__cell" data-label="Secrets" role="cell">
              <span class="companion-pill companion-pill--info">{{
                secretsLabel(row.secretNameCount)
              }}</span>
            </td>
            <td class="view__cell" data-label="Audit" role="cell">
              <code class="view__audit">{{ auditLabel(row) }}</code>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.view {
  container: runs / inline-size;
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.view__header {
  margin-bottom: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
}

.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.view__error {
  margin: 0;
  font-size: 0.875rem;
  color: var(--danger);
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
  font-weight: 600;
  color: var(--text-muted);
  font-size: 0.6875rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  white-space: nowrap;
}

.view__table tbody tr:last-child td {
  border-bottom: 0;
}

.view__table tbody tr:hover {
  background: var(--bg-subtle);
}

.view__muted {
  color: var(--text-secondary);
}

.view__pid,
.view__process summary,
.view__timestamp {
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.view__process summary {
  cursor: pointer;
}

.view__process p {
  max-width: 16ch;
  margin: 0.25rem 0 0;
  font-size: 0.75rem;
}

.view__process time {
  display: block;
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}

.view__command {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 0;
}

.view__policy {
  font-weight: 650;
  white-space: nowrap;
}

.view__session-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.25rem 0.35rem;
  min-width: 0;
}

.view__session-id {
  min-width: 0;
  font-size: 0.75rem;
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}

.view__chip {
  flex: none;
  padding: 0 0.4rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 0.6875rem;
  line-height: 1.35rem;
  white-space: nowrap;
}

.view__dot {
  display: inline-block;
  flex: none;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: var(--text-muted);
}

.view__dot--running {
  background: var(--success);
}

.view__dot--completed {
  background: var(--text-muted);
}

.view__dot--failed {
  background: var(--danger);
}

.view__dot--stale {
  background: var(--warn);
}

.view__state-label {
  text-transform: capitalize;
}

.view__exit {
  min-width: 1.5rem;
  justify-content: center;
  font-family: var(--font-mono);
}

.view__audit {
  color: var(--text-secondary);
  font-size: 0.75rem;
  white-space: nowrap;
}

/* Stacked cards whenever the panel is too narrow for eight single-line columns. */
@container runs (max-width: 60rem) {
  .view__scroll {
    overflow: visible;
  }

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
    gap: 0.6rem 0.75rem;
    margin-bottom: 0.6rem;
    padding: 0.75rem;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    background: var(--bg-app);
  }

  .view__table tbody tr:hover {
    background: var(--bg-app);
  }

  .view__table tbody tr:last-child {
    margin-bottom: 0;
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

  .view__table td.view__cell--command {
    grid-column: 1 / 3;
    grid-row: 1;
    padding-bottom: 0.25rem;
  }

  .view__table td.view__cell--state {
    grid-column: 3;
    grid-row: 1;
    align-items: flex-end;
    padding-bottom: 0.25rem;
  }

  .view__table td.view__cell--command::before,
  .view__table td.view__cell--state::before {
    content: none;
  }

  .view__policy {
    font-size: 0.875rem;
    white-space: normal;
    overflow-wrap: anywhere;
  }
}

@container runs (max-width: 33rem) {
  .view__table tbody tr {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .view__table td.view__cell--command {
    grid-column: 1;
  }

  .view__table td.view__cell--state {
    grid-column: 2;
  }

  .view__table td.view__cell--process,
  .view__table td.view__cell--exit {
    grid-row: 2;
  }
}

@container runs (max-width: 23rem) {
  .view__table td.view__cell--time {
    grid-column: 1 / -1;
  }

  .view__timestamp {
    white-space: normal;
  }
}
</style>
