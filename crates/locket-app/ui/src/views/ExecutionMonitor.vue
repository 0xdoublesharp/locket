<script setup lang="ts">
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

function refresh(): void {
  emit('refresh');
}
</script>

<template>
  <section class="view" aria-labelledby="execution-monitor-heading">
    <header class="view__header">
      <h2 id="execution-monitor-heading">Runtime sessions</h2>
      <div class="view__actions">
        <span v-if="lastRefreshedAt" class="view__muted">
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button type="button" class="view__button" :disabled="loading" @click="refresh">
          Refresh
        </button>
      </div>
    </header>

    <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>
    <p v-else-if="loading && isEmpty" class="view__empty">Loading runtime sessions…</p>
    <p v-else-if="isEmpty" class="view__empty">No runtime sessions yet.</p>

    <div
      v-else
      class="companion-table-scroll"
      role="region"
      aria-labelledby="execution-monitor-heading"
      tabindex="0"
    >
      <table class="view__table" aria-describedby="execution-monitor-heading">
        <thead>
          <tr>
            <th scope="col">State</th>
            <th scope="col">Session</th>
            <th scope="col">Profile</th>
            <th scope="col">Policy</th>
            <th scope="col">Process</th>
            <th scope="col">Started</th>
            <th scope="col">Ended</th>
            <th scope="col">Exit</th>
            <th scope="col">Secrets</th>
            <th scope="col">Audit</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.sessionId">
            <td>
              <span class="view__state">
                <span :class="['view__dot', `view__dot--${row.state}`]" aria-hidden="true"></span>
                <span class="view__state-label">{{ stateLabel(row.state) }}</span>
              </span>
            </td>
            <td>
              <code class="view__session-id">{{ row.sessionId }}</code>
            </td>
            <td>{{ profileLabel(row) }}</td>
            <td>{{ policyLabel(row) }}</td>
            <td>
              <span class="view__muted">
                pid {{ row.pid }} ·
                <time :datetime="row.processStartTime" :title="row.processStartTime">{{
                  formatTime(row.processStartTime, 'timestamp')
                }}</time>
              </span>
            </td>
            <td>
              <time :datetime="row.startedAt" :title="row.startedAt">{{
                formatTime(row.startedAt, 'timestamp')
              }}</time>
            </td>
            <td>
              <time v-if="row.endedAt" :datetime="row.endedAt" :title="row.endedAt">{{
                formatTime(row.endedAt, 'timestamp')
              }}</time>
              <span v-else class="view__muted">—</span>
            </td>
            <td>
              <span v-if="typeof row.exitStatus === 'number'" class="view__muted">
                {{ row.exitStatus }}
              </span>
              <span v-else class="view__muted">—</span>
            </td>
            <td>
              <span class="badge badge--count">{{ row.secretNameCount }} secrets</span>
            </td>
            <td>
              <span class="view__muted">{{ auditLabel(row) }}</span>
            </td>
          </tr>
        </tbody>
      </table>
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
  gap: 1rem;
  margin-bottom: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
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

.view__actions {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
}

.view__button {
  border: 1px solid var(--accent);
  background: var(--accent-soft);
  color: var(--accent);
  border-radius: 0.375rem;
  padding: 0.375rem 0.625rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__button:disabled {
  cursor: default;
  opacity: 0.55;
}

.view__button:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
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
  font-weight: 600;
  color: var(--text-secondary);
  font-size: 0.75rem;
  letter-spacing: 0.04em;
}

.view__muted {
  color: var(--text-secondary);
}

.view__state {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}

.view__dot {
  display: inline-block;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: var(--bg-subtle);
}

.view__dot--running {
  background: var(--success);
}

.view__dot--completed {
  background: var(--bg-subtle);
}

.view__dot--failed {
  background: var(--danger);
}

.view__dot--stale {
  background: var(--accent);
}

.view__state-label {
  text-transform: capitalize;
}

.view__session-id {
  font-size: 0.8125rem;
  color: var(--text-primary);
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
}

.badge--count {
  background: var(--info-soft);
  border-color: var(--border-strong);
  color: var(--info);
}
</style>
