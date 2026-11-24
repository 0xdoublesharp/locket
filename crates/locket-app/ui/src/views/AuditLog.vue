<script setup lang="ts">
import { formatTime } from '../utils/formatTime';
import { computed, ref } from 'vue';

import { auditHealth } from '../dashboard/health';
import type { AuditLogRow } from '../types/views';

interface Props {
  rows: AuditLogRow[];
  privacyMode: boolean;
  chainOk: boolean | null;
  loading?: boolean;
  errorMessage?: string | null;
  lastCheckedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'verify'): void;
}>();

const searchQuery = ref<string>('');

const filteredRows = computed<AuditLogRow[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return props.rows;
  }
  return props.rows.filter((row) => searchText(row).includes(query));
});

const isEmpty = computed<boolean>(() => props.rows.length === 0);
const isFilteredEmpty = computed<boolean>(
  () => props.rows.length > 0 && filteredRows.value.length === 0,
);

const firstBrokenSequence = computed<number | null>(() => {
  for (const row of props.rows) {
    if (row.hmacOk === false) {
      return row.sequence;
    }
  }
  return null;
});

const chainBannerText = computed<string>(() => {
  if (props.chainOk === null)
    return 'Audit chain has not been verified. Unlock this project and retry verification.';
  if (props.chainOk === true) {
    return 'Audit chain verified.';
  }
  if (firstBrokenSequence.value !== null) {
    return `Audit chain broken at row ${firstBrokenSequence.value}.`;
  }
  return 'Audit chain broken.';
});

function profileLabel(row: AuditLogRow): string {
  if (props.privacyMode) {
    return row.profileAlias ?? row.profile ?? '—';
  }
  return row.profile ?? '—';
}

function secretLabel(row: AuditLogRow): string {
  if (props.privacyMode) {
    return row.secretAlias ?? row.secretName ?? '—';
  }
  return row.secretName ?? '—';
}

function statusLabel(status: AuditLogRow['status']): string {
  switch (status) {
    case 'OK':
      return 'OK';
    case 'DENIED':
      return 'DENIED';
    case 'FAILED':
      return 'FAILED';
    default:
      return status;
  }
}

function searchText(row: AuditLogRow): string {
  return [
    String(row.sequence),
    row.timestamp,
    row.action,
    row.status,
    profileLabel(row),
    secretLabel(row),
    row.denialReason ?? '',
    row.hmacOk === true
      ? 'hmac ok verified'
      : row.hmacOk === false
        ? 'hmac broken failed'
        : 'hmac not verified',
  ]
    .join(' ')
    .toLowerCase();
}

function onVerify(): void {
  emit('verify');
}
</script>

<template>
  <section class="view" aria-labelledby="audit-log-heading">
    <header class="view__header">
      <h2 id="audit-log-heading">Audit log</h2>
      <div class="view__actions">
        <label class="view__search">
          <span class="view__search-label">Search audit</span>
          <input
            v-model="searchQuery"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search metadata"
          />
        </label>
        <button
          type="button"
          class="view__action"
          aria-label="Verify audit chain"
          @click="onVerify"
        >
          Verify chain
        </button>
      </div>
    </header>

    <p
      :class="['view__chain', chainOk ? 'view__chain--ok' : 'view__chain--broken']"
      role="status"
      aria-live="polite"
    >
      {{ chainBannerText }}
    </p>

    <p v-if="loading" role="status">Loading audit…</p>
    <p v-if="errorMessage" role="alert">{{ errorMessage }} Retry verification.</p>
    <p v-if="lastCheckedAt">
      Project audit last checked
      <time :datetime="lastCheckedAt" :title="lastCheckedAt">{{ formatTime(lastCheckedAt) }}</time>
    </p>
    <p class="view__muted">{{ auditHealth(chainOk).label }}</p>
    <p v-if="isEmpty && !loading" class="view__empty">No audit rows.</p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching audit rows.</p>

    <table v-else class="view__table" aria-describedby="audit-log-heading">
      <thead>
        <tr>
          <th scope="col">Seq</th>
          <th scope="col">Timestamp</th>
          <th scope="col">Action</th>
          <th scope="col">Status</th>
          <th scope="col">Profile</th>
          <th scope="col">Secret</th>
          <th scope="col">Denial reason</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in filteredRows" :key="row.sequence">
          <td>
            <span class="view__muted">{{ row.sequence }}</span>
          </td>
          <td>
            <time :datetime="row.timestamp" :title="row.timestamp">{{
              formatTime(row.timestamp, 'timestamp')
            }}</time>
          </td>
          <td>
            <span class="view__name">{{ row.action }}</span>
          </td>
          <td>
            <span :class="['badge', `badge--status-${row.status.toLowerCase()}`]">
              {{ statusLabel(row.status) }}
            </span>
          </td>
          <td>{{ profileLabel(row) }}</td>
          <td>{{ secretLabel(row) }}</td>
          <td>
            <span v-if="row.status === 'DENIED' && row.denialReason" class="badge badge--warning">
              {{ row.denialReason }}
            </span>
            <span v-else class="view__muted">—</span>
          </td>
        </tr>
      </tbody>
    </table>
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

.view__action {
  background: var(--bg-subtle);
  color: var(--text-primary);
  border: 1px solid var(--border-subtle);
  border-radius: 0.375rem;
  padding: 0.25rem 0.75rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover {
  background: var(--bg-subtle);
}

.view__action:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.view__chain {
  margin: 0 0 0.75rem;
  padding: 0.5rem 0.75rem;
  border-radius: 0.5rem;
  font-size: 0.8125rem;
  border: 1px solid var(--border-subtle);
}

.view__chain--ok {
  background: var(--success-soft);
  border-color: var(--border-strong);
  color: var(--success);
}

.view__chain--broken {
  background: var(--danger-soft);
  border-color: var(--danger);
  color: var(--danger);
}

.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
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

.view__name {
  font-weight: 600;
}

.view__muted {
  color: var(--text-secondary);
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

.badge--status-ok {
  background: var(--success-soft);
  border-color: var(--border-strong);
  color: var(--success);
}

.badge--status-denied {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}

.badge--status-failed {
  background: var(--danger-soft);
  border-color: var(--danger);
  color: var(--danger);
}

.badge--warning {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}
</style>
