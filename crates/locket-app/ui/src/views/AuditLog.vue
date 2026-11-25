<script setup lang="ts">
import AppIcon from '../components/AppIcon.vue';
import { formatTime } from '../utils/formatTime';
import { computed, ref, watch } from 'vue';

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
const publicSnapshots = new WeakSet<AuditLogRow[]>();

// The agent returns redacted labels in the same fields as plain names.
// Remember snapshots seen in public mode so they stay hidden during the transition.
watch(
  () => [props.rows, props.privacyMode] as const,
  ([rows, privacyMode]) => {
    if (!privacyMode) publicSnapshots.add(rows);
  },
  { immediate: true },
);

const visibleRows = computed(() =>
  props.privacyMode && (props.loading || publicSnapshots.has(props.rows)) ? [] : props.rows,
);

const filteredRows = computed<AuditLogRow[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return visibleRows.value;
  }
  return visibleRows.value.filter((row) => searchText(row).includes(query));
});

const isEmpty = computed<boolean>(() => visibleRows.value.length === 0);
const isFilteredEmpty = computed<boolean>(
  () => visibleRows.value.length > 0 && filteredRows.value.length === 0,
);

const firstBrokenSequence = computed<number | null>(() => {
  for (const row of visibleRows.value) {
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

function visibleLabel(
  value: string | undefined,
  alias: string | undefined,
  wireAlias: RegExp,
): string | null {
  // Wire aliases are distinct from profile IDs (lk_prof_*) and uppercase secret names.
  const label = props.privacyMode
    ? (alias ?? (value && wireAlias.test(value) ? value : undefined))
    : value;
  return label?.trim() ? label : null;
}

function profileValue(row: AuditLogRow): string | null {
  return visibleLabel(row.profile, row.profileAlias, /^profile-[0-9a-f]{8}$/);
}

function secretValue(row: AuditLogRow): string | null {
  return visibleLabel(row.secretName, row.secretAlias, /^secret-[0-9a-f]{8}$/);
}

function profileLabel(row: AuditLogRow): string {
  return profileValue(row) ?? '—';
}

function secretLabel(row: AuditLogRow): string {
  return secretValue(row) ?? '—';
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
    <header class="companion-toolbar view__header">
      <h2 id="audit-log-heading">Audit log</h2>
      <div class="companion-toolbar__controls">
        <label class="companion-toolbar__search">
          <span class="visually-hidden">Search audit</span>
          <AppIcon name="search" :size="14" />
          <input
            v-model="searchQuery"
            class="companion-input"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search audit log…"
          />
        </label>
        <button
          type="button"
          class="companion-button icon-label"
          aria-label="Verify audit chain"
          @click="onVerify"
        >
          <AppIcon name="check" />
          Verify chain
        </button>
      </div>
    </header>

    <div
      :class="[
        'view__chain',
        chainOk === true
          ? 'view__chain--ok'
          : chainOk === false
            ? 'view__chain--broken'
            : 'view__chain--unknown',
      ]"
    >
      <AppIcon :name="chainOk === true ? 'check' : 'alert'" />
      <p class="view__chain-text" role="status" aria-live="polite">{{ chainBannerText }}</p>
      <span v-if="lastCheckedAt" class="view__chain-meta">
        Project audit last checked
        <time :datetime="lastCheckedAt" :title="lastCheckedAt">{{
          formatTime(lastCheckedAt)
        }}</time>
      </span>
    </div>

    <p v-if="loading" class="view__empty" role="status">Loading audit…</p>
    <p v-if="errorMessage" class="view__error" role="alert">
      {{ errorMessage }} Retry verification.
    </p>
    <p v-if="isEmpty && !loading" class="view__empty">No audit rows.</p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching audit rows.</p>

    <div
      v-else
      class="companion-table-scroll view__scroll"
      role="region"
      aria-labelledby="audit-log-heading"
      tabindex="0"
    >
      <table class="view__table" role="table" aria-describedby="audit-log-heading">
        <thead role="rowgroup">
          <tr role="row">
            <th scope="col" role="columnheader">Seq</th>
            <th scope="col" role="columnheader">Timestamp</th>
            <th scope="col" role="columnheader">Action</th>
            <th scope="col" role="columnheader">Status</th>
            <th scope="col" role="columnheader">Profile</th>
            <th scope="col" role="columnheader">Secret</th>
            <th scope="col" role="columnheader">Denial reason</th>
          </tr>
        </thead>
        <tbody role="rowgroup">
          <tr v-for="row in filteredRows" :key="row.sequence" role="row">
            <td class="view__cell--seq" data-label="Seq" role="cell">
              <span class="view__seq">#{{ row.sequence }}</span>
            </td>
            <td class="view__cell--time" data-label="Timestamp" role="cell">
              <time class="view__timestamp" :datetime="row.timestamp" :title="row.timestamp">{{
                formatTime(row.timestamp, 'datetime')
              }}</time>
            </td>
            <td class="view__cell--action" data-label="Action" role="cell">
              <span class="view__name">{{ row.action }}</span>
            </td>
            <td class="view__cell--status" data-label="Status" role="cell">
              <span :class="['badge', `badge--status-${row.status.toLowerCase()}`]">
                {{ statusLabel(row.status) }}
              </span>
            </td>
            <td data-label="Profile" role="cell">
              <span v-if="profileValue(row)">{{ profileValue(row) }}</span>
              <span v-else class="view__muted">—</span>
            </td>
            <td data-label="Secret" role="cell">
              <span v-if="secretValue(row)" class="view__secret">{{ secretValue(row) }}</span>
              <span v-else class="view__muted">—</span>
            </td>
            <td data-label="Denial reason" role="cell">
              <span v-if="row.status === 'DENIED' && row.denialReason" class="badge badge--warning">
                {{ row.denialReason }}
              </span>
              <span v-else class="view__muted">—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.view {
  container: audit / inline-size;
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

.view__chain {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.25rem 0.5rem;
  margin: 0 0 0.75rem;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  font-size: 0.8125rem;
}

.view__chain-text {
  flex: 1 1 auto;
  margin: 0;
  font-weight: 600;
}

.view__chain-meta {
  color: var(--text-secondary);
  white-space: nowrap;
}

.view__chain--ok {
  background: var(--success-soft);
  color: var(--success);
}

.view__chain--broken {
  background: var(--danger-soft);
  border-color: var(--danger);
  color: var(--danger);
}

.view__chain--unknown {
  background: var(--warn-soft);
  color: var(--warn);
}

.view__empty {
  margin: 0 0 0.5rem;
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.view__error {
  margin: 0 0 0.5rem;
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
  padding: 0.5rem 0.65rem;
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

.view__seq {
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 0.75rem;
}

.view__timestamp {
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.view__name {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  font-weight: 650;
  white-space: nowrap;
}

.view__secret {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}

.view__muted {
  color: var(--text-secondary);
}

.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 999px;
  font-size: 0.6875rem;
  font-weight: 650;
  letter-spacing: 0.03em;
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
  white-space: nowrap;
}

.badge--status-ok {
  background: var(--success-soft);
  border-color: transparent;
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

@container audit (max-width: 46rem) {
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
    gap: 0.5rem 0.75rem;
    margin-bottom: 0.5rem;
    padding: 0.7rem 0.75rem;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    background: var(--bg-app);
  }

  .view__table tbody tr:hover {
    background: var(--bg-app);
  }

  .view__table td {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2rem;
    min-width: 0;
    padding: 0;
    border: 0;
    overflow-wrap: anywhere;
  }

  .view__table td::before {
    content: attr(data-label);
    color: var(--text-muted);
    font-size: 0.6875rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  /* Card header: action on the left, status on the right. */
  .view__table td.view__cell--action,
  .view__table td.view__cell--status {
    grid-row: 1;
    flex-direction: row;
    align-items: center;
  }

  .view__table td.view__cell--action {
    grid-column: 1 / 3;
  }

  .view__table td.view__cell--status {
    grid-column: 3;
    justify-content: flex-end;
  }

  .view__table td.view__cell--action::before,
  .view__table td.view__cell--status::before {
    content: none;
  }

  .view__table td.view__cell--time {
    grid-column: span 2;
  }

  .badge--warning {
    white-space: normal;
  }
}
</style>
