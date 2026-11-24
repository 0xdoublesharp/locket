<script setup lang="ts">
import { computed, ref } from 'vue';

import AppIcon from '../components/AppIcon.vue';
import AgentUnavailableBanner from '../components/AgentUnavailableBanner.vue';
import type { AgentClientError } from '../agent/types';
import { formatTime } from '../utils/formatTime';
import CopyReference from '../components/CopyReference.vue';
import { secretReference } from '../secret/reference';
import type { SecretRowMeta, VersionHistoryRow } from '../types/views';
import { defaultSecretFilter, filterSecretRows, type SecretFilterState } from '../secret/filter';

interface Props {
  rows: SecretRowMeta[];
  versions: VersionHistoryRow[];
  profileName?: string | null;
  profileLabel: string;
  connected: boolean;
  canStart: boolean;
  starting: boolean;
  canAccessValues?: boolean;
  copyVerification?: boolean;
  loadError?: AgentClientError | null;
  privacyMode: boolean;
  loading: boolean;
  metadataLoaded: boolean;
  actionGuidance?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'select', row: SecretRowMeta): void;
  (e: 'refresh' | 'add' | 'retry' | 'start'): void;
  (e: 'copyValue' | 'revealValue', row: SecretRowMeta): void;
}>();

const searchQuery = ref<string>('');
const filterState = ref<SecretFilterState>(defaultSecretFilter());
const inspectedId = ref<string | null>(null);
const inspectedRow = computed(() => props.rows.find(({ id }) => id === inspectedId.value));
const inspectedReference = computed(() =>
  secretReference(props.profileName, inspectedRow.value?.name ?? '', props.privacyMode),
);
const inspectedGrace = computed(() =>
  props.versions.filter(
    (version) =>
      version.secretName === inspectedRow.value?.name &&
      version.source === inspectedRow.value?.source &&
      version.state === 'deprecated' &&
      version.graceUntil,
  ),
);

const metadataFilteredRows = computed<SecretRowMeta[]>(() =>
  filterSecretRows(props.rows, filterState.value),
);

const filteredRows = computed<SecretRowMeta[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return metadataFilteredRows.value;
  }
  return metadataFilteredRows.value.filter((row) => searchText(row).includes(query));
});

const filtersOpen = ref(false);
const filterCount = computed(
  () => Object.values(filterState.value).filter((value) => value !== 'all').length,
);
const sourceIcons = { team: 'cloud', 'user-local': 'user', 'machine-local': 'laptop' } as const;

function clearFilters(): void {
  filterState.value = defaultSecretFilter();
  searchQuery.value = '';
}

const isEmpty = computed<boolean>(
  () => props.metadataLoaded && !props.loading && props.rows.length === 0,
);
const isFilteredEmpty = computed<boolean>(
  () => !props.loading && props.rows.length > 0 && filteredRows.value.length === 0,
);

function displayName(row: SecretRowMeta): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

function sourceLabel(source: SecretRowMeta['source']): string {
  switch (source) {
    case 'team':
      return 'Shared';
    case 'user-local':
      return 'My override';
    case 'machine-local':
      return 'This machine';
    default:
      return source;
  }
}

function searchText(row: SecretRowMeta): string {
  return [
    displayName(row),
    row.source,
    row.required ? 'required' : '',
    row.optional ? 'optional' : '',
    row.ownerLabel ?? '',
    ...(row.tags ?? []),
    `v${row.currentVersion}`,
    row.hasDeprecatedGrace ? 'deprecated grace' : '',
    ...(row.deprecatedReferenceWarnings ?? []).map(warningSearchText),
  ]
    .join(' ')
    .toLowerCase();
}

function warningLabel(
  warning: NonNullable<SecretRowMeta['deprecatedReferenceWarnings']>[number],
): string {
  const status = warning.status === 'expired-grace' ? 'expired grace' : 'active grace';
  const surface = warning.surface === 'command-preview' ? 'command preview' : 'policy';
  const count = warning.referenceCount > 1 ? ` (${warning.referenceCount.toString()})` : '';
  return `v${warning.version.toString()} ${status} ${surface}${count}`;
}

function warningSearchText(
  warning: NonNullable<SecretRowMeta['deprecatedReferenceWarnings']>[number],
): string {
  return [
    `v${warning.version}`,
    warning.status,
    warning.surface,
    warning.referenceCount > 1 ? `${warning.referenceCount} references` : '1 reference',
  ].join(' ');
}

function graceDetails(row: SecretRowMeta): string {
  return (row.deprecatedReferenceWarnings ?? [])
    .map((warning) =>
      [
        warningLabel(warning),
        warning.graceUntil && `Until ${formatTime(warning.graceUntil)} (${warning.graceUntil})`,
      ]
        .filter(Boolean)
        .join(' · '),
    )
    .join('\n');
}
</script>

<template>
  <section class="variables" aria-labelledby="secret-metadata-list-heading">
    <header class="variables__header">
      <h2 id="secret-metadata-list-heading">
        <template v-if="metadataLoaded">
          {{ rows.length }} {{ rows.length === 1 ? 'variable' : 'variables' }} · {{ profileLabel }}
        </template>
        <template v-else>Variable metadata</template>
      </h2>
      <div class="variables__actions">
        <span v-if="lastRefreshedAt && !loadError" class="variables__updated">
          Updated
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button
          class="companion-button icon-label"
          type="button"
          aria-label="Refresh variables"
          title="Refresh variables"
          :disabled="loading || !connected"
          @click="emit('refresh')"
        >
          <AppIcon name="refresh" />
          <span class="variables__refresh-label">Refresh</span>
        </button>
        <button
          class="companion-button icon-label"
          :class="{ 'companion-button--primary': connected }"
          type="button"
          :disabled="!connected"
          @click="emit('add')"
        >
          <AppIcon name="plus" />
          Add variable
        </button>
      </div>
    </header>

    <AgentUnavailableBanner
      v-if="loadError"
      :error="loadError"
      heading="Can't load variables"
      :retrying="loading"
      :can-start="canStart"
      :starting="starting"
      @retry="emit('retry')"
      @start="emit('start')"
    />
    <p v-else-if="loading" class="variables__empty" role="status">Loading variable metadata…</p>
    <p v-else-if="actionGuidance" class="variables__empty" role="status">{{ actionGuidance }}</p>

    <template v-else>
      <div class="variables__toolbar">
        <label class="variables__search">
          <AppIcon name="search" />
          <input
            v-model="searchQuery"
            type="search"
            aria-label="Search variable metadata"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search variables"
          />
        </label>
        <button
          class="companion-button icon-label variables__filter-toggle"
          type="button"
          :aria-expanded="filtersOpen"
          aria-controls="variable-filters"
          @click="filtersOpen = !filtersOpen"
        >
          Filters<span v-if="filterCount"> ({{ filterCount }})</span>
          <AppIcon name="chevron-down" :size="13" />
        </button>
        <div id="variable-filters" class="variables__filters" :class="{ 'is-open': filtersOpen }">
          <select v-model="filterState.source" aria-label="Filter by source">
            <option value="all">All sources</option>
            <option value="team">Shared</option>
            <option value="user-local">My override</option>
            <option value="machine-local">This machine</option>
          </select>
          <select v-model="filterState.required" aria-label="Filter by requirement">
            <option value="all">Any requirement</option>
            <option value="required">Required</option>
            <option value="optional">Optional</option>
          </select>
          <select v-model="filterState.deprecation" aria-label="Filter by status">
            <option value="all">Any status</option>
            <option value="current">Current</option>
            <option value="deprecated">Deprecated grace</option>
          </select>
          <button
            v-if="filterCount || searchQuery"
            class="companion-button"
            type="button"
            @click="clearFilters"
          >
            Clear filters
          </button>
        </div>
      </div>

      <p v-if="isEmpty" class="variables__empty">
        No variables in this environment yet. You can add one here or run
        <code>locket set &lt;KEY&gt;</code> or <code>locket import &lt;file.env&gt;</code>.
      </p>
      <p v-else-if="isFilteredEmpty" class="variables__empty" role="status">
        No matching variables.
      </p>
      <ul v-else class="variables__list" aria-label="Variable metadata">
        <li
          v-for="row in filteredRows"
          :key="row.id"
          class="variables__row"
          :class="{ 'variables__row--inspected': row.id === inspectedId }"
        >
          <button
            type="button"
            class="variables__name"
            :title="displayName(row)"
            :aria-label="`Open metadata for ${displayName(row)}`"
            @click="emit('select', row)"
          >
            {{ displayName(row) }}
          </button>

          <div class="variables__badges">
            <span :class="['variable-badge', `variable-badge--${row.source}`]">
              <AppIcon :name="sourceIcons[row.source]" :size="14" />
              {{ sourceLabel(row.source) }}
            </span>
            <span
              v-if="row.required || row.optional"
              class="variable-badge"
              :class="row.required ? 'variable-badge--required' : 'variable-badge--optional'"
            >
              {{ row.required ? 'Required' : 'Optional' }}
            </span>
            <span class="variable-badge">v{{ row.currentVersion }}</span>
            <span
              v-if="row.hasDeprecatedGrace || row.deprecatedReferenceWarnings?.length"
              class="variable-badge variable-badge--grace"
              role="note"
              :title="graceDetails(row) || 'A deprecated version is still in its grace period.'"
            >
              <AppIcon name="alert" :size="13" />
              {{
                row.deprecatedReferenceWarnings?.[0]?.status === 'expired-grace'
                  ? 'Expired'
                  : 'Grace'
              }}<template v-if="row.deprecatedReferenceWarnings?.length">
                · v{{ row.deprecatedReferenceWarnings[0]?.version
                }}<template v-if="row.deprecatedReferenceWarnings.length > 1">
                  +{{ row.deprecatedReferenceWarnings.length - 1 }}</template
                >
              </template>
            </span>
          </div>

          <div class="variables__attribution">
            <span v-if="!privacyMode && (row.ownerLabel || row.tags?.length)">
              {{ [row.ownerLabel, ...(row.tags ?? [])].filter(Boolean).join(' · ') }}
            </span>
          </div>
          <div class="variables__dates">
            <span>
              Created
              <time :datetime="row.createdAt" :title="row.createdAt">{{
                formatTime(row.createdAt)
              }}</time>
            </span>
            <span v-if="row.rotatedAt">
              Rotated
              <time :datetime="row.rotatedAt" :title="row.rotatedAt">{{
                formatTime(row.rotatedAt)
              }}</time>
            </span>
          </div>

          <div class="variables__row-actions">
            <CopyReference :reference="secretReference(profileName, row.name, privacyMode)" />
            <button
              v-if="canAccessValues"
              class="companion-button icon-label"
              type="button"
              :aria-description="copyVerification ? 'System verification required' : undefined"
              :title="
                copyVerification ? 'Copy value with Touch ID or system verification' : 'Copy value'
              "
              @click="emit('copyValue', row)"
            >
              <AppIcon name="copy" />
              Copy value
              <AppIcon
                v-if="copyVerification"
                class="variables__verification"
                name="fingerprint"
                :size="13"
              />
            </button>
            <button
              v-if="canAccessValues"
              class="companion-button icon-label"
              type="button"
              @click="emit('revealValue', row)"
            >
              <AppIcon name="eye" />
              Reveal
            </button>
            <button
              class="companion-button icon-label variables__details-button"
              type="button"
              :aria-label="`Details for ${displayName(row)}`"
              :aria-expanded="row.id === inspectedId"
              :aria-controls="row.id === inspectedId ? 'variable-inspector' : undefined"
              @click="inspectedId = row.id === inspectedId ? null : row.id"
            >
              Details
              <AppIcon name="chevron-down" :size="12" />
            </button>
          </div>
          <section
            v-if="row.id === inspectedId"
            id="variable-inspector"
            class="variable-inspector"
            aria-labelledby="variable-inspector-title"
          >
            <header class="variable-inspector__header">
              <h3 id="variable-inspector-title">{{ displayName(row) }}</h3>
              <div class="variables__row-actions">
                <CopyReference :reference="inspectedReference" />
                <button
                  class="companion-button icon-label"
                  type="button"
                  @click="emit('select', row)"
                >
                  <AppIcon name="clock" />
                  Variable history
                </button>
              </div>
            </header>
            <dl class="variable-inspector__metadata">
              <div v-if="inspectedReference" class="variable-inspector__reference">
                <dt>Reference</dt>
                <dd>
                  <code>{{ inspectedReference }}</code>
                </dd>
              </div>
              <div>
                <dt>Created (UTC)</dt>
                <dd>
                  <time :datetime="row.createdAt">{{ row.createdAt }}</time>
                </dd>
              </div>
              <div>
                <dt>Rotated (UTC)</dt>
                <dd>
                  <time v-if="row.rotatedAt" :datetime="row.rotatedAt">{{ row.rotatedAt }}</time>
                  <span v-else>Never</span>
                </dd>
              </div>
              <div v-if="!privacyMode">
                <dt>Owner</dt>
                <dd>{{ row.ownerLabel || 'Unassigned' }}</dd>
              </div>
              <div v-if="!privacyMode">
                <dt>Tags</dt>
                <dd>{{ row.tags?.join(' · ') || 'None' }}</dd>
              </div>
            </dl>
            <div
              v-if="inspectedGrace.length || row.deprecatedReferenceWarnings?.length"
              class="variable-inspector__grace"
            >
              <h4><AppIcon name="alert" :size="14" /> Deprecation grace</h4>
              <ul>
                <li v-for="version in inspectedGrace" :key="version.id">
                  v{{ version.version }} · Grace expiry
                  <time :datetime="version.graceUntil">{{ version.graceUntil }}</time>
                </li>
                <li
                  v-for="warning in row.deprecatedReferenceWarnings"
                  :key="`${warning.version}:${warning.surface}`"
                >
                  {{ warningLabel(warning) }}
                </li>
              </ul>
            </div>
          </section>
        </li>
      </ul>
    </template>
  </section>
</template>

<style scoped>
.variables {
  display: grid;
  gap: 0.75rem;
  min-width: 0;
}
.variables__header,
.variables__actions,
.variables__toolbar,
.variables__filters,
.variables__badges,
.variables__row-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.variables__header {
  justify-content: space-between;
}
.variables__header h2 {
  margin: 0;
  font-size: var(--font-page-title);
  letter-spacing: -0.025em;
  overflow-wrap: anywhere;
}
.variables__actions,
.variables__row-actions {
  flex: none;
}
.variables__actions .companion-button:disabled:not(.companion-button--primary) {
  background: transparent;
}
.variables__updated,
.variables__attribution,
.variables__dates {
  color: var(--text-secondary);
  font-size: 0.75rem;
}
.variables__updated {
  white-space: nowrap;
}
.variables__search {
  position: relative;
  flex: 1 1 12rem;
  min-width: 0;
  max-width: 23rem;
  color: var(--text-secondary);
}
.variables__search .app-icon {
  position: absolute;
  top: 50%;
  left: 0.6rem;
  transform: translateY(-50%);
  pointer-events: none;
}
.variables__search input,
.variables__filters select {
  box-sizing: border-box;
  min-height: 2.125rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  color: var(--text-primary);
  font: inherit;
  font-size: 0.8125rem;
}
.variables__search input {
  width: 100%;
  padding: 0.35rem 0.65rem 0.35rem 1.95rem;
}
.variables__filters select {
  padding: 0.3rem;
}
.variables__filter-toggle {
  display: none;
}
.variables__empty {
  margin: 0;
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  color: var(--text-secondary);
  font-size: 0.875rem;
}
.variables__list {
  margin: 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
}
.variables__row {
  display: grid;
  grid-template-columns: minmax(6rem, 1fr) minmax(7rem, 1.35fr) minmax(0, 0.8fr) 6.25rem auto;
  align-items: center;
  gap: 0.6rem;
  min-height: 3.1rem;
  padding: 0.35rem 0.65rem;
}
.variables__row + .variables__row {
  border-top: 1px solid var(--border-subtle);
}
.variables__row:first-child {
  border-radius: var(--radius-md) var(--radius-md) 0 0;
}
.variables__row:last-child {
  border-radius: 0 0 var(--radius-md) var(--radius-md);
}
.variables__row:hover,
.variables__row--inspected {
  background: color-mix(in srgb, var(--bg-surface), var(--bg-subtle) 50%);
}
.variables__name {
  overflow: hidden;
  padding: 0.25rem 0;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-primary);
  font: 650 0.8125rem var(--font-mono);
  text-overflow: ellipsis;
  white-space: nowrap;
  text-align: start;
  cursor: pointer;
}
.variables__name:hover {
  text-decoration: underline;
}
.variables__badges,
.variables__row-actions {
  gap: 0.3rem;
  flex-wrap: wrap;
}
.variable-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.15rem 0.4rem;
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  color: var(--text-secondary);
  font-size: 0.7rem;
  white-space: nowrap;
}
.variable-badge--team {
  color: var(--info);
  background: var(--info-soft);
}
.variable-badge--user-local {
  color: var(--success);
  background: var(--success-soft);
}
.variable-badge--grace {
  color: var(--warn);
  background: var(--warn-soft);
}
.variable-badge--required {
  background: color-mix(in srgb, var(--accent-soft), var(--bg-subtle) 45%);
  color: var(--text-primary);
}
.variable-badge--optional {
  box-shadow: inset 0 0 0 1px var(--border-subtle);
  background: transparent;
}
.variables__attribution {
  min-width: 0;
  overflow-wrap: anywhere;
}
.variables__dates {
  display: grid;
  gap: 0.15rem;
  font-variant-numeric: tabular-nums;
}
.variables__row-actions {
  justify-content: end;
}
.variables__row-actions :deep(.companion-button) {
  min-height: 1.875rem;
  padding-inline: 0.4rem;
  font-size: 0.75rem;
  white-space: nowrap;
}
.variables__verification {
  color: var(--text-secondary);
}
.variables__details-button[aria-expanded='true'] {
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--accent);
}
.variables__details-button[aria-expanded='true'] .app-icon {
  transform: rotate(180deg);
}
.variable-inspector {
  grid-column: 1 / -1;
  display: grid;
  gap: 0.65rem;
  min-width: 0;
  margin-bottom: 0.3rem;
  padding: 0.75rem;
  border: 1px solid var(--border-subtle);
  border-inline-start: 2px solid var(--accent);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
  overflow-wrap: anywhere;
}
.variable-inspector__header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
}
.variable-inspector h3,
.variable-inspector h4,
.variable-inspector dd,
.variable-inspector dl {
  margin: 0;
}
.variable-inspector h3 {
  font: 650 0.875rem var(--font-mono);
}
.variable-inspector__metadata {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 13rem), 1fr));
  gap: 0.65rem 1rem;
  font-size: 0.8rem;
}
.variable-inspector__reference {
  grid-column: 1 / -1;
}
.variable-inspector dt {
  margin-bottom: 0.2rem;
  color: var(--text-secondary);
  font-size: 0.75rem;
}
.variable-inspector time {
  font-family: var(--font-mono);
}
.variable-inspector__grace {
  font-size: 0.8rem;
}
.variable-inspector__grace h4 {
  color: var(--warn);
}
.variable-inspector__grace ul {
  margin: 0.25rem 0 0;
  padding-inline-start: 1.15rem;
}
@media (max-width: 959px) {
  .variables__list {
    display: grid;
    gap: 0.5rem;
    border: 0;
    background: transparent;
  }
  .variables__list .variables__row {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
    gap: 0.45rem 0.75rem;
    padding: 0.65rem 0.75rem;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }
  .variables__name,
  .variables__badges {
    grid-column: 1 / -1;
  }
  .variables__name {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .variables__row-actions :deep(.companion-button) {
    min-height: 2rem;
  }
}
@media (max-width: 767px) {
  .variables__updated {
    display: none;
  }
  .variables__toolbar {
    flex-wrap: wrap;
  }
  .variables__filter-toggle {
    display: inline-flex;
  }
  .variables__filters {
    display: none;
    flex: 1 0 100%;
    flex-wrap: wrap;
  }
  .variables__filters.is-open {
    display: flex;
  }
  .variables__list .variables__row {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .variables__row > .variables__row-actions {
    grid-column: 1 / -1;
  }
  .variables__row-actions {
    justify-content: start;
    padding-top: 0.15rem;
  }
}
@media (max-width: 479px) {
  .variables__refresh-label {
    display: none;
  }
}
</style>
