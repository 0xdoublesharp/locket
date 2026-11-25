<script setup lang="ts">
import { computed, nextTick, ref } from 'vue';

import AppIcon from '../components/AppIcon.vue';
import AgentUnavailableBanner from '../components/AgentUnavailableBanner.vue';
import { desktopActionsAvailable, desktopCopyTextPlain } from '../agent/client';
import { dotenvMigrationPrompt } from '../agent/agentPrompts';
import type { AgentClientError } from '../agent/types';
import { formatTime } from '../utils/formatTime';
import CopyReference from '../components/CopyReference.vue';
import VariableSourceBadge from '../components/VariableSourceBadge.vue';
import { secretReference } from '../secret/reference';
import type { SecretDeprecationWarning, SecretRowMeta, VersionHistoryRow } from '../types/views';
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
  isShared?: boolean;
  actionGuidance?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'select', row: SecretRowMeta): void;
  (e: 'refresh' | 'add' | 'retry' | 'start' | 'openAgentSetup'): void;
  (e: 'copyValue' | 'revealValue', row: SecretRowMeta): void;
}>();

const searchQuery = ref<string>('');
const filterState = ref<SecretFilterState>(defaultSecretFilter());
const inspectedId = ref<string | null>(null);
const inspectedRow = computed(() => props.rows.find(({ id }) => id === inspectedId.value));
const inspectedReference = computed(() =>
  secretReference(props.profileName, inspectedRow.value?.name ?? '', props.privacyMode),
);
const inspectedGrace = computed(() => {
  const row = inspectedRow.value;
  if (!row) return [];
  const warnings = row.deprecatedReferenceWarnings ?? [];
  const grace = new Map<number, { until?: string; expired: boolean; references: string[] }>();
  for (const version of props.versions) {
    if (
      version.secretName === row.name &&
      version.source === row.source &&
      version.state === 'deprecated' &&
      version.graceUntil
    ) {
      grace.set(version.version, {
        until: version.graceUntil,
        expired: !version.pinnedReferenceEligible || Date.parse(version.graceUntil) <= Date.now(),
        references: [],
      });
    }
  }
  for (const warning of warnings) {
    const entry = grace.get(warning.version) ?? {
      until: warning.graceUntil,
      expired: warning.status === 'expired-grace',
      references: [],
    };
    entry.references.push(referenceCountLabel(warning));
    grace.set(warning.version, entry);
  }
  return Array.from(grace, ([version, entry]) => ({ version, ...entry }));
});

async function toggleDetails(row: SecretRowMeta, event: MouseEvent): Promise<void> {
  const button = event.currentTarget as HTMLButtonElement;
  inspectedId.value = row.id === inspectedId.value ? null : row.id;
  if (inspectedId.value !== row.id || !window.matchMedia('(max-width: 959px)').matches) return;
  await nextTick();
  button.closest('li')?.querySelector('.variable-inspector')?.scrollIntoView({ block: 'nearest' });
}

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

const desktop = desktopActionsAvailable();
const migrationMessage = ref('');

async function copyMigrationPrompt(): Promise<void> {
  migrationMessage.value = '';
  const result = await desktopCopyTextPlain(dotenvMigrationPrompt({ isShared: props.isShared }));
  migrationMessage.value = result.ok
    ? 'Copied AI migration prompt.'
    : 'Could not copy AI migration prompt.';
}

function displayName(row: SecretRowMeta): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
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

function referenceCountLabel(warning: SecretDeprecationWarning): string {
  const surface = warning.surface === 'command-preview' ? 'command preview' : 'policy';
  const count = warning.referenceCount;
  return `${count} ${surface} ${count === 1 ? 'reference' : 'references'}`;
}

function warningSearchText(warning: SecretDeprecationWarning): string {
  return [
    `v${warning.version}`,
    warning.status,
    warning.surface,
    warning.referenceCount > 1 ? `${warning.referenceCount} references` : '1 reference',
  ].join(' ');
}

function graceDetails(row: SecretRowMeta): string {
  return (row.deprecatedReferenceWarnings ?? [])
    .map((warning) => {
      const until = warning.graceUntil && formatTime(warning.graceUntil, 'utc');
      const status = warning.status === 'expired-grace' ? 'no longer accepted' : 'still accepted';
      return `v${warning.version} ${status}${until ? ` (${until})` : ''} · ${referenceCountLabel(warning)}`;
    })
    .join('\n');
}
</script>

<template>
  <section class="variables" aria-labelledby="secret-metadata-list-heading">
    <header class="variables__header">
      <h2 id="secret-metadata-list-heading">
        <template v-if="metadataLoaded && !loadError">
          {{ rows.length }} {{ rows.length === 1 ? 'secret' : 'secrets' }} · {{ profileLabel }}
        </template>
        <template v-else>Secrets · {{ profileLabel }}</template>
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
          aria-label="Refresh secrets"
          title="Refresh secrets"
          :disabled="loading || !connected"
          @click="emit('refresh')"
        >
          <AppIcon name="refresh" />
          <span class="variables__refresh-label">Refresh</span>
        </button>
        <button
          v-if="!isEmpty || loadError || actionGuidance"
          class="companion-button icon-label"
          :class="{ 'companion-button--primary': connected }"
          type="button"
          :disabled="!connected"
          @click="emit('add')"
        >
          <AppIcon name="plus" />
          Add secret
        </button>
      </div>
    </header>

    <AgentUnavailableBanner
      v-if="loadError"
      :error="loadError"
      heading="Can't load secrets"
      :retrying="loading"
      :can-start="canStart"
      :starting="starting"
      @retry="emit('retry')"
      @start="emit('start')"
    />
    <p v-else-if="loading" class="variables__empty" role="status">Loading secret metadata…</p>
    <p v-else-if="actionGuidance" class="variables__empty" role="status">{{ actionGuidance }}</p>

    <section
      v-else-if="isEmpty"
      class="variables__empty variables__onboarding"
      aria-labelledby="variables-onboarding-heading"
    >
      <h3 id="variables-onboarding-heading">No secrets yet</h3>
      <p>Add a secret or ask your AI agent to migrate existing <code>.env</code> files.</p>
      <div class="variables__onboarding-actions">
        <button
          class="companion-button companion-button--primary icon-label"
          type="button"
          :disabled="!connected"
          @click="emit('add')"
        >
          <AppIcon name="plus" />
          Add a secret
        </button>
        <button
          class="companion-button icon-label"
          type="button"
          :disabled="!desktop"
          @click="copyMigrationPrompt"
        >
          <AppIcon name="copy" />
          Copy AI migration prompt
        </button>
        <button class="companion-button icon-label" type="button" @click="emit('openAgentSetup')">
          <AppIcon name="terminal" />
          AI agent &amp; MCP setup
        </button>
      </div>
      <p class="variables__migration-status" role="status">{{ migrationMessage }}</p>
    </section>

    <template v-else>
      <div class="variables__toolbar">
        <label class="variables__search">
          <AppIcon name="search" />
          <input
            v-model="searchQuery"
            type="search"
            aria-label="Search secrets"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search secrets"
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
          <label class="variables__select">
            <select v-model="filterState.source" aria-label="Filter by source">
              <option value="all">All sources</option>
              <option value="team">Shared</option>
              <option value="user-local">My override</option>
              <option value="machine-local">This machine</option>
            </select>
            <AppIcon name="chevron-down" :size="13" />
          </label>
          <label class="variables__select">
            <select v-model="filterState.required" aria-label="Filter by requirement">
              <option value="all">Any requirement</option>
              <option value="required">Required</option>
              <option value="optional">Optional</option>
            </select>
            <AppIcon name="chevron-down" :size="13" />
          </label>
          <label class="variables__select">
            <select v-model="filterState.deprecation" aria-label="Filter by status">
              <option value="all">Any status</option>
              <option value="current">Current</option>
              <option value="deprecated">Deprecated grace</option>
            </select>
            <AppIcon name="chevron-down" :size="13" />
          </label>
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

      <p v-if="isFilteredEmpty" class="variables__empty" role="status">No matching secrets.</p>
      <ul v-else class="variables__list" aria-label="Secret metadata">
        <li
          v-for="row in filteredRows"
          :key="row.id"
          class="variables__row"
          :class="{ 'variables__row--inspected': row.id === inspectedId }"
        >
          <div class="variables__row-header">
            <button
              type="button"
              class="variables__name"
              :title="displayName(row)"
              :aria-label="`Open metadata for ${displayName(row)}`"
              @click="emit('select', row)"
            >
              {{ displayName(row) }}
            </button>
            <button
              class="companion-button icon-label variables__details-button"
              type="button"
              :aria-label="`Details for ${displayName(row)}`"
              :aria-expanded="row.id === inspectedId"
              :aria-controls="row.id === inspectedId ? 'variable-inspector' : undefined"
              @click="toggleDetails(row, $event)"
            >
              Details <AppIcon name="chevron-down" :size="12" />
            </button>
          </div>

          <div class="variables__badges">
            <VariableSourceBadge :source="row.source" />
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
            <div
              v-if="canAccessValues"
              class="variables__sensitive"
              role="group"
              aria-label="Secret value"
            >
              <button
                class="companion-button icon-label"
                type="button"
                :aria-description="copyVerification ? 'System verification required' : undefined"
                :title="
                  copyVerification
                    ? 'Copy value with Touch ID or system verification'
                    : 'Copy value'
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
                class="companion-button icon-label"
                type="button"
                @click="emit('revealValue', row)"
              >
                <AppIcon name="eye" />
                Reveal
              </button>
            </div>
          </div>
          <section
            v-if="row.id === inspectedId"
            id="variable-inspector"
            class="variable-inspector"
            aria-labelledby="variable-inspector-title"
          >
            <header class="variable-inspector__header">
              <h3 id="variable-inspector-title">Secret details</h3>
              <button
                class="companion-button icon-label"
                type="button"
                @click="emit('select', row)"
              >
                <AppIcon name="clock" /> Version history
              </button>
            </header>
            <dl class="variable-inspector__metadata">
              <div v-if="inspectedReference" class="variable-inspector__reference">
                <dt>Reference</dt>
                <dd>
                  <code>{{ inspectedReference }}</code>
                </dd>
              </div>
              <div>
                <dt>Created</dt>
                <dd>
                  <time :datetime="row.createdAt" :title="row.createdAt">{{
                    formatTime(row.createdAt, 'utc')
                  }}</time>
                </dd>
              </div>
              <div>
                <dt>Rotated</dt>
                <dd>
                  <time v-if="row.rotatedAt" :datetime="row.rotatedAt" :title="row.rotatedAt">{{
                    formatTime(row.rotatedAt, 'utc')
                  }}</time>
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
            <div v-if="inspectedGrace.length" class="variable-inspector__grace">
              <h4>Grace periods</h4>
              <ul>
                <li v-for="entry in inspectedGrace" :key="entry.version">
                  <AppIcon :name="entry.expired ? 'alert' : 'clock'" :size="14" />
                  <span>
                    v{{ entry.version }} {{ entry.expired ? 'no longer accepted' : 'still accepted'
                    }}<template v-if="entry.until">
                      {{ entry.expired ? ' since ' : ' until ' }}
                      <time :datetime="entry.until" :title="entry.until">{{
                        formatTime(entry.until, 'utc-date')
                      }}</time></template
                    ><template v-if="entry.references.length">
                      · {{ entry.references.join(' · ') }}</template
                    >
                  </span>
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
.variables__select {
  position: relative;
  display: inline-flex;
}
.variables__select select {
  appearance: none;
  padding: 0.3rem 1.6rem 0.3rem 0.55rem;
}
.variables__select .app-icon {
  position: absolute;
  inset-inline-end: 0.5rem;
  top: 50%;
  transform: translateY(-50%);
  pointer-events: none;
  color: var(--text-secondary);
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
.variables__onboarding {
  display: grid;
  gap: 0.65rem;
}
.variables__onboarding h3,
.variables__onboarding p {
  margin: 0;
}
.variables__onboarding h3 {
  color: var(--text-primary);
  font-size: 0.95rem;
}
.variables__onboarding-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.variables__migration-status:empty {
  position: absolute;
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
  grid-template-columns: minmax(10.5rem, 1.25fr) minmax(8rem, 1.25fr) minmax(0, 0.8fr) 6.25rem auto;
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
.variables__row-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  min-width: 0;
  gap: 0.35rem;
}
.variables__name {
  min-width: 0;
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
.variable-badge--grace {
  color: var(--warn);
  background: var(--warn-soft);
}
.variable-badge--required {
  box-shadow: inset 0 0 0 1px var(--border-required);
  background: var(--accent-soft);
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
  flex-wrap: nowrap;
}
.variables__sensitive {
  display: inline-flex;
  align-items: center;
  gap: 0.125rem;
  padding: 0.125rem;
  border-radius: var(--radius-sm);
  background: var(--bg-app);
}
.variables__row-actions :deep(.companion-button),
.variables__row-header .variables__details-button {
  min-height: 2rem;
  padding: 0.2rem 0.4rem;
  border-color: transparent;
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.75rem;
  white-space: nowrap;
}
.variables__row-actions :deep(.companion-button:hover:not(:disabled)),
.variables__row-header .variables__details-button:hover {
  border-color: transparent;
  background: var(--bg-subtle);
  color: var(--text-primary);
}
.variables__row-actions :deep(.companion-button:focus-visible),
.variables__details-button:focus-visible {
  outline-offset: -2px;
}
.variables__verification {
  color: var(--text-secondary);
}
.variables__row-header .variables__details-button[aria-expanded='true'] {
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
  border-radius: var(--radius-md);
  background: var(--bg-app);
  overflow-wrap: anywhere;
  scroll-margin-block: 0.75rem;
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
  font-size: 0.875rem;
}
.variable-inspector__metadata {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
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
  font-variant-numeric: tabular-nums;
}
.variable-inspector__grace {
  font-size: 0.8rem;
}
.variable-inspector__grace h4 {
  color: var(--text-secondary);
}
.variable-inspector__grace ul {
  display: grid;
  gap: 0.35rem;
  margin: 0.35rem 0 0;
  padding: 0;
  list-style: none;
}
.variable-inspector__grace li {
  display: flex;
  gap: 0.4rem;
  align-items: baseline;
}
.variable-inspector__grace .app-icon {
  align-self: start;
  color: var(--warn);
}
@media (max-width: 959px) {
  .variable-inspector__metadata {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .variables__list {
    display: grid;
    gap: 0.5rem;
    border: 0;
    background: transparent;
  }
  .variables__list .variables__row {
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.35rem 0.65rem;
    padding: 0.35rem 0.65rem;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
  }
  .variables__row-header {
    grid-column: 1 / -1;
  }
  .variables__name {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .variables__attribution:empty {
    display: none;
  }
  .variables__attribution {
    grid-column: 1 / -1;
  }
  .variables__dates {
    grid-column: 2;
    grid-row: 2;
    text-align: end;
  }
  .variables__row > .variables__row-actions {
    grid-column: 1 / -1;
    justify-content: start;
  }
}
@media (max-width: 767px) {
  .variables {
    gap: 0.55rem;
  }
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
}
@media (min-width: 640px) and (max-width: 959px) {
  .variables__attribution {
    grid-column: 1;
  }
  .variables__row > .variables__row-actions {
    grid-column: 2;
    grid-row: 3;
    justify-content: end;
  }
}
@media (max-width: 479px) {
  .variables__refresh-label {
    display: none;
  }
}
@media (min-width: 640px) and (max-width: 767px) and (max-height: 520px) {
  .variables:has(.variables__toolbar) {
    grid-template-columns: auto minmax(0, 1fr);
    align-items: start;
    column-gap: 0.75rem;
  }
  .variables__header {
    gap: 0.65rem;
  }
  .variables__refresh-label {
    display: none;
  }
  .variables__search {
    flex-basis: 0;
  }
  .variables__list,
  .variables__empty {
    grid-column: 1 / -1;
  }
}
</style>
