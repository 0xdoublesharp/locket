<script setup lang="ts">
import { computed, onScopeDispose, ref, watch } from 'vue';
import { actionError, discoverSecrets } from '../agent/client';
import type { DiscoveredSecretWire } from '../agent/types';
import AppIcon from '../components/AppIcon.vue';
import CopyReference from '../components/CopyReference.vue';
import { createRequestLifetime } from '../utils/requestLifetime';

const props = defineProps<{
  privacyMode: boolean;
  knownProjectIds: string[];
  currentProjectId?: string | null;
  currentProfileId?: string | null;
  switching?: boolean;
  switchError?: string | null;
}>();
const emit = defineEmits<{
  openProject: [row: DiscoveredSecretWire];
  switchEnvironment: [row: DiscoveredSecretWire];
}>();

const query = ref('');
const tag = ref('');
const owner = ref('');
const rows = ref<DiscoveredSecretWire[]>([]);
const loading = ref(false);
const error = ref('');
const requests = createRequestLifetime();
const limit = 200;
const filters = computed(() =>
  props.privacyMode
    ? {}
    : {
        ...(query.value.trim() && { query: query.value.trim() }),
        ...(tag.value.trim() && { tag: tag.value.trim() }),
        ...(owner.value.trim() && { owner: owner.value.trim() }),
      },
);

async function search(): Promise<void> {
  const isCurrent = requests.begin();
  rows.value = [];
  error.value = '';
  loading.value = true;
  const result = await discoverSecrets({
    ...filters.value,
    redact_names: props.privacyMode,
    limit,
  });
  if (!isCurrent()) return;
  if (result.ok) rows.value = result.value;
  else error.value = actionError(result.error);
  loading.value = false;
}

watch(
  () => props.privacyMode,
  (redacted) => {
    if (redacted) query.value = tag.value = owner.value = '';
    void search();
  },
  { immediate: true, flush: 'sync' },
);
onScopeDispose(requests.dispose);

function canOpenProject(row: DiscoveredSecretWire): boolean {
  return (
    props.knownProjectIds.includes(row.project_id) ||
    (!props.privacyMode && row.trusted_roots.length > 0)
  );
}

function isActive(row: DiscoveredSecretWire): boolean {
  return row.project_id === props.currentProjectId && row.profile_id === props.currentProfileId;
}
</script>

<template>
  <section class="discovery" aria-labelledby="discovery-title">
    <header>
      <h2 id="discovery-title">Discover across projects</h2>
      <p>Find variables by name, tag, or owner, including variables in the shared vault.</p>
    </header>

    <form v-if="!privacyMode" class="discovery__filters" @submit.prevent="search">
      <label>Search <input v-model="query" type="search" placeholder="Name or keyword" /></label>
      <label>Tag <input v-model="tag" type="text" placeholder="Any tag" /></label>
      <label>Owner <input v-model="owner" type="text" placeholder="Any owner" /></label>
      <button class="companion-button companion-button--primary icon-label" type="submit">
        <AppIcon name="search" /> Search all projects
      </button>
    </form>
    <p v-else>Turn off name redaction in Settings to search by name, tag, or owner.</p>

    <p v-if="switchError" class="discovery__error" role="alert">{{ switchError }}</p>

    <p v-if="loading" role="status">Searching projects…</p>
    <div v-else-if="error" class="discovery__error" role="alert">
      <p>{{ error }}</p>
      <button class="companion-button" type="button" @click="search">Retry</button>
    </div>
    <p v-else-if="rows.length === 0" role="status">No matching variables across projects.</p>
    <template v-else>
      <p role="status">
        {{
          rows.length === limit
            ? `Showing the first ${limit} results`
            : `${rows.length} ${rows.length === 1 ? 'result' : 'results'}`
        }}
      </p>
      <ul class="discovery__list">
        <li v-for="row in rows" :key="row.secret_id">
          <div>
            <strong>{{ row.name }}</strong>
            <p>
              {{ row.project_name }} <span aria-hidden="true">/</span> {{ row.profile }}
              <span v-if="row.dangerous" class="discovery__warning">Dangerous</span>
            </p>
            <p v-if="!privacyMode && (row.owner || row.tags.length)">
              {{ [row.owner, ...row.tags].filter(Boolean).join(' · ') }}
            </p>
          </div>
          <div class="discovery__actions">
            <CopyReference :reference="privacyMode ? null : row.reference" />
            <span v-if="isActive(row)" class="discovery__current">
              <AppIcon name="check" :size="14" /> Active
            </span>
            <template v-else-if="row.project_id === currentProjectId && currentProfileId">
              <button
                v-if="!privacyMode"
                class="companion-button icon-label"
                type="button"
                :title="`Switch to ${row.profile}`"
                :disabled="switching"
                @click="emit('switchEnvironment', row)"
              >
                <span>Switch to {{ row.profile }}</span>
              </button>
            </template>
            <button
              v-else-if="canOpenProject(row)"
              class="companion-button icon-label"
              type="button"
              @click="emit('openProject', row)"
            >
              <AppIcon name="folder" /> Open project
            </button>
            <small v-else-if="!privacyMode">No local folder</small>
          </div>
        </li>
      </ul>
    </template>
  </section>
</template>

<style scoped>
.discovery {
  display: grid;
  gap: 0.875rem;
}
.discovery h2,
.discovery p {
  margin: 0;
}
.discovery h2 {
  font-size: var(--font-page-title);
  letter-spacing: -0.025em;
}
.discovery p,
.discovery small {
  color: var(--text-secondary);
}
.discovery header p {
  margin-top: 0.35rem;
}
.discovery__filters {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) repeat(2, minmax(0, 1fr)) auto;
  align-items: end;
  gap: 0.5rem;
}
.discovery__actions {
  display: grid;
  grid-template-columns: 5.5rem minmax(0, 1fr);
  align-items: center;
  gap: 0.35rem;
  text-align: end;
}
.discovery__actions > :first-child:not(.copy-reference) {
  grid-column: 2;
}
.discovery__actions .companion-button {
  min-width: 0;
  white-space: nowrap;
}
.discovery__actions :deep(.copy-reference .companion-button) {
  width: 100%;
  padding-inline: 0.35rem;
  white-space: nowrap;
}
.discovery__actions .companion-button span {
  overflow: hidden;
  text-overflow: ellipsis;
}
.discovery__filters label {
  display: grid;
  min-width: 0;
  gap: 0.25rem;
  font-size: 0.875rem;
}
.discovery__filters input {
  box-sizing: border-box;
  width: 100%;
  min-width: 0;
  min-height: 2.125rem;
  padding: 0.35rem 0.6rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  color: var(--text-primary);
  font: inherit;
}
.discovery .discovery__error,
.discovery__error p {
  color: var(--danger);
}
.discovery__list {
  display: grid;
  gap: 0.5rem;
  margin: 0;
  padding: 0;
  list-style: none;
}
.discovery__list li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 14rem;
  align-items: center;
  gap: 0.65rem;
  padding: 0.55rem 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  overflow-wrap: anywhere;
}
.discovery__list strong {
  font-family: var(--font-mono);
}
.discovery__list p {
  font-size: 0.85rem;
}
.discovery__warning {
  margin-left: 0.4rem;
  padding: 0.1rem 0.4rem;
  border-radius: var(--radius-sm);
  background: var(--warn-soft);
  color: var(--warn);
}
.discovery__current {
  display: inline-flex;
  justify-content: end;
  align-items: center;
  gap: 0.25rem;
  padding-inline-end: 0.55rem;
  color: var(--success);
  font-size: 0.75rem;
  font-weight: 650;
}
@media (max-width: 600px) {
  .discovery__filters {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .discovery__filters > :first-child,
  .discovery__filters > button {
    grid-column: 1 / -1;
  }
  .discovery__filters > button {
    justify-self: start;
  }
}
@media (max-width: 479px) {
  .discovery__list li {
    grid-template-columns: minmax(0, 1fr);
  }
  .discovery__actions {
    width: min(100%, 14rem);
    justify-self: end;
  }
}
</style>
