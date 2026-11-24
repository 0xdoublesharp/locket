<script setup lang="ts">
import { computed, ref } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import { formatTime } from '../utils/formatTime';
import VariableReadinessPanel from '../components/VariableReadinessPanel.vue';
import type {
  AuditLogRow,
  CommandPolicyRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from '../types/views';
import { startHereActions, type StartHereTarget } from '../dashboard/startHere';
import { auditHealth, scanHealth } from '../dashboard/health';
const props = defineProps<{
  projectId?: string;
  profileId?: string;
  privacyMode?: boolean;
  lockLabel: string;
  projectLabel: string;
  profileLabel: string;
  loading: boolean;
  setupComplete: boolean;
  projectConnected: boolean;
  activeProjectFolder?: boolean;
  connected: boolean;
  secretsLoaded: boolean;
  policiesLoaded: boolean;
  secrets: SecretRowMeta[];
  versions: VersionHistoryRow[];
  sessions: RuntimeSessionRow[];
  auditRows: AuditLogRow[];
  findings: ScanFindingRow[];
  policies: CommandPolicyRow[];
  settings: SettingsState;
  auditChainOk: boolean | null;
  auditError?: string | null;
  auditLastRefreshed?: string;
  lastScanAt?: string;
  scanLocked: boolean;
  scanError?: string | null;
  sessionsLastRefreshed?: string;
}>();
const emit = defineEmits<{
  action: [target: StartHereTarget];
  navigate: [target: 'secrets' | 'execution' | 'audit' | 'scan' | 'profiles'];
  refresh: [];
}>();
const startActions = computed(() =>
  startHereActions(props).filter((action) => action.target !== 'start-agent'),
);
const refreshCount = ref(0);
function refreshDashboard(): void {
  refreshCount.value += 1;
  emit('refresh');
}
const audit = computed(() => auditHealth(props.auditChainOk));
const scan = computed(() =>
  scanHealth(props.lastScanAt, props.scanLocked, props.scanError, props.findings.length),
);
const failedRuns = computed(
  () => props.sessions.filter((row) => row.state === 'failed' || row.state === 'stale').length,
);
const readiness = computed(() => ({
  projectId: props.projectId,
  profileId: props.profileId,
  privacyMode: props.privacyMode,
  hideRefresh: true,
  collapsible: true,
  refreshKey: [
    refreshCount.value,
    props.policies.map((row) => row.updatedAt).join('|'),
    props.secrets.map((row) => row.id + row.currentVersion).join('|'),
  ].join(':'),
}));
</script>
<template>
  <section class="dashboard" aria-labelledby="project-dashboard-heading">
    <header class="dashboard__header">
      <div>
        <h2 id="project-dashboard-heading">Project</h2>
        <p class="dashboard__context">{{ projectLabel }} / {{ profileLabel }}</p>
      </div>
      <div class="dashboard__header-actions">
        <slot name="search" />
        <button
          type="button"
          class="companion-button icon-label"
          :disabled="loading"
          @click="refreshDashboard"
        >
          <AppIcon name="refresh" />
          {{ loading ? 'Refreshing…' : 'Refresh' }}
        </button>
      </div>
    </header>
    <p v-if="!startActions.length && connected" class="dashboard__setup-complete">
      <AppIcon name="check" /> Setup complete
    </p>
    <VariableReadinessPanel v-if="activeProjectFolder" v-bind="readiness" />
    <slot name="connection" />
    <section
      v-if="startActions.length"
      class="dashboard__start"
      aria-labelledby="dashboard-start-heading"
    >
      <div class="dashboard__section-head">
        <h3 id="dashboard-start-heading">Start here</h3>
      </div>
      <ol class="dashboard__start-list">
        <li v-for="action in startActions" :key="action.id">
          <div>
            <strong>{{ action.title }}</strong>
            <p>{{ action.detail }}</p>
          </div>
          <button
            type="button"
            class="dashboard__start-action"
            @click="emit('action', action.target)"
          >
            {{ action.actionLabel }}
          </button>
        </li>
      </ol>
    </section>
    <VariableReadinessPanel v-if="!activeProjectFolder" v-bind="readiness" />
    <section class="dashboard__status" aria-label="Agent status">
      <div class="dashboard__lock">
        <span class="dashboard__lock-label">Vault</span><strong>{{ lockLabel }}</strong>
      </div>
      <dl class="dashboard__facts">
        <div>
          <dt>Agent</dt>
          <dd>{{ connected ? settings.agentVersion : 'Offline' }}</dd>
        </div>
        <div>
          <dt>Environment</dt>
          <dd>{{ profileLabel }}</dd>
        </div>
        <div>
          <dt>Unlock duration</dt>
          <dd>{{ settings.unlockTtlSeconds || 900 }} seconds</dd>
        </div>
      </dl>
    </section>
    <section class="dashboard__metrics" aria-label="Project summary">
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'secrets')">
        <span>Variables</span><strong>{{ secretsLoaded ? secrets.length : 'Unknown' }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'execution')">
        <span>Recorded runs</span
        ><strong>{{ sessionsLastRefreshed ? sessions.length : 'Unknown' }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'audit')">
        <span>Audit chain</span
        ><strong :class="`dashboard__health-${audit.tone}`">{{ audit.label }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'scan')">
        <span>Project scan</span
        ><strong :class="`dashboard__health-${scan.tone}`">{{ scan.label }}</strong>
      </button>
    </section>
    <section class="dashboard__health" aria-labelledby="dashboard-health-heading">
      <h3 id="dashboard-health-heading">Checks for this project</h3>
      <p>
        Audit: {{ audit.label
        }}<span v-if="auditLastRefreshed">
          · Last checked
          <time :datetime="auditLastRefreshed" :title="auditLastRefreshed">{{
            formatTime(auditLastRefreshed)
          }}</time></span
        >
      </p>
      <p v-if="auditError" role="alert">{{ auditError }} Retry from Activity.</p>
      <p>
        Scan: {{ scan.label
        }}<span v-if="lastScanAt">
          · Last checked
          <time :datetime="lastScanAt" :title="lastScanAt">{{ formatTime(lastScanAt) }}</time></span
        >. Scans check this project's files and available known values.
      </p>
      <p v-if="scanError" role="alert">{{ scanError }} Retry the scan.</p>
      <p v-if="sessionsLastRefreshed">Failed or stale runs: {{ failedRuns }}</p>
    </section>
  </section>
</template>
<style scoped>
.dashboard {
  color: var(--text-primary);
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.dashboard__status,
.dashboard__search,
.dashboard__start,
.dashboard__health {
  background: var(--bg-surface);
  border-radius: 0.5rem;
  padding: 1rem;
}

.dashboard__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  min-width: 0;
}

.dashboard__header h2 {
  margin: 0;
  font-size: var(--font-page-title);
  letter-spacing: -0.025em;
}
.dashboard__header > div {
  min-width: 0;
  overflow-wrap: anywhere;
}
.dashboard__header .dashboard__header-actions {
  display: flex;
  gap: 0.5rem;
  flex: none;
}

.dashboard__setup-complete {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  margin: 0;
  color: var(--success);
  font-size: 0.8125rem;
}

.dashboard__section-head h3,
.dashboard__search h3,
.dashboard__health h3 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
}

.dashboard__context {
  margin: 0.35rem 0 0;
  color: var(--text-secondary);
  display: flex;
  gap: 0.4rem;
  min-width: 0;
  overflow-wrap: anywhere;
}

.dashboard__context span {
  overflow-wrap: anywhere;
}

.dashboard__metric,
.dashboard__start-action {
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
  cursor: pointer;
}

.dashboard__section-head {
  align-items: center;
  display: flex;
  gap: 1rem;
  justify-content: space-between;
}

.dashboard__section-head span {
  color: var(--text-secondary);
  font-size: 0.78rem;
}

.dashboard__start {
  display: grid;
  gap: 0.875rem;
}

.dashboard__start-list {
  display: grid;
  gap: 0.625rem;
  list-style: none;
  margin: 0;
  padding: 0;
}

.dashboard__start-list li {
  align-items: center;
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  display: grid;
  gap: 1rem;
  grid-template-columns: 1fr auto;
  min-width: 0;
  padding: 0.875rem;
}

.dashboard__start-list p {
  color: var(--text-secondary);
  font-size: 0.85rem;
  margin: 0.25rem 0 0;
}

.dashboard__start-title {
  display: block;
}

.dashboard__start-title--ok {
  color: var(--success);
}

.dashboard__start-title--warn {
  color: var(--accent);
}

.dashboard__start-title--critical {
  color: var(--danger);
}

.dashboard__start-title--neutral {
  color: var(--text-primary);
}

.dashboard__start-action {
  border-radius: 0.375rem;
  min-height: 2.25rem;
  padding: 0 0.875rem;
  white-space: nowrap;
}

.dashboard__status {
  display: grid;
  grid-template-columns: minmax(12rem, 0.4fr) 1fr;
  gap: 1rem;
}

.dashboard__lock {
  border-radius: 0.5rem;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  background: var(--bg-subtle);
}

.dashboard__lock-label,
.dashboard__facts dt,
.dashboard__metric span,
.dashboard__health li span {
  color: var(--text-secondary);
  font-size: 0.78rem;
}

.dashboard__lock strong {
  font-size: 1.5rem;
}

.dashboard__status--ok {
  color: var(--success);
}

.dashboard__status--locked,
.dashboard__status--pending {
  color: var(--accent);
}

.dashboard__status--error {
  color: var(--danger);
}

.dashboard__facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__facts div {
  min-width: 0;
}

.dashboard__facts dd {
  margin: 0.25rem 0 0;
  overflow-wrap: anywhere;
}

.dashboard__metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__metric {
  border-radius: 0.5rem;
  min-height: 6rem;
  padding: 0.875rem;
  text-align: left;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.dashboard__metric:hover,
.dashboard__metric:focus-visible,
.dashboard__metric strong {
  font-size: 2rem;
}

.dashboard__search {
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}

.dashboard__search-header {
  align-items: center;
  display: flex;
  justify-content: space-between;
  gap: 1rem;
}

.dashboard__search-scopes {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.dashboard__scope {
  border: 1px solid var(--border-subtle);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  cursor: pointer;
  min-height: 2rem;
  padding: 0 0.7rem;
}

.dashboard__scope--active {
  border-color: var(--accent);
  color: var(--accent);
}

.dashboard__search-box {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.dashboard__search-box span,
.dashboard__search-results li span,
.dashboard__search-results li em {
  color: var(--text-secondary);
  font-size: 0.78rem;
  font-style: normal;
}

.dashboard__search-box input {
  border: 1px solid var(--border-subtle);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  min-height: 2.5rem;
  padding: 0 0.75rem;
}

.dashboard__search-box input:focus,
.dashboard__scope:focus-visible {
  border-color: var(--accent);
  outline: none;
}

.dashboard__search-results {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.75rem;
  list-style: none;
  margin: 0;
  padding: 0;
}

.dashboard__search-results li {
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  display: grid;
  gap: 0.25rem;
  min-height: 4.5rem;
  padding: 0.75rem;
}

.dashboard__search-results li strong {
  overflow-wrap: anywhere;
}

.dashboard__search-empty {
  grid-column: 1 / -1;
}

.dashboard__health ul {
  margin: 0.75rem 0 0;
  padding: 0;
  list-style: none;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__health li {
  min-width: 0;
}

.dashboard__health li strong {
  display: block;
  margin-top: 0.25rem;
  overflow-wrap: anywhere;
}

.dashboard__health-ok {
  color: var(--success);
}

.dashboard__health-warn {
  color: var(--accent);
}

.dashboard__health-neutral {
  color: var(--text-primary);
}

@media (max-width: 860px) {
  .dashboard__status,
  .dashboard__facts,
  .dashboard__metrics,
  .dashboard__search-results,
  .dashboard__health ul,
  .dashboard__start-list li {
    grid-template-columns: 1fr;
  }

  .dashboard__start-action {
    width: 100%;
  }

  .dashboard__search-header,
  .dashboard__section-head {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
