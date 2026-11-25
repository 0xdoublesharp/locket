<script setup lang="ts">
import { computed, ref } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import { formatDuration, formatTime } from '../utils/formatTime';
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
const requiredVariables = computed(() => props.secrets.filter((row) => row.required).length);
const vaultTone = computed(() => {
  switch (props.lockLabel) {
    case 'Unlocked':
      return 'ok';
    case 'Locked':
      return 'locked';
    case 'Connecting…':
      return 'pending';
    default:
      return 'error';
  }
});
const unlockDuration = computed(() => formatDuration(props.settings.unlockTtlSeconds || 900));
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
      <div class="dashboard__heading">
        <h2 id="project-dashboard-heading">Project</h2>
        <div class="dashboard__context-row">
          <p class="dashboard__context">{{ projectLabel }} / {{ profileLabel }}</p>
          <span
            v-if="!startActions.length && connected"
            class="companion-pill companion-pill--ok dashboard__setup-complete"
          >
            <AppIcon name="check" :size="12" /> Setup complete
          </span>
        </div>
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
            class="companion-button companion-button--primary dashboard__start-action"
            @click="emit('action', action.target)"
          >
            {{ action.actionLabel }}
          </button>
        </li>
      </ol>
    </section>
    <section class="dashboard__metrics" aria-label="Project summary">
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'secrets')">
        <span class="dashboard__metric-label"
          >Variables <AppIcon name="chevron-down" class="dashboard__metric-arrow" :size="14"
        /></span>
        <strong>{{ secretsLoaded ? secrets.length : 'Unknown' }}</strong>
        <span class="dashboard__metric-meta">{{
          secretsLoaded ? `${requiredVariables} required` : 'Not loaded'
        }}</span>
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'execution')">
        <span class="dashboard__metric-label"
          >Recorded runs <AppIcon name="chevron-down" class="dashboard__metric-arrow" :size="14"
        /></span>
        <strong>{{ sessionsLastRefreshed ? sessions.length : 'Unknown' }}</strong>
        <span
          :class="['dashboard__metric-meta', { 'dashboard__metric-meta--warn': failedRuns > 0 }]"
          >{{ sessionsLastRefreshed ? `${failedRuns} failed/stale` : 'Not loaded' }}</span
        >
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'audit')">
        <span class="dashboard__metric-label"
          >Audit chain <AppIcon name="chevron-down" class="dashboard__metric-arrow" :size="14"
        /></span>
        <strong :class="`dashboard__health-${audit.tone}`">{{ audit.label }}</strong>
        <span class="dashboard__metric-meta">
          <template v-if="auditLastRefreshed"
            >Checked {{ formatTime(auditLastRefreshed) }}</template
          >
          <template v-else>Not checked yet</template>
        </span>
      </button>
      <button type="button" class="dashboard__metric" @click="emit('navigate', 'scan')">
        <span class="dashboard__metric-label"
          >Project scan <AppIcon name="chevron-down" class="dashboard__metric-arrow" :size="14"
        /></span>
        <strong :class="`dashboard__health-${scan.tone}`">{{ scan.label }}</strong>
        <span class="dashboard__metric-meta">
          <template v-if="lastScanAt">Checked {{ formatTime(lastScanAt) }}</template>
          <template v-else>Runs in your terminal</template>
        </span>
      </button>
    </section>
    <section class="dashboard__status" aria-label="Agent status">
      <dl class="dashboard__facts">
        <div class="dashboard__fact">
          <dt>Vault</dt>
          <dd :class="`dashboard__status--${vaultTone}`">
            <span class="dashboard__dot" aria-hidden="true"></span>
            <strong>{{ lockLabel }}</strong>
          </dd>
        </div>
        <div class="dashboard__fact">
          <dt>Agent</dt>
          <dd>{{ connected ? settings.agentVersion : 'Offline' }}</dd>
        </div>
        <div class="dashboard__fact">
          <dt>Environment</dt>
          <dd>{{ profileLabel }}</dd>
        </div>
        <div class="dashboard__fact">
          <dt>Unlock duration</dt>
          <dd :title="`${settings.unlockTtlSeconds || 900} seconds`">{{ unlockDuration }}</dd>
        </div>
      </dl>
    </section>
    <div class="dashboard__pair">
      <VariableReadinessPanel v-if="activeProjectFolder" v-bind="readiness" />
      <slot name="connection" />
      <VariableReadinessPanel v-if="!activeProjectFolder" v-bind="readiness" />
    </div>
    <section class="dashboard__health" aria-labelledby="dashboard-health-heading">
      <h3 id="dashboard-health-heading">Checks for this project</h3>
      <ul class="dashboard__checks">
        <li>
          <span :class="['dashboard__check-dot', `dashboard__check-dot--${audit.tone}`]"></span>
          <span class="dashboard__check-body">
            <strong>Audit: {{ audit.label }}</strong>
            <span v-if="auditLastRefreshed" class="dashboard__check-meta">
              Last checked
              <time :datetime="auditLastRefreshed" :title="auditLastRefreshed">{{
                formatTime(auditLastRefreshed)
              }}</time>
            </span>
          </span>
        </li>
        <li>
          <span :class="['dashboard__check-dot', `dashboard__check-dot--${scan.tone}`]"></span>
          <span class="dashboard__check-body">
            <strong>Scan: {{ scan.label }}</strong>
            <span class="dashboard__check-meta">
              <template v-if="lastScanAt">
                Last checked
                <time :datetime="lastScanAt" :title="lastScanAt">{{ formatTime(lastScanAt) }}</time>
                ·
              </template>
              Scans check this project's files and available known values.
            </span>
          </span>
        </li>
        <li v-if="sessionsLastRefreshed">
          <span
            :class="[
              'dashboard__check-dot',
              failedRuns ? 'dashboard__check-dot--warn' : 'dashboard__check-dot--ok',
            ]"
          ></span>
          <span class="dashboard__check-body">
            <strong>Failed or stale runs: {{ failedRuns }}</strong>
          </span>
        </li>
      </ul>
      <p v-if="auditError" class="dashboard__alert" role="alert">
        {{ auditError }} Retry from Activity.
      </p>
      <p v-if="scanError" class="dashboard__alert" role="alert">{{ scanError }} Retry the scan.</p>
    </section>
  </section>
</template>
<style scoped>
.dashboard {
  container: dashboard / inline-size;
  color: var(--text-primary);
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}

.dashboard__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  min-width: 0;
}

.dashboard__heading {
  min-width: 0;
}

.dashboard__header h2 {
  margin: 0;
  font-size: var(--font-page-title);
  letter-spacing: -0.025em;
}

.dashboard__header .dashboard__header-actions {
  display: flex;
  gap: 0.5rem;
  flex: none;
}

.dashboard__context-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem 0.6rem;
  margin-top: 0.25rem;
  min-width: 0;
}

.dashboard__context {
  margin: 0;
  color: var(--text-secondary);
  font-size: 0.9375rem;
  min-width: 0;
  overflow-wrap: anywhere;
}

.dashboard__start,
.dashboard__status,
.dashboard__health {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.dashboard__section-head h3,
.dashboard__health h3 {
  margin: 0;
  font-size: 0.875rem;
}

.dashboard__section-head {
  align-items: center;
  display: flex;
  gap: 1rem;
  justify-content: space-between;
}

.dashboard__start {
  display: grid;
  gap: 0.75rem;
  padding: 0.9rem 1rem;
}

.dashboard__start-list {
  display: grid;
  gap: 0.5rem;
  list-style: none;
  margin: 0;
  padding: 0;
}

.dashboard__start-list li {
  align-items: center;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  display: grid;
  gap: 1rem;
  grid-template-columns: 1fr auto;
  min-width: 0;
  padding: 0.75rem;
}

.dashboard__start-list p {
  color: var(--text-secondary);
  font-size: 0.8125rem;
  margin: 0.2rem 0 0;
}

.dashboard__start-action {
  white-space: nowrap;
}

/* KPI strip */
.dashboard__metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.625rem;
}

.dashboard__metric {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0.25rem;
  min-width: 0;
  padding: 0.7rem 0.85rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  color: var(--text-primary);
  font: inherit;
  text-align: left;
  cursor: pointer;
  transition:
    border-color 120ms ease,
    background 120ms ease;
}

.dashboard__metric:hover {
  border-color: var(--border-strong);
  background: var(--bg-subtle);
}

.dashboard__metric-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.35rem;
  color: var(--text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
}

.dashboard__metric-arrow {
  flex: none;
  color: var(--text-muted);
  transform: rotate(-90deg);
  transition: transform 120ms ease;
}

.dashboard__metric:hover .dashboard__metric-arrow,
.dashboard__metric:focus-visible .dashboard__metric-arrow {
  color: var(--accent);
  transform: rotate(-90deg) translateY(2px);
}

.dashboard__metric strong {
  font-size: 1.375rem;
  font-weight: 700;
  line-height: 1.2;
  letter-spacing: -0.01em;
  overflow-wrap: anywhere;
}

.dashboard__metric-meta {
  color: var(--text-muted);
  font-size: 0.75rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dashboard__metric-meta--warn {
  color: var(--warn);
}

/* Status bar */
.dashboard__status {
  padding: 0;
}

.dashboard__facts {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 0;
}

.dashboard__fact {
  min-width: 0;
  padding: 0.65rem 1rem;
}

.dashboard__fact + .dashboard__fact {
  border-left: 1px solid var(--border-subtle);
}

.dashboard__facts dt {
  color: var(--text-muted);
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.dashboard__facts dd {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin: 0.2rem 0 0;
  font-size: 0.9375rem;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.dashboard__facts dd strong {
  font-weight: 650;
}

.dashboard__dot {
  flex: none;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: currentColor;
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

/* Configuration checks + project connection */
.dashboard__pair {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0.875rem;
  align-items: start;
}

/* Health strip */
.dashboard__health {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 0.5rem 1.25rem;
  padding: 0.7rem 1rem;
}

.dashboard__checks {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 1.5rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.dashboard__checks li {
  display: flex;
  align-items: flex-start;
  gap: 0.45rem;
  min-width: 0;
  font-size: 0.8125rem;
}

.dashboard__check-body {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 0.1rem 0.45rem;
  min-width: 0;
}

.dashboard__check-body strong {
  font-weight: 600;
  white-space: nowrap;
}

.dashboard__check-meta {
  color: var(--text-muted);
  font-size: 0.75rem;
}

.dashboard__check-dot {
  flex: none;
  margin-top: 0.4em;
  width: 0.45rem;
  height: 0.45rem;
  border-radius: 50%;
  background: var(--text-muted);
}

.dashboard__check-dot--ok {
  background: var(--success);
}

.dashboard__check-dot--warn {
  background: var(--warn);
}

.dashboard__alert {
  grid-column: 1 / -1;
  margin: 0;
  padding: 0.45rem 0.65rem;
  border-radius: var(--radius-sm);
  background: var(--danger-soft);
  color: var(--danger);
  font-size: 0.8125rem;
}

.dashboard__health-ok {
  color: var(--success);
}

.dashboard__health-warn {
  color: var(--warn);
}

.dashboard__health-neutral {
  color: var(--text-primary);
}

@container dashboard (min-width: 62rem) {
  .dashboard__pair {
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
  }
}

@container dashboard (max-width: 44rem) {
  .dashboard__metrics,
  .dashboard__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .dashboard__fact:nth-child(3) {
    border-left: 0;
  }

  .dashboard__fact:nth-child(n + 3) {
    border-top: 1px solid var(--border-subtle);
  }

  .dashboard__health {
    grid-template-columns: minmax(0, 1fr);
  }

  .dashboard__checks {
    flex-direction: column;
  }

  .dashboard__start-list li {
    grid-template-columns: 1fr;
  }

  .dashboard__start-action {
    width: 100%;
  }
}

@container dashboard (max-width: 26rem) {
  .dashboard__metric strong {
    font-size: 1.125rem;
  }

  .dashboard__fact {
    padding: 0.6rem 0.75rem;
  }
}
</style>
