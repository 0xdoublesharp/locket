<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, onUnmounted, ref, watch } from 'vue';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import PolicyEditorForm from './components/PolicyEditorForm.vue';
import ProfileSwitcherView from './views/ProfileSwitcherView.vue';
import RevealModal from './components/RevealModal.vue';
import UnlockModal from './components/UnlockModal.vue';
import { auditHealth, auditRowVerified, unlockTtl, projectStatusMatches } from './dashboard/health';
import { scopedProjectContext, actionAvailability } from './dashboard/context';
import {
  captureSelection,
  withCurrentSelection,
  initialProjectSelection,
} from './profile/selection';
import type { StartHereTarget } from './dashboard/startHere';
import type { DesktopProjectContext, UnlockRequest } from './agent/types';
import {
  copySecret,
  exportBundle,
  importBundle,
  listAudit,
  listDeviceMembers,
  listPolicies,
  listRuntimeSessions,
  listSecrets,
  listVersions,
  lockVault,
  readConfig,
  recoveryRotate,
  desktopListProjects,
  desktopOpenProject,
  desktopInitializeProject,
  desktopImportEnv,
  desktopStartAgent,
  desktopRunPolicy,
  desktopScanProject,
  desktopSavePolicy,
  unlockVault,
  actionError,
  reveal as revealAgent,
  rotateSecret,
  setActiveProfile,
  setSecret,
  writeConfig,
  verifyAudit,
  verifyBundle,
} from './agent/client';
import type { SetSecretRequest, SetSecretResponse } from './agent/client';
import type { PolicyFormMode } from './policy/form';
import { rememberTarget, type ProfileSwitchState } from './profile/switcher';
import type { CommandPolicySnapshotWire } from './agent/types';
import { deviceMemberRow } from './agent/deviceMembers';
import { commandPolicyRow } from './agent/policies';
import { runtimeSessionRow } from './agent/runtimeSessions';
import { secretRow } from './agent/secrets';
import { versionHistoryRow } from './agent/versions';
import { useAgent } from './composables/useAgent';
import { useTray } from './composables/useTray';
import { secretRowsWithDeprecationWarnings } from './secret/deprecationWarnings';
import AuditLog from './views/AuditLog.vue';
import BackupRecovery from './views/BackupRecovery.vue';
import { exportSelectionKey, type BundleAction } from './backup/actions';
import DeviceMemberDirectory from './views/DeviceMemberDirectory.vue';
import ExecutionMonitor from './views/ExecutionMonitor.vue';
import PolicyEditor from './views/PolicyEditor.vue';
import ProjectDashboard from './views/ProjectDashboard.vue';
import ScanResults from './views/ScanResults.vue';
import SecretEditorView from './views/SecretEditorView.vue';
import SecretMetadataList from './views/SecretMetadataList.vue';
import SecretVersionHistory from './views/SecretVersionHistory.vue';
import Settings from './views/Settings.vue';
import TeamInviteView from './views/TeamInviteView.vue';
import type {
  AuditLogRow,
  CommandPolicyRow,
  DeviceMemberRow,
  RuntimeSessionRow,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from './types/views';
import type {
  AgentClientError,
  AgentConfigSettings,
  AuditChainStatus,
  AuditWireRow,
  ListAuditRequest,
  ListDeviceMembersRequest,
  ListPoliciesRequest,
  ListRuntimeSessionsRequest,
  ListSecretsRequest,
  ListVersionsRequest,
  WriteConfigChanges,
} from './agent/types';
import { privacyAlias, privacyLabel } from './utils/privacy';
import { createRequestLifetime } from './utils/requestLifetime';

type ViewKey =
  | 'dashboard'
  | 'secrets'
  | 'secret-editor'
  | 'versions'
  | 'execution'
  | 'devices'
  | 'audit'
  | 'scan'
  | 'policies'
  | 'profiles'
  | 'team'
  | 'recovery'
  | 'settings';

const { status: agentStatus, error, loading, lastSeenAt, connected, refresh } = useAgent();
const selectedProject = ref<DesktopProjectContext | null>(null);
const selectionGeneration = ref(0);
const status = computed(() =>
  projectStatusMatches(agentStatus.value, selectedProject.value, connected.value)
    ? agentStatus.value
    : null,
);
const activeContext = computed(() =>
  scopedProjectContext(agentStatus.value, selectedProject.value, connected.value),
);
const projectConnected = computed(
  () => selectedProject.value !== null || status.value?.project_id != null,
);
const projectPath = ref('');
const knownProjects = ref<DesktopProjectContext[]>([]);
const desktopAvailable = isTauri();
const desktopBusy = ref(false);
const desktopError = ref<string | null>(null);
const desktopNotice = ref<string | null>(null);
const unlockOpen = ref(false);
const unlockBusy = ref(false);
const unlockError = ref<string | null>(null);
const envPath = ref('.env');
const importOverwrite = ref(false);
const importConfirmation = ref('');
const importLiteral = ref(false);
const commandRunning = ref(false);
const commandRunError = ref<string | null>(null);
const commandRunNotice = ref<string | null>(null);
useTray(status, error);

const connectionLabel = computed<string>(() => {
  if (!connected.value) {
    return desktopAvailable ? 'Disconnected' : 'Desktop required';
  }
  if (lastSeenAt.value === null) {
    return 'Connected';
  }
  return `Live · ${formatLastSeen(lastSeenAt.value)}`;
});

const connectionTone = computed<'ok' | 'warn'>(() => (connected.value ? 'ok' : 'warn'));

function formatLastSeen(iso: string): string {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) {
    return 'just now';
  }
  const seconds = Math.max(0, Math.round((Date.now() - parsed) / 1000));
  if (seconds < 5) {
    return 'just now';
  }
  if (seconds < 60) {
    return `${seconds.toString()}s ago`;
  }
  const minutes = Math.round(seconds / 60);
  return `${minutes.toString()}m ago`;
}

const currentView = ref<ViewKey>('dashboard');
const revealModal = ref<InstanceType<typeof RevealModal> | null>(null);
const copyError = ref<string | null>(null);
const revealError = ref<string | null>(null);
const revealRequests = createRequestLifetime();
let unlistenTrayMenu: UnlistenFn | null = null;

type TrayMenuAction =
  | 'open-app'
  | 'lock-vault'
  | 'unlock-vault'
  | 'switch-profile'
  | 'run-policy'
  | 'start-scan'
  | 'reveal-secret'
  | 'copy-secret';

const navGroups: ReadonlyArray<{
  label: string;
  items: ReadonlyArray<{ key: ViewKey; label: string }>;
}> = [
  {
    label: 'Workspace',
    items: [
      { key: 'dashboard', label: 'Project' },
      { key: 'secrets', label: 'Variables' },
      { key: 'policies', label: 'Commands' },
      { key: 'execution', label: 'Activity' },
      { key: 'team', label: 'Team' },
      { key: 'settings', label: 'Settings' },
    ],
  },
];
const secondaryItems = computed<Array<{ key: ViewKey; label: string }>>(() => {
  if (['secrets', 'secret-editor', 'versions'].includes(currentView.value))
    return [
      { key: 'secrets', label: 'Variables' },
      { key: 'secret-editor', label: 'Import or add' },
      ...(selectedSecret.value
        ? [{ key: 'versions' as const, label: 'Selected variable history' }]
        : []),
    ];
  if (['execution', 'audit', 'scan'].includes(currentView.value))
    return [
      { key: 'execution', label: 'Runs' },
      { key: 'audit', label: 'Audit' },
      { key: 'scan', label: 'Scan in terminal' },
    ];
  if (['team', 'devices'].includes(currentView.value))
    return [
      { key: 'team', label: 'Sharing' },
      { key: 'devices', label: 'People and devices' },
    ];
  if (['settings', 'profiles', 'recovery'].includes(currentView.value))
    return [
      { key: 'settings', label: 'Preferences' },
      { key: 'profiles', label: 'Environments' },
      { key: 'recovery', label: 'Backup and recovery' },
    ];
  return [];
});

const lockLabel = computed<string>(() => {
  if (loading.value && status.value === null && error.value === null) {
    return 'Connecting…';
  }
  if (selectedProject.value && !status.value) return 'Unknown';
  if (!connected.value || status.value === null) {
    return 'Unavailable';
  }
  switch (status.value.lock_state) {
    case 'unlocked':
      return 'Unlocked';
    case 'locked':
      return 'Locked';
    case 'unknown':
      return 'Unknown';
    default:
      return 'Unknown';
  }
});

const projectAlias = ref<string | null>(null);
const profileAlias = ref<string | null>(null);

const projectLabel = computed<string>(() =>
  privacyLabel(
    'project',
    selectedProject.value?.project_name ?? status.value?.project_id,
    settings.value.privacyRedactNames,
    projectAlias.value,
  ),
);
const profileLabel = computed<string>(() =>
  privacyLabel(
    'profile',
    selectedProject.value?.profile_name ?? status.value?.profile_name,
    settings.value.privacyRedactNames,
    profileAlias.value,
  ),
);

const secrets = ref<SecretRowMeta[]>([]);
const versions = ref<VersionHistoryRow[]>([]);
const sessions = ref<RuntimeSessionRow[]>([]);
const deviceMembers = ref<DeviceMemberRow[]>([]);
const auditRows = ref<AuditLogRow[]>([]);
const policies = ref<CommandPolicyRow[]>([]);
const rawAuditRows = ref<AuditWireRow[]>([]);
const secretsLoading = ref<boolean>(false);
const secretsError = ref<string | null>(null);
const secretsLastRefreshed = ref<string | undefined>(undefined);
const versionsLoading = ref<boolean>(false);
const versionsError = ref<string | null>(null);
const versionsLastRefreshed = ref<string | undefined>(undefined);
const sessionsLoading = ref<boolean>(false);
const sessionsError = ref<string | null>(null);
const sessionsLastRefreshed = ref<string | undefined>(undefined);
const deviceMembersLoading = ref<boolean>(false);
const deviceMembersError = ref<string | null>(null);
const deviceMembersLastRefreshed = ref<string | undefined>(undefined);
const policiesLoading = ref<boolean>(false);
const policiesError = ref<string | null>(null);
const policiesLastRefreshed = ref<string | undefined>();
const completedSetupContexts = ref<Set<string>>(new Set());
const setupContext = computed(
  () =>
    `${selectedProject.value?.project_id ?? status.value?.project_id ?? ''}:${selectedProject.value?.profile_name ?? status.value?.profile_name ?? ''}`,
);
const setupComplete = computed(() => completedSetupContexts.value.has(setupContext.value));
watch([secrets, policies, sessions], () => {
  if (
    status.value &&
    secretsLastRefreshed.value &&
    policiesLastRefreshed.value &&
    sessionsLastRefreshed.value &&
    secrets.value.length &&
    policies.value.length &&
    sessions.value.length
  ) {
    completedSetupContexts.value = new Set([...completedSetupContexts.value, setupContext.value]);
  }
});
const settingsLoading = ref<boolean>(false);
const settingsError = ref<string | null>(null);
const auditLoading = ref<boolean>(false);
const auditError = ref<string | null>(null);
const auditLastRefreshed = ref<string | undefined>(undefined);
const scanLaunching = ref(false);
const scanError = ref<string | null>(null);
const scanNotice = ref<string | null>(null);
const scanRequests = createRequestLifetime();
const backupBusy = ref<boolean>(false);
const backupNotice = ref<string | null>(null);
const backupError = ref<string | null>(null);
const backupPreviewKey = ref<string | null>(null);
const backupPreviewMessage = ref<string | null>(null);
const auditChainOk = ref<boolean | null>(null);

function accessFor(loaded: boolean, pending: boolean, requestError: string | null) {
  return actionAvailability({
    projectSelected: selectedProject.value !== null,
    connected: connected.value,
    scoped: activeContext.value !== null,
    unlocked: status.value?.lock_state === 'unlocked',
    loaded,
    loading: pending,
    error: requestError,
  });
}
const policyAccess = computed(() =>
  accessFor(!!policiesLastRefreshed.value, policiesLoading.value, policiesError.value),
);
const secretAccess = computed(() =>
  accessFor(!!secretsLastRefreshed.value, secretsLoading.value, secretsError.value),
);
const teamAccess = computed(() =>
  accessFor(!!auditLastRefreshed.value, auditLoading.value, auditError.value),
);

const secretRows = computed<SecretRowMeta[]>(() =>
  secretRowsWithDeprecationWarnings(secrets.value, versions.value, policies.value, nowUnixNanos()),
);

const settings = ref<SettingsState>({
  privacyRedactNames: false,
  unlockTtlSeconds: 900,
  requireUserVerification: false,
  dangerousProfileFlag: false,
  agentVersion: status.value?.agent_version ?? 'unknown',
});

watch(
  [status, () => settings.value.privacyRedactNames],
  ([nextStatus, redactNames]) => {
    const projectId = nextStatus?.project_id ?? null;
    const profileName = nextStatus?.profile_name ?? null;

    projectAlias.value = null;
    profileAlias.value = null;

    if (!redactNames) {
      return;
    }

    if (projectId !== null && projectId.length > 0) {
      void privacyAlias('project', projectId)
        .then((alias) => {
          if (settings.value.privacyRedactNames && status.value?.project_id === projectId) {
            projectAlias.value = alias;
          }
        })
        .catch(() => {});
    }
    if (profileName !== null && profileName.length > 0) {
      void privacyAlias('profile', profileName)
        .then((alias) => {
          if (settings.value.privacyRedactNames && status.value?.profile_name === profileName) {
            profileAlias.value = alias;
          }
        })
        .catch(() => {});
    }
  },
  { immediate: true },
);

function applySettingsPatch(patch: Partial<SettingsState>): void {
  settings.value = { ...settings.value, ...patch };
}

function durationSeconds(value: string | null): number {
  if (value === null) {
    return 0;
  }
  const match = /^(\d+)(ms|s|m|h)?$/.exec(value.trim());
  if (match === null) {
    return 0;
  }
  const amount = Number.parseInt(match[1] ?? '0', 10);
  switch (match[2] ?? 's') {
    case 'ms':
      return Math.ceil(amount / 1000);
    case 'm':
      return amount * 60;
    case 'h':
      return amount * 3600;
    default:
      return amount;
  }
}

function verificationRequired(settings: AgentConfigSettings): boolean {
  return Object.values(settings.user_verification_required_for).some((value) => value);
}

function applyAgentConfig(config: AgentConfigSettings): void {
  settings.value = {
    ...settings.value,
    privacyRedactNames: config.privacy_redact_names,
    unlockTtlSeconds: durationSeconds(config.agent_unlock_ttl),
    requireUserVerification: verificationRequired(config),
    dangerousProfileFlag: config.dangerous_profile?.dangerous ?? false,
    agentVersion: status.value?.agent_version ?? settings.value.agentVersion,
  };
}

function settingsErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Settings request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Settings request failed.';
  }
}

async function refreshSettings(): Promise<void> {
  settingsLoading.value = true;
  settingsError.value = null;
  const currentStatus = status.value;
  const result = await readConfig({
    project_id: currentStatus?.project_id ?? null,
    profile_name: currentStatus?.profile_name ?? null,
  });
  if (result.ok) {
    applyAgentConfig(result.value);
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

async function handleSettingsPatch(patch: Partial<SettingsState>): Promise<void> {
  applySettingsPatch(patch);

  if (!('privacyRedactNames' in patch)) {
    return;
  }
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return;
  }
  const changes: WriteConfigChanges = {
    privacy_redact_names: patch.privacyRedactNames ?? false,
  };
  settingsLoading.value = true;
  settingsError.value = null;
  const result = await writeConfig({
    project_id: projectId,
    profile_name: status.value?.profile_name ?? null,
    changes,
  });
  if (result.ok) {
    applyAgentConfig(result.value.settings);
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

const settingsContextKey = computed<string>(
  () => `${status.value?.project_id ?? ''}:${status.value?.profile_name ?? ''}`,
);

watch(
  status,
  () => {
    settings.value = {
      ...settings.value,
      agentVersion: status.value?.agent_version ?? 'unknown',
    };
  },
  { immediate: true },
);

watch(
  settingsContextKey,
  () => {
    void refreshSettings();
  },
  { immediate: true },
);

function selectView(key: ViewKey): void {
  currentView.value = key;
}

async function handleTrayMenuAction(action: TrayMenuAction): Promise<void> {
  switch (action) {
    case 'open-app':
      currentView.value = 'dashboard';
      break;
    case 'lock-vault':
      {
        invalidateReveal();
        const result = await lockVault();
        if (!result.ok) desktopError.value = actionError(result.error);
      }
      await refresh();
      break;
    case 'unlock-vault':
      openUnlock();
      break;
    case 'switch-profile':
      currentView.value = 'profiles';
      await refresh();
      break;
    case 'run-policy':
      currentView.value = 'policies';
      await refreshPolicies();
      break;
    case 'start-scan':
      currentView.value = 'scan';
      await launchProjectScan();
      break;
    case 'reveal-secret':
      currentView.value = 'secrets';
      await handleRevealSelectedSecret();
      break;
    case 'copy-secret':
      currentView.value = 'secrets';
      await handleCopySelectedSecret();
      break;
    default:
      break;
  }
}

const selectedSecret = ref<SecretRowMeta | null>(null);

function selectSecret(row?: SecretRowMeta): void {
  if (row !== undefined) {
    selectedSecret.value = row;
  }
  currentView.value = 'versions';
}

/** Generic, name-free label for the reveal modal heading. */
function secretLabel(row: SecretRowMeta | null, redactNames: boolean): string {
  if (row === null) {
    return 'Secret';
  }
  if (redactNames) {
    return row.alias ?? 'Secret';
  }
  return row.name;
}

async function pushTraySelection(): Promise<void> {
  if (!isTauri()) {
    return;
  }
  const selection = {
    vault_unlocked: status.value?.lock_state === 'unlocked',
    secret_selected: selectedSecret.value !== null,
  };
  try {
    await invoke<void>('tray_set_selection', { selection });
  } catch {
    // Tray refresh failures are local-only; the next change will retry.
  }
}

async function pushTrayPrivacyContext(): Promise<void> {
  if (!isTauri()) {
    return;
  }
  try {
    await invoke<void>('tray_set_privacy_context', {
      context: {
        project_id: status.value?.project_id ?? null,
        profile_name: status.value?.profile_name ?? null,
        privacy_redact_names: settings.value.privacyRedactNames,
      },
    });
  } catch {
    // Tray tooltip refresh failures are local-only; the next status or
    // settings change retries with the current context.
  }
}

watch(
  [() => status.value?.lock_state, selectedSecret],
  () => {
    void pushTraySelection();
  },
  { immediate: true },
);

watch(
  [
    () => status.value?.project_id,
    () => status.value?.profile_name,
    () => settings.value.privacyRedactNames,
  ],
  () => {
    void pushTrayPrivacyContext();
  },
  { immediate: true },
);

function invalidateReveal(): void {
  revealRequests.invalidate();
  revealModal.value?.scrub();
  revealError.value = null;
}

watch(
  [
    currentView,
    selectedSecret,
    selectionGeneration,
    () => activeContext.value?.root,
    () => activeContext.value?.project_id,
    () => activeContext.value?.profile_id,
    () => activeContext.value?.profile_name,
    () => status.value?.lock_state,
  ],
  invalidateReveal,
  // Invalidate even when a transition is reversed in the same tick. A tray
  // view change also needs to finish before it starts its own reveal request.
  { flush: 'sync' },
);

async function handleRevealSelectedSecret(): Promise<void> {
  invalidateReveal();
  const isCurrent = revealRequests.begin();
  if (!isCurrent()) return;
  const target = selectedSecret.value;
  if (target === null) {
    revealError.value = 'Select a secret in the list before revealing.';
    return;
  }
  const profileId = activeContext.value?.profile_id;
  if (profileId === null || profileId === undefined) {
    revealError.value = 'Active profile unavailable.';
    return;
  }
  const result = await revealAgent({
    secret_name: target.name,
    profile_id: profileId,
  });
  if (!isCurrent()) return;
  if (!result.ok) {
    revealError.value = revealErrorLabel(result.error);
    return;
  }
  revealModal.value?.show({
    secretLabel: secretLabel(target, settings.value.privacyRedactNames),
    value: result.value.value,
    ttlSeconds: result.value.ttl_seconds,
  });
}

function revealErrorLabel(err: AgentClientError): string {
  switch (err.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Reveal request failed.';
    case 'rejected':
      return err.code;
    default:
      return 'Reveal request failed.';
  }
}

async function handleCopySelectedSecret(): Promise<void> {
  copyError.value = null;
  const target = selectedSecret.value;
  if (target === null) {
    copyError.value = 'Select a secret in the list before copying.';
    return;
  }
  const profileId = activeContext.value?.profile_id;
  if (profileId === null || profileId === undefined) {
    copyError.value = 'Active profile unavailable.';
    return;
  }
  const result = await copySecret({
    secret_name: target.name,
    profile_id: profileId,
    project_id: status.value?.project_id ?? undefined,
  });
  if (!result.ok) {
    copyError.value = revealErrorLabel(result.error);
    return;
  }
  if (result.value.kind === 'unsupported') {
    copyError.value = `Clipboard unavailable: ${result.value.unsupported_reason}.`;
  }
}

async function triggerVerify(): Promise<void> {
  await refresh();
  await Promise.all([
    refreshSecrets(),
    refreshVersions(),
    refreshRuntimeSessions(),
    refreshDeviceMembers(),
    refreshPolicies(),
    refreshAuditLog(),
  ]);
  await verifyAuditChain();
}

function nowUnixNanos(): number {
  return Date.now() * 1_000_000;
}

const secretsRequest = computed<ListSecretsRequest | null>(() => {
  const context = activeContext.value;
  if (context === null) return null;
  return {
    project_id: context.project_id,
    profile_id: context.profile_id,
    redact_names: settings.value.privacyRedactNames,
  };
});

const versionsRequest = computed<ListVersionsRequest | null>(() => {
  const context = activeContext.value;
  if (context === null) return null;
  return {
    project_id: context.project_id,
    profile_id: context.profile_id,
    now_unix_nanos: nowUnixNanos(),
    redact_names: settings.value.privacyRedactNames,
  };
});

const runtimeSessionRequest = computed<ListRuntimeSessionsRequest | null>(() => {
  const context = activeContext.value;
  if (context === null) return null;
  return {
    project_id: context.project_id,
    profile_id: context.profile_id,
    privacy_redact_names: settings.value.privacyRedactNames,
  };
});

const policiesRequest = computed<ListPoliciesRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    privacy_redact_names: settings.value.privacyRedactNames,
  };
});

const deviceMembersRequest = computed<ListDeviceMembersRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    redact_names: settings.value.privacyRedactNames,
    include_revoked_devices: true,
  };
});

let secretRefreshSequence = 0;

async function refreshSecrets(): Promise<void> {
  const request = secretsRequest.value;
  const sequence = (secretRefreshSequence += 1);
  if (request === null) {
    secrets.value = [];
    secretsError.value = null;
    secretsLoading.value = false;
    secretsLastRefreshed.value = undefined;
    return;
  }

  secretsLoading.value = true;
  secretsError.value = null;
  const result = await listSecrets(request);
  if (sequence !== secretRefreshSequence) {
    return;
  }
  if (result.ok) {
    secrets.value = result.value.rows.map(secretRow);
    secretsLastRefreshed.value = new Date().toISOString();
  } else {
    secrets.value = [];
    secretsError.value = actionError(result.error);
    secretsLastRefreshed.value = undefined;
  }
  secretsLoading.value = false;
}

watch(secretsRequest, () => {
  selectedSecret.value = null;
  void refreshSecrets();
});

function versionErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Version request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Version request failed.';
  }
}

let versionRefreshSequence = 0;

async function refreshVersions(): Promise<void> {
  const request = versionsRequest.value;
  const sequence = (versionRefreshSequence += 1);
  if (request === null) {
    versions.value = [];
    versionsError.value = null;
    versionsLoading.value = false;
    versionsLastRefreshed.value = undefined;
    return;
  }

  versionsLoading.value = true;
  versionsError.value = null;
  const result = await listVersions({ ...request, now_unix_nanos: nowUnixNanos() });
  if (sequence !== versionRefreshSequence) {
    return;
  }
  if (result.ok) {
    versions.value = result.value.rows.map(versionHistoryRow);
    versionsLastRefreshed.value = new Date().toISOString();
  } else {
    versions.value = [];
    versionsError.value = versionErrorLabel(result.error);
  }
  versionsLoading.value = false;
}

watch(versionsRequest, () => {
  void refreshVersions();
});

let sessionRefreshSequence = 0;

async function refreshRuntimeSessions(): Promise<void> {
  const request = runtimeSessionRequest.value;
  const sequence = (sessionRefreshSequence += 1);
  if (request === null) {
    sessions.value = [];
    sessionsError.value = null;
    sessionsLoading.value = false;
    sessionsLastRefreshed.value = undefined;
    return;
  }

  sessionsLoading.value = true;
  sessionsError.value = null;
  const result = await listRuntimeSessions(request);
  if (sequence !== sessionRefreshSequence) {
    return;
  }
  if (result.ok) {
    sessions.value = result.value.rows.map(runtimeSessionRow);
    sessionsLastRefreshed.value = new Date().toISOString();
  } else {
    sessions.value = [];
    sessionsError.value = actionError(result.error);
    sessionsLastRefreshed.value = undefined;
  }
  sessionsLoading.value = false;
}

watch(runtimeSessionRequest, () => {
  void refreshRuntimeSessions();
});

let policyRefreshSequence = 0;

async function refreshPolicies(): Promise<void> {
  const request = policiesRequest.value;
  const sequence = (policyRefreshSequence += 1);
  if (request === null) {
    policies.value = [];
    policiesError.value = null;
    policiesLoading.value = false;
    policiesLastRefreshed.value = undefined;
    return;
  }

  policiesLoading.value = true;
  policiesError.value = null;
  const result = await listPolicies(request);
  if (sequence !== policyRefreshSequence) {
    return;
  }
  if (result.ok) {
    policies.value = result.value.rows.map(commandPolicyRow);
    policiesLastRefreshed.value = new Date().toISOString();
  } else {
    policies.value = [];
    policiesError.value = actionError(result.error);
    policiesLastRefreshed.value = undefined;
  }
  policiesLoading.value = false;
}

watch(policiesRequest, () => {
  void refreshPolicies();
});

const profileSwitchState = ref<ProfileSwitchState>({
  activeProfile: null,
  activeDangerous: false,
  recentTargets: [],
});
const profileSwitchInProgress = ref<boolean>(false);
const profileSwitchError = ref<string | null>(null);
const profileSwitchLastAt = ref<string | undefined>(undefined);

watch(
  [() => status.value?.profile_name ?? null, () => settings.value.dangerousProfileFlag],
  ([nextProfile, nextDangerous]) => {
    profileSwitchState.value = {
      ...profileSwitchState.value,
      activeProfile: nextProfile,
      activeDangerous: nextDangerous,
    };
  },
  { immediate: true },
);

watch(
  selectedProject,
  () => {
    selectionGeneration.value++;
    profileSwitchInProgress.value = false;
    profileSwitchError.value = null;
  },
  { flush: 'sync' },
);

async function handleProfileSwitch(payload: {
  profileName: string;
  confirmation: string | undefined;
  dangerous: boolean;
}): Promise<void> {
  const captured = captureSelection(selectedProject.value, selectionGeneration.value);
  if (!captured || !activeContext.value || profileSwitchInProgress.value) {
    profileSwitchError.value =
      'Connect and unlock the selected project before switching environments.';
    return;
  }
  invalidateReveal();
  profileSwitchInProgress.value = true;
  profileSwitchError.value = null;
  await withCurrentSelection(
    captured,
    () => captureSelection(selectedProject.value, selectionGeneration.value),
    () =>
      setActiveProfile({
        project_id: captured.projectId,
        profile_name: payload.profileName,
        confirmation: payload.confirmation,
        privacy_redact_names: settings.value.privacyRedactNames,
      }),
    async (result) => {
      profileSwitchInProgress.value = false;
      if (!result.ok) {
        profileSwitchError.value = profileSwitchErrorLabel(result.error);
        return;
      }
      selectedProject.value = {
        ...selectedProject.value!,
        profile_id: result.value.profile_id,
        profile_name: result.value.profile_name,
      };
      profileSwitchState.value = rememberTarget(profileSwitchState.value, payload.profileName);
      profileSwitchLastAt.value = new Date().toISOString();
      await refresh();
    },
  );
}

function profileSwitchErrorLabel(err: AgentClientError): string {
  switch (err.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Profile switch failed.';
    case 'rejected':
      return err.code;
    default:
      return 'Profile switch failed.';
  }
}

const policyFormMode = ref<PolicyFormMode | null>(null);
const policyFormRow = ref<CommandPolicyRow | null>(null);
const policyFormSubmitting = ref<boolean>(false);
const policyFormError = ref<string | null>(null);

function openPolicyCreate(): void {
  if (!policyAccess.value.enabled) return;
  policyFormMode.value = 'create';
  policyFormRow.value = null;
  policyFormError.value = null;
}

function openPolicyEdit(row: CommandPolicyRow): void {
  if (!policyAccess.value.enabled) return;
  policyFormMode.value = 'edit';
  policyFormRow.value = row;
  policyFormError.value = null;
}

function openPolicyDelete(row: CommandPolicyRow): void {
  if (!policyAccess.value.enabled) return;
  policyFormMode.value = 'delete';
  policyFormRow.value = row;
  policyFormError.value = null;
}

function dismissPolicyForm(): void {
  policyFormMode.value = null;
  policyFormRow.value = null;
  policyFormError.value = null;
}

async function submitPolicyForm(payload: {
  mode: PolicyFormMode;
  snapshot: CommandPolicySnapshotWire;
  originalName: string;
  confirmation?: string;
}): Promise<void> {
  const projectId = activeContext.value?.project_id;
  if (!policyAccess.value.enabled || projectId === undefined) {
    policyFormError.value = 'Active project unavailable.';
    return;
  }
  policyFormSubmitting.value = true;
  policyFormError.value = null;
  const result = await desktopSavePolicy({
    project_id: projectId,
    mode: payload.mode,
    original_name: payload.originalName,
    policy: payload.snapshot,
    confirmation: payload.confirmation,
  });
  policyFormSubmitting.value = false;
  if (!result.ok) {
    policyFormError.value = actionError(result.error);
    return;
  }
  dismissPolicyForm();
  await refreshPolicies();
}

function deviceMemberErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Device request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Device request failed.';
  }
}

let deviceMembersRefreshSequence = 0;

async function refreshDeviceMembers(): Promise<void> {
  const request = deviceMembersRequest.value;
  const sequence = (deviceMembersRefreshSequence += 1);
  if (request === null) {
    deviceMembers.value = [];
    deviceMembersError.value = null;
    deviceMembersLoading.value = false;
    deviceMembersLastRefreshed.value = undefined;
    return;
  }

  deviceMembersLoading.value = true;
  deviceMembersError.value = null;
  const result = await listDeviceMembers(request);
  if (sequence !== deviceMembersRefreshSequence) {
    return;
  }
  if (result.ok) {
    deviceMembers.value = result.value.rows.map(deviceMemberRow);
    deviceMembersLastRefreshed.value = new Date().toISOString();
  } else {
    deviceMembers.value = [];
    deviceMembersError.value = deviceMemberErrorLabel(result.error);
  }
  deviceMembersLoading.value = false;
}

watch(deviceMembersRequest, () => {
  void refreshDeviceMembers();
});

const auditRequest = computed<ListAuditRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    profile_id: activeContext.value?.profile_id ?? null,
    action: null,
    status: null,
    limit: 100,
    redact_names: settings.value.privacyRedactNames,
  };
});

function auditStatusLabel(status: string): AuditLogRow['status'] {
  switch (status.toUpperCase()) {
    case 'SUCCESS':
    case 'OK':
      return 'OK';
    case 'DENIED':
      return 'DENIED';
    default:
      return 'FAILED';
  }
}

function auditTimestamp(timestampUnixNanos: number): string {
  return new Date(Math.trunc(timestampUnixNanos / 1_000_000)).toISOString();
}

function auditLogRow(row: AuditWireRow, chainStatus: AuditChainStatus): AuditLogRow {
  const statusLabel = auditStatusLabel(row.status);
  const metadata: Record<string, string | number> = {
    action: row.action,
    status: row.status,
  };
  if (row.command !== null) {
    metadata.command = row.command;
  }
  return {
    sequence: row.sequence,
    action: row.action,
    status: statusLabel,
    timestamp: auditTimestamp(row.timestamp),
    profile: row.profile_id ?? undefined,
    secretName: row.secret_name ?? undefined,
    metadataJson: JSON.stringify(metadata),
    denialReason: statusLabel === 'DENIED' ? row.status : undefined,
    hmacOk: chainStatus.locked ? null : auditRowVerified(chainStatus, row.sequence),
  };
}

let auditRefreshSequence = 0;

async function refreshAuditLog(): Promise<void> {
  const request = auditRequest.value;
  const sequence = (auditRefreshSequence += 1);
  if (request === null) {
    auditRows.value = [];
    rawAuditRows.value = [];
    auditLoading.value = false;
    auditLastRefreshed.value = undefined;
    auditChainOk.value = null;
    return;
  }

  auditLoading.value = true;
  auditError.value = null;
  const result = await listAudit(request);
  if (sequence !== auditRefreshSequence) {
    return;
  }
  if (result.ok) {
    const hmacOk =
      result.value.chain_status.locked || status.value?.lock_state !== 'unlocked'
        ? null
        : result.value.chain_status.hmac_ok;
    auditRows.value = result.value.rows.map((row) => auditLogRow(row, result.value.chain_status));
    rawAuditRows.value = [...result.value.rows];
    auditChainOk.value = hmacOk;
    auditLastRefreshed.value = new Date().toISOString();
  } else {
    auditRows.value = [];
    rawAuditRows.value = [];
    auditError.value = actionError(result.error);
    auditLastRefreshed.value = undefined;
    auditChainOk.value = null;
  }
  auditLoading.value = false;
}

const recentActivityRows = computed(() => {
  const okCount = auditRows.value.filter((row) => row.status === 'OK').length;
  const deniedCount = auditRows.value.filter((row) => row.status === 'DENIED').length;
  const failedCount = auditRows.value.filter(
    (row) => row.status === 'FAILED' || row.hmacOk === false,
  ).length;
  return [
    {
      label: 'OK',
      value: auditLastRefreshed.value ? okCount.toString() : 'Unknown',
      tone: 'neutral',
    },
    {
      label: 'Denied',
      value: auditLastRefreshed.value ? deniedCount.toString() : 'Unknown',
      tone: deniedCount === 0 ? 'neutral' : 'warn',
    },
    {
      label: 'Failed',
      value: auditLastRefreshed.value ? failedCount.toString() : 'Unknown',
      tone: failedCount === 0 ? 'neutral' : 'warn',
    },
    {
      label: 'Audit',
      value: auditHealth(auditChainOk.value).label,
      tone: auditHealth(auditChainOk.value).tone,
    },
  ];
});

async function verifyAuditChain(): Promise<void> {
  const request = auditRequest.value;
  auditChainOk.value = null;
  if (request === null) return;
  const result = await verifyAudit({ project_id: request.project_id });
  if (auditRequest.value?.project_id !== request.project_id) return;
  if (!result.ok) {
    auditChainOk.value = null;
    auditError.value = actionError(result.error);
    return;
  }
  auditChainOk.value = result.value.locked ? null : result.value.hmac_ok;
  auditLastRefreshed.value = new Date().toISOString();
}

watch(auditRequest, () => {
  void refreshAuditLog();
});

watch(
  [selectionGeneration, profileSwitchInProgress],
  () => {
    scanRequests.invalidate();
    scanLaunching.value = false;
    scanError.value = null;
    scanNotice.value = null;
  },
  { flush: 'sync' },
);

async function launchProjectScan(): Promise<void> {
  if (scanLaunching.value || desktopBusy.value || profileSwitchInProgress.value) return;
  scanError.value = null;
  scanNotice.value = null;
  const projectId = selectedProject.value?.project_id;
  if (!projectId) {
    scanError.value = 'Connect a project before opening a scan in your terminal.';
    return;
  }
  const isCurrent = scanRequests.begin();
  if (!isCurrent()) return;
  scanLaunching.value = true;
  const result = await desktopScanProject({ project_id: projectId });
  if (!isCurrent()) return;
  scanLaunching.value = false;
  if (!result.ok) scanError.value = actionError(result.error);
  else if (!result.value.launched) {
    scanError.value =
      'The terminal did not launch. Check the desktop terminal configuration and retry.';
  } else {
    scanNotice.value =
      'Opened in your terminal. Complete any unlock or approval there, then check the scan results there.';
  }
}

function backupErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Backup request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Backup request failed.';
  }
}

async function triggerBackupAction(action: BundleAction): Promise<void> {
  backupBusy.value = true;
  backupNotice.value = null;
  backupError.value = null;
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    backupError.value = 'Active project unavailable.';
    backupBusy.value = false;
    return;
  }

  switch (action.kind) {
    case 'export': {
      if (
        !action.request.previewOnly &&
        backupPreviewKey.value !== exportSelectionKey(action.request)
      ) {
        backupError.value = 'Preview the current export scope before exporting.';
        backupBusy.value = false;
        return;
      }
      const result = await exportBundle({
        project_id: projectId,
        profile_id: activeContext.value?.profile_id ?? null,
        recipient_descriptor: action.request.recipientDescriptor,
        scope: action.request.scope,
        include_audit: action.request.includeAudit,
        output_path: action.request.outputPath || null,
        include_personal: action.request.includePersonal,
        include_history: action.request.includeHistory,
        preview_only: action.request.previewOnly,
      });
      if (result.ok) {
        if (action.request.previewOnly && result.value.status === 'preview') {
          backupPreviewKey.value = exportSelectionKey(action.request);
          backupPreviewMessage.value = result.value.message;
        }
        backupNotice.value = `${result.value.status}: ${result.value.message}`;
        await refresh();
      } else {
        backupError.value = backupErrorLabel(result.error);
      }
      break;
    }
    case 'import': {
      const result = await importBundle({
        project_id: projectId,
        bundle_path: action.request.bundlePath,
        include_audit: action.request.includeAudit,
        conflict_mode: action.request.conflictMode,
      });
      if (result.ok) {
        backupNotice.value = `${result.value.status}: ${result.value.message}`;
        await refresh();
      } else {
        backupError.value = backupErrorLabel(result.error);
      }
      break;
    }
    case 'verify': {
      const result = await verifyBundle({
        bundle_path: action.request.bundlePath,
        require_decryptable: action.request.requireDecryptable,
      });
      if (result.ok) {
        backupNotice.value = result.value.message;
        await refresh();
      } else {
        backupError.value = backupErrorLabel(result.error);
      }
      break;
    }
    case 'rotate': {
      const result = await recoveryRotate({
        project_id: projectId,
        verification: action.request.verification,
        acknowledged_one_time_display: action.request.acknowledgedOneTimeDisplay,
        clear_after_display: action.request.clearAfterDisplay,
      });
      if (result.ok) {
        backupNotice.value = `${result.value.status}: ${result.value.message}`;
        await refresh();
      } else {
        backupError.value = backupErrorLabel(result.error);
      }
      break;
    }
    default:
      break;
  }
  backupBusy.value = false;
}

async function handleSetSecret(
  payload: SetSecretRequest,
): Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }> {
  const result = await setSecret(payload);
  if (result.ok) {
    await refreshSecrets();
  }
  return result;
}

async function handleRotateSecret(
  payload: SetSecretRequest,
): Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }> {
  const result = await rotateSecret(payload);
  if (result.ok) {
    await refreshSecrets();
    await refreshVersions();
  }
  return result;
}

async function handleEditorReveal(row: SecretRowMeta): Promise<void> {
  selectedSecret.value = row;
  await handleRevealSelectedSecret();
}

async function refreshProjectConnections(): Promise<void> {
  const generation = selectionGeneration.value;
  const result = await desktopListProjects();
  if (result.ok) {
    knownProjects.value = result.value;
    if (generation !== selectionGeneration.value) return;
    const initial = initialProjectSelection(result.value, selectedProject.value);
    if (!selectedProject.value && initial) {
      await connectProject(false, initial.root);
    }
  } else if (generation === selectionGeneration.value && desktopAvailable)
    desktopError.value = actionError(result.error);
}

async function connectProject(initialize = false, path = projectPath.value): Promise<void> {
  if (desktopBusy.value || !path.trim()) return;
  selectionGeneration.value++;
  profileSwitchInProgress.value = false;
  profileSwitchError.value = null;
  desktopBusy.value = true;
  desktopError.value = null;
  desktopNotice.value = null;
  const result = initialize
    ? await desktopInitializeProject({ path: path.trim() })
    : await desktopOpenProject({ path: path.trim() });
  if (result.ok) {
    selectedProject.value = result.value;
    selectedSecret.value = null;
    unlockOpen.value = false;
    projectPath.value = result.value.root;
    desktopNotice.value = `Connected to ${result.value.project_name}.`;
    await refreshProjectConnections();
    await refresh();
  } else desktopError.value = actionError(result.error);
  desktopBusy.value = false;
}
async function startAgent(): Promise<void> {
  if (desktopBusy.value) return;
  desktopBusy.value = true;
  desktopError.value = null;
  const result = await desktopStartAgent({
    project_id: selectedProject.value?.project_id ?? status.value?.project_id ?? undefined,
  });
  if (!result.ok) desktopError.value = actionError(result.error);
  else {
    desktopNotice.value = 'Agent started. Refreshing connection…';
    await refresh();
  }
  desktopBusy.value = false;
}
function openUnlock(): void {
  unlockError.value = null;
  if (!projectConnected.value) {
    currentView.value = 'dashboard';
    desktopError.value = 'Connect a project before unlocking.';
    return;
  }
  unlockOpen.value = true;
}
async function handleUnlock(source: UnlockRequest['source']): Promise<void> {
  const projectId = selectedProject.value?.project_id ?? status.value?.project_id;
  if (!projectId || unlockBusy.value) return;
  unlockBusy.value = true;
  unlockError.value = null;
  const profileId = selectedProject.value?.profile_id;
  const result = await unlockVault({
    project_id: projectId,
    ttl_seconds: unlockTtl(settings.value.unlockTtlSeconds),
    source,
    ...(profileId ? { audit: { profile_id: profileId } } : {}),
  });
  if (source.kind === 'passphrase') source.passphrase = '';
  if (result.ok) {
    unlockOpen.value = false;
    await refresh();
    await triggerVerify();
  } else unlockError.value = actionError(result.error);
  unlockBusy.value = false;
}
async function importEnv(): Promise<void> {
  const projectId = selectedProject.value?.project_id ?? status.value?.project_id;
  if (!secretAccess.value.enabled || !projectId || desktopBusy.value || !envPath.value.trim())
    return;
  desktopBusy.value = true;
  desktopError.value = null;
  desktopNotice.value = null;
  const result = await desktopImportEnv({
    project_id: projectId,
    path: envPath.value.trim(),
    overwrite: importOverwrite.value,
    literal: importLiteral.value,
    confirmation: importConfirmation.value || undefined,
  });
  if (!result.ok) desktopError.value = actionError(result.error);
  else {
    desktopNotice.value = result.value.summary;
    importConfirmation.value = '';
    await refreshSecrets();
  }
  desktopBusy.value = false;
}
async function runCommand(row: CommandPolicyRow): Promise<void> {
  const projectId = activeContext.value?.project_id;
  if (!policyAccess.value.enabled || !projectId || commandRunning.value) return;
  commandRunning.value = true;
  commandRunError.value = null;
  commandRunNotice.value = null;
  const result = await desktopRunPolicy({ project_id: projectId, policy_name: row.name });
  if (!result.ok) commandRunError.value = actionError(result.error);
  else if (!result.value.launched)
    commandRunError.value =
      'The terminal did not launch. Check the desktop terminal configuration and retry.';
  else {
    commandRunNotice.value = 'Opened in your terminal. Complete any approval there.';
    await refreshRuntimeSessions();
  }
  commandRunning.value = false;
}
function handleNextAction(target: StartHereTarget): void {
  if (target === 'connect') {
    document.getElementById('project-path')?.focus();
    return;
  }
  if (target === 'start-agent') {
    void startAgent();
    return;
  }
  if (target === 'unlock') {
    openUnlock();
    return;
  }
  if (target === 'refresh') {
    triggerVerify();
    return;
  }
  currentView.value = target;
  if (target === 'policies' && policiesLastRefreshed.value && policies.value.length === 0)
    openPolicyCreate();
}
watch(
  () =>
    `${status.value?.project_id ?? ''}:${status.value?.profile_name ?? ''}:${status.value?.lock_state ?? ''}`,
  () => {
    auditChainOk.value = null;
    auditLastRefreshed.value = undefined;
    auditError.value = null;
    backupPreviewKey.value = null;
    backupPreviewMessage.value = null;
  },
);

onMounted(() => {
  void refreshProjectConnections();
  void listen<TrayMenuAction>('tray-menu-action', (event) => {
    void handleTrayMenuAction(event.payload);
  })
    .then((unlisten) => {
      unlistenTrayMenu = unlisten;
    })
    .catch(() => {});
});

onBeforeUnmount(() => {
  scanRequests.dispose();
  scanLaunching.value = false;
  scanError.value = null;
  scanNotice.value = null;
  revealRequests.dispose();
  revealModal.value?.scrub('component-unmount');
  revealError.value = null;
});

onUnmounted(() => {
  unlistenTrayMenu?.();
  unlistenTrayMenu = null;
});
</script>

<template>
  <div class="shell">
    <aside class="shell__nav" aria-label="Primary navigation">
      <div class="shell__brand">
        <h1>Locket</h1>
        <dl class="shell__status">
          <dt>Vault</dt>
          <dd>{{ lockLabel }}</dd>
          <dt>Project</dt>
          <dd>{{ projectLabel }}</dd>
          <dt>Environment</dt>
          <dd>{{ profileLabel }}</dd>
          <dt>Agent</dt>
          <dd>
            <span
              :class="`shell__connection shell__connection--${connectionTone}`"
              :data-connected="connected ? 'true' : 'false'"
              role="status"
              aria-live="polite"
              >{{ connectionLabel }}</span
            >
          </dd>
        </dl>
        <section class="shell__activity" aria-label="Recent activity">
          <div class="shell__activity-head">
            <span>Recent</span>
            <span v-if="auditLoading">Loading</span>
            <span v-else-if="auditError">{{ auditError }}</span>
            <span v-else-if="auditLastRefreshed">Updated</span>
          </div>
          <dl>
            <div v-for="row in recentActivityRows" :key="row.label">
              <dt>{{ row.label }}</dt>
              <dd :class="`shell__activity-value shell__activity-value--${row.tone}`">
                {{ row.value }}
              </dd>
            </div>
          </dl>
        </section>
      </div>

      <nav>
        <div v-for="group in navGroups" :key="group.label" class="shell__nav-group">
          <span class="shell__nav-group-label">{{ group.label }}</span>
          <ul>
            <li v-for="item in group.items" :key="item.key">
              <button
                type="button"
                :class="[
                  'shell__nav-item',
                  { 'shell__nav-item--active': currentView === item.key },
                ]"
                :aria-current="currentView === item.key ? 'page' : undefined"
                @click="selectView(item.key)"
              >
                {{ item.label }}
              </button>
            </li>
          </ul>
        </div>
      </nav>
    </aside>

    <main class="shell__main">
      <AgentUnavailableBanner v-if="error" :error="error" />
      <p
        v-if="connected && agentStatus && !agentStatus.session_monitoring?.startsWith('active:')"
        role="status"
        class="shell__notice"
        data-testid="session-lock-warning"
      >
        Automatic locking on screen lock or sleep is unavailable. Lock the vault before leaving this
        device.
      </p>
      <p v-if="!desktopAvailable" class="shell__notice">
        Browser preview is disconnected. Open the Locket desktop app to connect projects, unlock,
        import values, and run commands.
      </p>
      <div class="shell__toolbar" aria-label="Vault actions">
        <button
          v-if="!connected"
          type="button"
          :disabled="!desktopAvailable || desktopBusy"
          @click="startAgent"
        >
          {{ desktopBusy ? 'Starting…' : 'Start agent' }}
        </button>
        <button
          v-if="lockLabel !== 'Unlocked' && projectConnected"
          type="button"
          :disabled="!desktopAvailable || unlockBusy"
          @click="openUnlock"
        >
          Unlock
        </button>
      </div>
      <nav v-if="secondaryItems.length" class="shell__toolbar" aria-label="Section navigation">
        <button
          v-for="item in secondaryItems"
          :key="item.key"
          type="button"
          :aria-current="currentView === item.key ? 'page' : undefined"
          @click="selectView(item.key)"
        >
          {{ item.label }}
        </button>
      </nav>
      <section
        v-if="currentView === 'dashboard'"
        class="shell__panel"
        aria-labelledby="connect-heading"
      >
        <h2 id="connect-heading">Project connection</h2>
        <p>Open a folder with locket.toml, or initialize a project in an existing folder.</p>
        <form class="shell__toolbar" @submit.prevent="connectProject(false)">
          <label
            >Project folder
            <input
              id="project-path"
              v-model="projectPath"
              type="text"
              placeholder="/path/to/project"
              autocomplete="off"
              :disabled="desktopBusy || !desktopAvailable"
          /></label>
          <button type="submit" :disabled="desktopBusy || !desktopAvailable || !projectPath.trim()">
            Open project
          </button>
          <button
            type="button"
            :disabled="desktopBusy || !desktopAvailable || !projectPath.trim()"
            @click="connectProject(true)"
          >
            Initialize project
          </button>
        </form>
        <div v-if="knownProjects.length" class="shell__toolbar">
          <span>Known projects</span
          ><button
            v-for="project in knownProjects"
            :key="project.root"
            type="button"
            :disabled="desktopBusy"
            @click="connectProject(false, project.root)"
          >
            {{ settings.privacyRedactNames ? 'Project' : project.project_name }}
          </button>
        </div>
      </section>
      <section
        v-if="currentView === 'secret-editor'"
        class="shell__panel"
        aria-labelledby="import-heading"
      >
        <h2 id="import-heading">Import an env file</h2>
        <p v-if="secretAccess.guidance" role="status">{{ secretAccess.guidance }}</p>
        <form @submit.prevent="importEnv">
          <label
            >File path
            <input v-model="envPath" type="text" autocomplete="off" :disabled="desktopBusy"
          /></label>
          <p>Paths are relative to the connected project. The original file remains in place.</p>
          <details>
            <summary>Import options</summary>
            <label
              ><input v-model="importOverwrite" type="checkbox" /> Replace existing values</label
            ><label
              ><input v-model="importLiteral" type="checkbox" /> Keep expansion syntax as literal
              text</label
            >
          </details>
          <label v-if="importOverwrite && settings.dangerousProfileFlag">
            Type {{ activeContext?.profile_name }} to confirm replacement in this environment
            <input
              v-model="importConfirmation"
              type="text"
              autocomplete="off"
              :disabled="desktopBusy"
            />
          </label>
          <button
            type="submit"
            :disabled="
              !desktopAvailable ||
              desktopBusy ||
              !secretAccess.enabled ||
              !envPath.trim() ||
              (importOverwrite &&
                settings.dangerousProfileFlag &&
                importConfirmation !== activeContext?.profile_name)
            "
          >
            {{ desktopBusy ? 'Importing…' : 'Import variables' }}
          </button>
        </form>
      </section>
      <p v-if="desktopError" role="alert" class="shell__notice">{{ desktopError }}</p>
      <p v-if="desktopNotice" role="status" class="shell__notice">{{ desktopNotice }}</p>

      <ProjectDashboard
        v-if="currentView === 'dashboard'"
        :privacy-mode="settings.privacyRedactNames"
        :project-id="activeContext?.project_id"
        :profile-id="activeContext?.profile_id"
        :lock-label="lockLabel"
        :project-label="projectLabel"
        :profile-label="profileLabel"
        :loading="loading"
        :project-connected="projectConnected"
        :setup-complete="setupComplete"
        :connected="connected"
        :secrets-loaded="!!secretsLastRefreshed && !secretsError"
        :policies-loaded="!!policiesLastRefreshed && !policiesError"
        :audit-error="auditError"
        :audit-last-refreshed="auditLastRefreshed"
        :scan-locked="false"
        :sessions-last-refreshed="sessionsLastRefreshed"
        :secrets="secrets"
        :versions="versions"
        :sessions="sessions"
        :audit-rows="auditRows"
        :findings="[]"
        :policies="policies"
        :settings="settings"
        :audit-chain-ok="auditChainOk"
        @action="handleNextAction"
        @navigate="selectView"
        @refresh="triggerVerify"
      />

      <SecretMetadataList
        v-else-if="currentView === 'secrets'"
        :rows="secretRows"
        :privacy-mode="settings.privacyRedactNames"
        :loading="secretsLoading"
        :error-message="secretsError"
        :last-refreshed-at="secretsLastRefreshed"
        :metadata-loaded="secretAccess.enabled"
        :action-guidance="secretAccess.guidance"
        @select="selectSecret"
        @refresh="refreshSecrets"
      />

      <SecretEditorView
        v-else-if="currentView === 'secret-editor'"
        :rows="secretRows"
        :privacy-mode="settings.privacyRedactNames"
        :loading="secretsLoading"
        :error-message="secretsError"
        :last-refreshed-at="secretsLastRefreshed"
        :metadata-loaded="secretAccess.enabled"
        :action-guidance="secretAccess.guidance"
        :project-id="activeContext?.project_id"
        :profile-id="activeContext?.profile_id"
        :on-set-secret="handleSetSecret"
        :on-rotate-secret="handleRotateSecret"
        @refresh="refreshSecrets"
        @reveal="handleEditorReveal"
      />

      <SecretVersionHistory
        v-else-if="currentView === 'versions'"
        :rows="versions.filter((row) => row.secretName === selectedSecret?.name)"
        :secret-label="secretLabel(selectedSecret, settings.privacyRedactNames)"
        :loading="versionsLoading"
        :error-message="versionsError"
        :last-refreshed-at="versionsLastRefreshed"
        @refresh="refreshVersions"
      />

      <ExecutionMonitor
        v-else-if="currentView === 'execution'"
        :rows="sessions"
        :privacy-mode="settings.privacyRedactNames"
        :loading="sessionsLoading"
        :error-message="sessionsError"
        :last-refreshed-at="sessionsLastRefreshed"
        @refresh="refreshRuntimeSessions"
      />

      <DeviceMemberDirectory
        v-else-if="currentView === 'devices'"
        :rows="deviceMembers"
        :privacy-mode="settings.privacyRedactNames"
        :loading="deviceMembersLoading"
        :error-message="deviceMembersError"
        :last-refreshed-at="deviceMembersLastRefreshed"
        @refresh="refreshDeviceMembers"
      />

      <AuditLog
        v-else-if="currentView === 'audit'"
        :rows="auditRows"
        :privacy-mode="settings.privacyRedactNames"
        :chain-ok="auditChainOk"
        :loading="auditLoading"
        :error-message="auditError"
        :last-checked-at="auditLastRefreshed"
        @verify="triggerVerify"
      />

      <ScanResults
        v-else-if="currentView === 'scan'"
        :actions-enabled="
          desktopAvailable && !!selectedProject && !desktopBusy && !profileSwitchInProgress
        "
        :launching="scanLaunching"
        :error-message="scanError"
        :launch-notice="scanNotice"
        @scan="launchProjectScan"
      />

      <PolicyEditor
        v-else-if="currentView === 'policies'"
        :project-id="activeContext?.project_id"
        :profile-id="activeContext?.profile_id"
        :rows="policies"
        :privacy-mode="settings.privacyRedactNames"
        :loading="policiesLoading || loading"
        :error-message="policiesError"
        :actions-enabled="policyAccess.enabled"
        :metadata-loaded="policyAccess.enabled"
        :action-guidance="policyAccess.guidance"
        :running="commandRunning"
        :run-error="commandRunError"
        :run-notice="commandRunNotice"
        @run="runCommand"
        @refresh="refreshPolicies"
        @create="openPolicyCreate"
        @edit="openPolicyEdit"
        @delete="openPolicyDelete"
      />

      <ProfileSwitcherView
        v-else-if="currentView === 'profiles'"
        :state="profileSwitchState"
        :privacy-mode="settings.privacyRedactNames"
        :switching="profileSwitchInProgress"
        :error-message="profileSwitchError"
        :last-switched-at="profileSwitchLastAt"
        @switch="handleProfileSwitch"
      />

      <TeamInviteView
        v-else-if="currentView === 'team'"
        :project-id="activeContext?.project_id"
        :privacy-mode="settings.privacyRedactNames"
        :audit-rows="rawAuditRows"
        :dangerous-profiles="settings.dangerousProfileFlag ? (status?.profile_name ?? '') : ''"
        :require-accept-user-verification="settings.requireUserVerification"
        :loading="auditLoading"
        :error-message="auditError"
        :last-refreshed-at="auditLastRefreshed"
        :metadata-loaded="teamAccess.enabled"
        :action-guidance="teamAccess.guidance"
        @refresh="refreshAuditLog"
      />

      <template v-else-if="currentView === 'recovery'">
        <BackupRecovery
          :busy="backupBusy"
          :preview-key="backupPreviewKey"
          :preview-message="backupPreviewMessage"
          @action="triggerBackupAction"
        />
        <p v-if="backupBusy" class="shell__notice">Backup action running…</p>
        <p v-if="backupNotice" class="shell__notice">{{ backupNotice }}</p>
        <p v-if="backupError" role="alert" class="shell__notice">{{ backupError }}</p>
      </template>

      <Settings
        v-else-if="currentView === 'settings'"
        :state="settings"
        :loading="settingsLoading"
        :error-message="settingsError"
        @update="handleSettingsPatch"
      />

      <p v-if="revealError" role="alert" class="shell__notice">{{ revealError }}</p>
      <p v-if="copyError" role="alert" class="shell__notice">{{ copyError }}</p>
    </main>

    <RevealModal ref="revealModal" @invalidate="invalidateReveal" />
    <UnlockModal
      v-if="unlockOpen"
      :project-label="projectLabel"
      :busy="unlockBusy"
      :error-message="unlockError"
      @submit="handleUnlock"
      @dismiss="unlockOpen = false"
    />
    <PolicyEditorForm
      v-if="policyFormMode !== null && policyAccess.enabled"
      :mode="policyFormMode"
      :row="policyFormRow"
      :project-id="status?.project_id ?? ''"
      :dangerous-profile="settings.dangerousProfileFlag"
      :profile-label="status?.profile_name ?? profileLabel"
      :submitting="policyFormSubmitting"
      :error-message="policyFormError"
      @submit="submitPolicyForm"
      @dismiss="dismissPolicyForm"
    />
  </div>
</template>

<style>
:root {
  color-scheme: light dark;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

body,
html,
#app {
  margin: 0;
  height: 100vh;
  background: #0f1115;
  color: #e6e8ec;
}

.shell {
  display: grid;
  grid-template-columns: 220px 1fr;
  min-height: 100vh;
}

.shell__nav {
  background: #0b0d11;
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  padding: 1.25rem 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.shell__brand h1 {
  margin: 0 0 0.875rem;
  font-size: 1rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #f8d77a;
}

.shell__status {
  margin: 0;
  font-size: 0.75rem;
  display: grid;
  grid-template-columns: auto 1fr;
  column-gap: 0.5rem;
  row-gap: 0.25rem;
  color: #9aa3b2;
}

.shell__status dt {
  font-weight: 500;
}

.shell__status dd {
  margin: 0;
  color: #e6e8ec;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell__connection {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.0625rem 0.375rem;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.shell__connection::before {
  content: '';
  width: 0.4rem;
  height: 0.4rem;
  border-radius: 50%;
  background: currentColor;
}

.shell__connection--ok {
  color: #8fd19e;
  background: rgba(143, 209, 158, 0.12);
}

.shell__connection--warn {
  color: #f2b879;
  background: rgba(242, 184, 121, 0.14);
}

.shell__activity {
  margin-top: 1rem;
  padding-top: 0.875rem;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.shell__activity-head {
  display: flex;
  justify-content: space-between;
  gap: 0.5rem;
  font-size: 0.7rem;
  color: #9aa3b2;
}

.shell__activity dl {
  margin: 0.625rem 0 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem;
}

.shell__activity div {
  min-width: 0;
}

.shell__activity dt {
  font-size: 0.68rem;
  color: #9aa3b2;
}

.shell__activity dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
  font-weight: 650;
}

.shell__activity-value--ok {
  color: #8fd19e;
}

.shell__activity-value--warn {
  color: #f2b879;
}

.shell__activity-value--neutral {
  color: #e6e8ec;
}

.shell__nav nav {
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}

.shell__nav nav ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
}

.shell__nav-group {
  display: grid;
  gap: 0.25rem;
}

.shell__nav-group-label {
  color: #747d8c;
  display: block;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  padding: 0 0.625rem;
  text-transform: uppercase;
}

.shell__nav-item {
  width: 100%;
  text-align: left;
  background: transparent;
  border: 0;
  padding: 0.5rem 0.625rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
  color: #c5cbd6;
  cursor: pointer;
}

.shell__nav-item:hover {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
}

.shell__nav-item:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.shell__nav-item--active {
  background: rgba(248, 215, 122, 0.12);
  color: #f8d77a;
}

.shell__main {
  padding: 1.5rem 2rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  overflow: auto;
}

.shell__toolbar {
  display: flex;
  align-items: end;
  gap: 0.65rem;
  flex-wrap: wrap;
}
.shell__panel {
  background: #161a22;
  border: 1px solid #303744;
  border-radius: 0.5rem;
  padding: 1.1rem;
}
.shell__panel h2 {
  font-size: 1rem;
  margin-top: 0;
}
.shell__panel p {
  color: #aeb7c6;
  font-size: 0.9rem;
}
.shell__panel label {
  display: inline-flex;
  flex-direction: column;
  gap: 0.4rem;
  margin: 0.4rem 0.7rem 0.4rem 0;
}
.shell__panel input[type='text'] {
  min-width: min(25rem, 60vw);
}
.shell__main input[type='text'],
.shell__toolbar button,
.shell__panel button {
  background: #10141c;
  color: #e6e8ec;
  border: 1px solid #465064;
  border-radius: 0.35rem;
  padding: 0.55rem 0.75rem;
  font: inherit;
}
.shell__main button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.shell__toolbar button[aria-current='page'] {
  border-color: #f8d77a;
  color: #f8d77a;
}
.shell__toolbar:empty {
  display: none;
}
@media (max-width: 760px) {
  .shell {
    grid-template-columns: 160px minmax(0, 1fr);
  }
  .shell__main {
    padding: 1rem;
  }
}
.shell__notice {
  margin: 0;
  padding: 0.5rem 0.75rem;
  border: 1px solid rgba(248, 215, 122, 0.32);
  background: rgba(248, 215, 122, 0.08);
  color: #f8d77a;
  border-radius: 0.375rem;
  font-size: 0.85rem;
}
</style>
