<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, onUnmounted, ref, watch } from 'vue';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import AppIcon from './components/AppIcon.vue';
import { formatTime } from './utils/formatTime';
import { shortenProjectPath } from './utils/projectPath';
import PathBrowse from './components/PathBrowse.vue';
import CommandPalette from './components/CommandPalette.vue';
import CopyReference from './components/CopyReference.vue';
import DiscoverSecrets from './views/DiscoverSecrets.vue';
import { secretReference } from './secret/reference';
import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import PolicyEditorForm from './components/PolicyEditorForm.vue';
import ProfileSwitcherView from './views/ProfileSwitcherView.vue';
import RevealModal from './components/RevealModal.vue';
import UnlockModal from './components/UnlockModal.vue';
import {
  auditHealth,
  auditRowVerified,
  configuredDurationSeconds,
  unlockTtl,
  projectStatusMatches,
} from './dashboard/health';
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
  listProjects,
  listRuntimeSessions,
  listSecrets,
  listVersions,
  lockVault,
  readConfig,
  recoveryRotate,
  desktopActionsAvailable,
  desktopCopyTextPlain,
  previewParams,
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
  AppIconName,
  AuditLogRow,
  CommandPolicyRow,
  DeviceMemberRow,
  RuntimeSessionRow,
  PaletteAction,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from './types/views';
import type {
  AgentClientError,
  AgentConfigSettings,
  DiscoveredSecretWire,
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
  | 'discover'
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
const activeProjectFolder = computed(() =>
  Boolean(selectedProject.value && projectPath.value.trim() === selectedProject.value.root),
);
const knownProjects = ref<DesktopProjectContext[]>([]);
const desktopAvailable = desktopActionsAvailable();
const desktopBusy = ref(false);
const desktopError = ref<string | null>(null);
const desktopNotice = ref<string | null>(null);
let desktopNoticeTimer: ReturnType<typeof setTimeout> | undefined;
watch(desktopNotice, (message) => {
  clearTimeout(desktopNoticeTimer);
  if (message)
    desktopNoticeTimer = setTimeout(() => {
      desktopNotice.value = null;
    }, 6000);
});
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

const agentOnline = computed(
  () => connected.value && !error.value && !isAgentUnavailable(secretsLoadError.value),
);
const connectionLabel = computed(() => {
  if (agentOnline.value) return 'Live';
  if (!desktopAvailable) return 'Desktop required';
  if (loading.value && !error.value && !secretsLoadError.value) return 'Connecting…';
  return 'Offline';
});

function isAgentUnavailable(error: AgentClientError | null): boolean {
  return (
    error?.kind === 'unavailable' ||
    (error?.kind === 'rejected' && error.code === 'AgentUnavailable')
  );
}

const previewViews: ViewKey[] = [
  'dashboard',
  'secrets',
  'discover',
  'secret-editor',
  'policies',
  'execution',
  'audit',
  'team',
  'recovery',
  'settings',
];
const currentView = ref<ViewKey>(
  previewViews.find((view) => view === previewParams?.get('view')) ?? 'dashboard',
);
const paletteOpen = ref(previewParams?.get('modal') === 'palette');
const paletteMessage = ref('');
const metadataClipboardRequests = createRequestLifetime();
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

const primaryItems: ReadonlyArray<{ key: ViewKey; label: string; icon: AppIconName }> = [
  { key: 'dashboard', label: 'Project', icon: 'folder' },
  { key: 'secrets', label: 'Variables', icon: 'key' },
  { key: 'policies', label: 'Commands', icon: 'terminal' },
  { key: 'execution', label: 'Activity', icon: 'activity' },
  { key: 'team', label: 'Team', icon: 'users' },
  { key: 'settings', label: 'Settings', icon: 'settings' },
];
const overflowItems = primaryItems.slice(3);
const moreOpen = ref(false);
const moreTrigger = ref<HTMLButtonElement | null>(null);
const secondaryItems = computed<Array<{ key: ViewKey; label: string }>>(() => {
  if (['secrets', 'discover', 'secret-editor', 'versions'].includes(currentView.value))
    return [
      { key: 'secrets', label: 'Variables' },
      { key: 'discover', label: 'Discover' },
      { key: 'secret-editor', label: 'Import or add' },
      ...(selectedSecret.value ? [{ key: 'versions' as const, label: 'Variable history' }] : []),
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
const overflowActive = computed(() =>
  overflowItems.find(
    ({ key }) => currentView.value === key || secondaryItems.value.some((item) => item.key === key),
  ),
);

function closeMore(restoreFocus = false): void {
  if (!moreOpen.value) return;
  moreOpen.value = false;
  if (restoreFocus) moreTrigger.value?.focus();
}

function onMoreFocusout(event: FocusEvent): void {
  if (
    event.relatedTarget &&
    !(event.currentTarget as HTMLElement).contains(event.relatedTarget as Node)
  ) {
    closeMore();
  }
}

function onMorePointerdown(event: PointerEvent): void {
  if (moreOpen.value && !moreTrigger.value?.parentElement?.contains(event.target as Node)) {
    closeMore();
  }
}

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
const secretsLoadError = ref<AgentClientError | null>(null);
const secretsError = computed(() =>
  secretsLoadError.value ? actionError(secretsLoadError.value) : null,
);
const variableViewError = computed(() => error.value ?? secretsLoadError.value);
const shellAgentError = computed(
  () => error.value ?? (isAgentUnavailable(secretsLoadError.value) ? secretsLoadError.value : null),
);
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
const settingsNotice = ref<string | null>(null);
const settingsReady = ref(false);
const settingsRequests = createRequestLifetime();
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
const compactAudit = computed(() => auditHealth(auditChainOk.value));

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
  unlockTtl: null,
  verification: null,
  dangerousProfile: null,
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

function applyAgentConfig(config: AgentConfigSettings): void {
  settings.value = {
    ...settings.value,
    privacyRedactNames: config.privacy_redact_names,
    unlockTtlSeconds: configuredDurationSeconds(config.agent_unlock_ttl) || 900,
    unlockTtl: config.agent_unlock_ttl,
    verification: config.user_verification_required_for,
    dangerousProfile: config.dangerous_profile,
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

const settingsContextKey = computed(() =>
  JSON.stringify([
    selectionGeneration.value,
    status.value?.project_id,
    status.value?.profile_name,
    status.value?.lock_state,
  ]),
);

async function refreshSettings(): Promise<void> {
  const isCurrent = settingsRequests.begin();
  settingsReady.value = false;
  settingsLoading.value = true;
  settingsError.value = null;
  settingsNotice.value = null;
  const currentStatus = status.value;
  const result = await readConfig({
    project_id: currentStatus?.project_id ?? null,
    profile_name: currentStatus?.profile_name ?? null,
  });
  if (!isCurrent()) return;
  if (result.ok) {
    applyAgentConfig(result.value);
    settingsReady.value = true;
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

async function handleSettingsPatch(changes: WriteConfigChanges): Promise<void> {
  if (settingsLoading.value) return;
  const projectId = status.value?.project_id;
  if (!projectId) {
    if (typeof changes.privacy_redact_names === 'boolean') {
      settings.value.privacyRedactNames = changes.privacy_redact_names;
    }
    return;
  }
  if (!settingsReady.value || status.value?.lock_state !== 'unlocked') return;
  const isCurrent = settingsRequests.begin();
  settingsLoading.value = true;
  settingsError.value = null;
  settingsNotice.value = null;
  const result = await writeConfig({
    project_id: projectId,
    profile_name: status.value?.profile_name ?? null,
    changes,
  });
  if (!isCurrent()) return;
  if (result.ok) {
    applyAgentConfig(result.value.settings);
    settingsNotice.value = changes.agent_unlock_ttl
      ? 'Vault session duration saved.'
      : 'Settings saved.';
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

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
  { immediate: true, flush: 'sync' },
);

function selectView(key: ViewKey): void {
  currentView.value = key;
}

function selectOverflowView(key: ViewKey): void {
  selectView(key);
  closeMore(true);
}

async function addVariable(): Promise<void> {
  selectView('secret-editor');
  await nextTick();
  document.getElementById('secret-editor-set-heading')?.focus();
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
const selectedReference = computed(() =>
  selectedSecret.value
    ? secretReference(
        activeContext.value?.profile_name,
        selectedSecret.value.name,
        settings.value.privacyRedactNames,
      )
    : null,
);
const copyNotice = ref<string | null>(null);
const copyRequests = createRequestLifetime();

type RunnablePaletteAction = PaletteAction & { run: () => void | Promise<void> };
const paletteActions = computed<RunnablePaletteAction[]>(() => {
  const redact = settings.value.privacyRedactNames;
  const views = [
    ...primaryItems,
    { key: 'discover' as const, label: 'Discover', icon: 'compass' as const },
  ];
  const actions: RunnablePaletteAction[] = views.map(({ key, label, icon }) => ({
    id: `view:${key}`,
    label,
    group: 'Views',
    icon,
    badge: 'View',
    run: () => selectView(key),
  }));
  if (projectConnected.value) {
    const unlocked = status.value?.lock_state === 'unlocked';
    actions.push({
      id: 'vault',
      group: 'Actions',
      icon: unlocked ? 'lock' : 'unlock',
      badge: 'Action',
      label: unlocked ? 'Lock vault' : 'Unlock vault',
      run: () => handleTrayMenuAction(unlocked ? 'lock-vault' : 'unlock-vault'),
    });
  }
  actions.push({
    id: 'add-variable',
    group: 'Quick actions',
    icon: 'plus',
    badge: 'Action',
    label: 'Add variable',
    run: addVariable,
  });
  knownProjects.value.forEach((project, index) => {
    actions.push({
      id: `project:${index}`,
      group: 'Projects',
      icon: 'folder',
      badge: 'Project',
      label: redact ? `Project ${index + 1}` : project.project_name,
      detail: redact ? 'Open project' : project.root,
      keywords: 'open project',
      run: async () => {
        if (await connectProject(false, project.root)) selectView('dashboard');
      },
    });
  });
  if (!secretAccess.value.enabled) return actions;
  secretRows.value.forEach((row, index) => {
    const name = secretLabel(row, redact);
    actions.push({
      id: `variable:${index}`,
      group: 'Variables',
      icon: 'key',
      badge: 'Variable',
      label: name,
      run: () => selectSecret(row),
    });
    const reference = secretReference(activeContext.value?.profile_name, row.name, redact);
    if (reference) {
      actions.push({
        id: `reference:${index}`,
        group: 'Variables',
        icon: 'link',
        badge: 'Reference',
        label: `Copy ${reference}`,
        run: async () => {
          const isCurrent = metadataClipboardRequests.begin();
          const result = await desktopCopyTextPlain(reference);
          if (!isCurrent()) return;
          paletteMessage.value = result.ok ? `Copied ${reference}` : 'Could not copy reference.';
        },
      });
    }
  });
  return actions;
});

function runPaletteAction(id: string): void {
  paletteMessage.value = '';
  void paletteActions.value.find((action) => action.id === id)?.run();
}

watch(
  [settingsContextKey, () => settings.value.privacyRedactNames],
  () => {
    metadataClipboardRequests.invalidate();
    paletteMessage.value = '';
    copyRequests.invalidate();
    copyNotice.value = null;
    copyError.value = null;
  },
  { flush: 'sync' },
);

async function openDiscoveredProject(row: DiscoveredSecretWire): Promise<void> {
  const root =
    knownProjects.value.find((project) => project.project_id === row.project_id)?.root ??
    (settings.value.privacyRedactNames ? undefined : row.trusted_roots[0]);
  if (root && (await connectProject(false, root))) selectView('dashboard');
}

function switchDiscoveredEnvironment(row: DiscoveredSecretWire): void {
  if (
    settings.value.privacyRedactNames ||
    row.project_id !== activeContext.value?.project_id ||
    row.profile_id === activeContext.value.profile_id ||
    profileSwitchInProgress.value
  )
    return;
  if (row.dangerous) {
    discoverProfileTarget.value = { name: row.profile, dangerous: true };
    selectView('profiles');
  } else {
    void handleProfileSwitch({
      profileName: row.profile,
      confirmation: undefined,
      dangerous: false,
    });
  }
}

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

const dangerousConfirmDialog = ref<HTMLDialogElement | null>(null);
const dangerousAction = ref('');

async function confirmDangerousAction(action: string): Promise<boolean | undefined> {
  if (!settings.value.dangerousProfileFlag) return false;
  const dialog = dangerousConfirmDialog.value;
  if (!dialog || dialog.open) return;
  const generation = selectionGeneration.value;
  const profile = activeContext.value?.profile_id;
  dangerousAction.value = action;
  dialog.returnValue = '';
  const approved = await new Promise<boolean>((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), {
      once: true,
    });
    dialog.showModal();
  });
  if (
    approved &&
    generation === selectionGeneration.value &&
    profile === activeContext.value?.profile_id
  ) {
    return true;
  }
}

watch(
  [selectionGeneration, () => activeContext.value?.profile_id, () => status.value?.lock_state],
  () => {
    const dialog = dangerousConfirmDialog.value;
    if (dialog?.open) dialog.close();
  },
  { flush: 'sync' },
);

onBeforeUnmount(() => {
  if (dangerousConfirmDialog.value?.open) dangerousConfirmDialog.value.close();
});

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
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Reveal secret')
    : false;
  if (approved === undefined || !isCurrent()) return;
  const result = await revealAgent({
    secret_name: target.name,
    profile_id: profileId,
    ...(approved && { confirm_dangerous: true }),
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
  const isCurrent = copyRequests.begin();
  copyError.value = null;
  copyNotice.value = null;
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
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Copy secret')
    : false;
  if (approved === undefined || !isCurrent()) return;
  const result = await copySecret({
    secret_name: target.name,
    ...(approved && { confirm_dangerous: true }),
    profile_id: profileId,
    project_id: status.value?.project_id ?? undefined,
  });
  if (!isCurrent()) return;
  if (!result.ok) {
    copyError.value = revealErrorLabel(result.error);
    return;
  }
  if (result.value.kind === 'unsupported') {
    copyError.value = `Clipboard unavailable: ${result.value.unsupported_reason}.`;
  } else {
    copyNotice.value = 'Copied value temporarily.';
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
    secretsLoadError.value = null;
    secretsLoading.value = false;
    secretsLastRefreshed.value = undefined;
    return;
  }

  secretsLoading.value = true;
  const result = await listSecrets(request);
  if (sequence !== secretRefreshSequence) {
    return;
  }
  if (result.ok) {
    secretsLoadError.value = null;
    secrets.value = result.value.rows.map(secretRow);
    secretsLastRefreshed.value = new Date().toISOString();
  } else {
    secrets.value = [];
    secretsLoadError.value = result.error;
    secretsLastRefreshed.value = undefined;
  }
  secretsLoading.value = false;
}

watch(secretsRequest, () => {
  selectedSecret.value = null;
  secretsLoadError.value = null;
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
const discoverProfileTarget = ref<{ name: string; dangerous: boolean } | null>(null);
watch(currentView, (view) => {
  if (view !== 'profiles') discoverProfileTarget.value = null;
  profileSwitchError.value = null;
});

watch(
  [currentView, settingsContextKey, () => settings.value.privacyRedactNames],
  async ([view, context, redact], _previous, onCleanup) => {
    profileSwitchState.value = { ...profileSwitchState.value, knownProfiles: [] };
    const projectId = status.value?.project_id;
    if (view !== 'profiles' || !projectId || redact) return;
    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });
    const result = await listProjects({ redact_names: false });
    if (!result.ok || cancelled || context !== settingsContextKey.value) return;
    const project = result.value.find((row) => row.project_id === projectId);
    profileSwitchState.value = {
      ...profileSwitchState.value,
      knownProfiles: project?.profiles ?? [],
    };
  },
);

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
        confirm_dangerous: action.request.confirmDangerous,
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
        confirm_dangerous: action.request.confirmDangerous,
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
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Save secret')
    : false;
  if (approved === undefined)
    return { ok: false, error: { kind: 'protocol', reason: 'Action canceled.' } };
  const result = await setSecret(approved ? { ...payload, confirm_dangerous: true } : payload);
  if (result.ok) {
    await refreshSecrets();
  }
  return result;
}

async function handleRotateSecret(
  payload: SetSecretRequest,
): Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }> {
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Rotate secret')
    : false;
  if (approved === undefined)
    return { ok: false, error: { kind: 'protocol', reason: 'Action canceled.' } };
  const result = await rotateSecret(approved ? { ...payload, confirm_dangerous: true } : payload);
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

async function handleListCopy(row: SecretRowMeta): Promise<void> {
  if (!secretAccess.value.enabled) return;
  selectedSecret.value = row;
  await handleCopySelectedSecret();
}

async function refreshProjectConnections(): Promise<void> {
  const generation = selectionGeneration.value;
  const result = await desktopListProjects();
  if (result.ok) {
    knownProjects.value = result.value;
    if (generation !== selectionGeneration.value) return;
    const initial = previewParams
      ? result.value[0]
      : initialProjectSelection(result.value, selectedProject.value);
    if (!selectedProject.value && initial) {
      await connectProject(false, initial.root);
    }
  } else if (generation === selectionGeneration.value && desktopAvailable)
    desktopError.value = actionError(result.error);
}

async function connectProject(initialize = false, path = projectPath.value): Promise<boolean> {
  if (desktopBusy.value || !path.trim()) return false;
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
    const showPreviewUnlock = !selectedProject.value && previewParams?.get('modal') === 'unlock';
    selectedProject.value = result.value;
    selectedSecret.value = null;
    unlockOpen.value = showPreviewUnlock;
    projectPath.value = result.value.root;
    await refreshProjectConnections();
    await refresh();
  } else desktopError.value = actionError(result.error);
  desktopBusy.value = false;
  return result.ok;
}
async function retryVariables(): Promise<void> {
  if (error.value) await refresh();
  if (!error.value) await refreshSecrets();
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
    if (!error.value && secretsLoadError.value) await refreshSecrets();
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
  if (
    settings.value.dangerousProfileFlag &&
    importConfirmation.value !== activeContext.value?.profile_name
  )
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
  window.addEventListener('pointerdown', onMorePointerdown);
  void refreshProjectConnections();
  if (previewParams) return;
  void listen<TrayMenuAction>('tray-menu-action', (event) => {
    void handleTrayMenuAction(event.payload);
  })
    .then((unlisten) => {
      unlistenTrayMenu = unlisten;
    })
    .catch(() => {});
});

onBeforeUnmount(() => {
  window.removeEventListener('pointerdown', onMorePointerdown);
  clearTimeout(desktopNoticeTimer);
  metadataClipboardRequests.dispose();
  copyRequests.dispose();
  settingsRequests.dispose();
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
    <aside class="shell__nav" aria-label="Workspace">
      <div class="shell__masthead">
        <h1><AppIcon name="brand-lock" :size="26" /> <span>Locket</span></h1>
        <button
          class="companion-button shell__context"
          type="button"
          :title="`${projectLabel} · ${profileLabel} — ${connectionLabel} · Vault ${lockLabel}`"
          :aria-label="
            projectConnected
              ? `Switch environment for ${projectLabel} / ${profileLabel}. Agent ${connectionLabel}. Vault ${lockLabel}.`
              : 'Open project'
          "
          @click="selectView(projectConnected ? 'profiles' : 'dashboard')"
        >
          <span class="shell__context-dot" :data-online="agentOnline" aria-hidden="true" />
          <span>{{ projectLabel }} · {{ profileLabel }}</span>
          <AppIcon name="chevron-down" :size="13" />
        </button>
        <div class="shell__agent">
          <span class="shell__vault" :data-unlocked="lockLabel === 'Unlocked'">
            <AppIcon :name="lockLabel === 'Unlocked' ? 'unlock' : 'lock'" />
            {{ lockLabel }}
          </span>
          <span
            class="shell__connection"
            :data-connected="agentOnline ? 'true' : 'false'"
            role="status"
            aria-label="Agent status"
          >
            {{ connectionLabel }}
            <time v-if="agentOnline && lastSeenAt" :datetime="lastSeenAt" :title="lastSeenAt">
              · {{ formatTime(lastSeenAt) }}
            </time>
          </span>
        </div>
        <span
          v-if="
            agentOnline &&
            !auditError &&
            !auditLoading &&
            auditChainOk !== null &&
            activeContext &&
            lockLabel === 'Unlocked'
          "
          class="shell__audit-pill"
          :data-tone="compactAudit.tone"
          :title="`Audit · ${compactAudit.label}`"
        >
          Audit<span class="shell__audit-label"> · {{ compactAudit.label }}</span>
          <AppIcon class="shell__audit-icon" :name="auditChainOk ? 'check' : 'alert'" :size="14" />
        </span>
        <button
          class="companion-button icon-label shell__palette-mobile"
          type="button"
          aria-label="Search quick actions"
          aria-keyshortcuts="Meta+K Control+K"
          aria-haspopup="dialog"
          :disabled="unlockOpen || policyFormMode !== null"
          @click="paletteOpen = true"
        >
          <AppIcon name="search" />
          <kbd>⌘K</kbd>
        </button>
      </div>

      <nav class="shell__primary" aria-label="Primary navigation">
        <ul class="shell__primary-list">
          <li
            v-for="(item, index) in primaryItems"
            :key="item.key"
            :class="{ 'shell__wide-destination': index >= 3 }"
          >
            <button
              type="button"
              class="shell__nav-item"
              :class="{
                'shell__nav-item--active':
                  currentView === item.key || secondaryItems.some(({ key }) => key === item.key),
              }"
              :aria-current="currentView === item.key ? 'page' : undefined"
              @click="selectView(item.key)"
            >
              <AppIcon :name="item.icon" />
              {{ item.label }}
            </button>
          </li>
          <li class="shell__more" @focusout="onMoreFocusout" @keydown.esc.stop="closeMore(true)">
            <button
              ref="moreTrigger"
              type="button"
              class="shell__nav-item"
              :class="{ 'shell__nav-item--active': overflowActive }"
              :aria-expanded="moreOpen"
              :aria-current="overflowActive ? 'location' : undefined"
              :aria-controls="moreOpen ? 'more-destinations' : undefined"
              @click="moreOpen = !moreOpen"
            >
              <AppIcon v-if="overflowActive" :name="overflowActive.icon" />
              {{ overflowActive?.label ?? 'More' }}
              <AppIcon name="chevron-down" :size="12" />
            </button>
            <ul v-if="moreOpen" id="more-destinations" class="shell__more-list">
              <li v-for="item in overflowItems" :key="item.key">
                <button
                  type="button"
                  class="shell__nav-item"
                  :class="{ 'shell__nav-item--active': overflowActive?.key === item.key }"
                  :aria-current="overflowActive?.key === item.key ? 'page' : undefined"
                  @click="selectOverflowView(item.key)"
                >
                  <AppIcon :name="item.icon" />
                  {{ item.label }}
                </button>
              </li>
            </ul>
          </li>
        </ul>
      </nav>

      <section class="shell__activity" aria-label="Recent activity">
        <div class="shell__activity-head">
          <span>Recent</span>
          <span v-if="auditLoading">Loading</span>
          <span v-else-if="auditError" class="shell__activity-error" :title="auditError"
            >Unavailable</span
          >
          <time
            v-else-if="auditLastRefreshed"
            :datetime="auditLastRefreshed"
            :title="auditLastRefreshed"
          >
            {{ formatTime(auditLastRefreshed) }}
          </time>
        </div>
        <dl>
          <div v-for="row in recentActivityRows" :key="row.label">
            <dt>{{ row.label }}</dt>
            <dd :class="`shell__activity-value--${row.tone}`">{{ row.value }}</dd>
          </div>
        </dl>
      </section>
    </aside>

    <main class="shell__main">
      <div
        v-if="currentView !== 'dashboard'"
        class="shell__topbar"
        :class="{ 'shell__topbar--has-sections': secondaryItems.length }"
      >
        <nav v-if="secondaryItems.length" class="shell__segments" aria-label="Section navigation">
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
        <button
          type="button"
          class="companion-button icon-label shell__palette-button"
          aria-keyshortcuts="Meta+K Control+K"
          aria-haspopup="dialog"
          :disabled="unlockOpen || policyFormMode !== null"
          @click="paletteOpen = true"
        >
          <AppIcon name="search" />
          Search <kbd>⌘K</kbd>
        </button>
      </div>
      <AgentUnavailableBanner
        v-if="shellAgentError && currentView !== 'secrets'"
        :error="shellAgentError"
        :retrying="loading || secretsLoading"
        :can-start="desktopAvailable && !agentOnline"
        :starting="desktopBusy"
        @retry="error ? refresh() : retryVariables()"
        @start="startAgent"
      />
      <p
        v-if="connected && agentStatus && !agentStatus.session_monitoring?.startsWith('active:')"
        role="status"
        class="shell__notice shell__notice--warning"
        data-testid="session-lock-warning"
      >
        <AppIcon name="alert" />
        <span
          >Automatic locking on screen lock or sleep is unavailable. Lock the vault before leaving
          this device.</span
        >
      </p>
      <p v-if="!desktopAvailable" class="shell__notice">
        Browser preview is disconnected. Open the Locket desktop app to connect projects, unlock,
        import values, and run commands.
      </p>
      <div
        v-if="agentOnline && lockLabel !== 'Unlocked' && projectConnected"
        class="shell__toolbar"
        aria-label="Vault actions"
      >
        <button
          type="button"
          class="companion-button icon-label"
          :disabled="!desktopAvailable || unlockBusy"
          @click="openUnlock"
        >
          <AppIcon name="unlock" />
          Unlock
        </button>
      </div>
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
          <PathBrowse
            title="Browse for an env file"
            :disabled="desktopBusy"
            @pick="envPath = $event"
          />
          <p>Relative paths start in the connected project.</p>
          <details>
            <summary>Import options</summary>
            <label
              ><input v-model="importOverwrite" type="checkbox" /> Replace existing values</label
            ><label
              ><input v-model="importLiteral" type="checkbox" /> Keep expansion syntax as literal
              text</label
            >
          </details>
          <label v-if="settings.dangerousProfileFlag">
            Type {{ activeContext?.profile_name }} to confirm import into this environment
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
              (settings.dangerousProfileFlag && importConfirmation !== activeContext?.profile_name)
            "
          >
            {{ desktopBusy ? 'Importing…' : 'Import variables' }}
          </button>
        </form>
      </section>
      <p v-if="desktopError" role="alert" class="shell__notice shell__notice--error">
        <AppIcon name="alert" />{{ desktopError }}
      </p>
      <p v-if="desktopNotice" role="status" class="shell__notice shell__notice--success">
        <AppIcon name="check" />{{ desktopNotice }}
      </p>

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
        :active-project-folder="activeProjectFolder && agentOnline"
        :setup-complete="setupComplete"
        :connected="agentOnline"
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
      >
        <template #search>
          <button
            type="button"
            class="companion-button icon-label shell__palette-button shell__dashboard-search"
            aria-keyshortcuts="Meta+K Control+K"
            aria-haspopup="dialog"
            :disabled="unlockOpen || policyFormMode !== null"
            @click="paletteOpen = true"
          >
            <AppIcon name="search" /> Search <kbd>⌘K</kbd>
          </button>
        </template>
        <template #connection>
          <section class="shell__panel" aria-labelledby="connect-heading">
            <h2 id="connect-heading">Project connection</h2>
            <p>Open a folder with locket.toml, or initialize a project in an existing folder.</p>
            <form class="shell__project-form" @submit.prevent="connectProject(false)">
              <div class="shell__project-field">
                <label for="project-path">Project folder</label>
                <div class="shell__path-input">
                  <input
                    id="project-path"
                    v-model="projectPath"
                    type="text"
                    placeholder="/path/to/project"
                    autocomplete="off"
                    spellcheck="false"
                    :disabled="desktopBusy || !desktopAvailable"
                  />
                  <PathBrowse
                    title="Browse for a project folder"
                    directory
                    :disabled="desktopBusy"
                    @pick="projectPath = $event"
                  />
                </div>
              </div>
              <div class="shell__toolbar">
                <button
                  class="companion-button"
                  :class="{
                    'companion-button--primary':
                      !activeProjectFolder && (agentOnline || !shellAgentError),
                  }"
                  type="submit"
                  :disabled="desktopBusy || !desktopAvailable || !projectPath.trim()"
                >
                  Open project
                </button>
                <button
                  class="companion-button"
                  type="button"
                  :disabled="desktopBusy || !desktopAvailable || !projectPath.trim()"
                  @click="connectProject(true)"
                >
                  Initialize project
                </button>
              </div>
            </form>
            <div v-if="knownProjects.length" class="shell__known-projects">
              <h3>Known projects</h3>
              <ul>
                <li v-for="project in knownProjects" :key="project.root">
                  <button
                    class="companion-button shell__known-project"
                    type="button"
                    :aria-current="selectedProject?.root === project.root ? 'true' : undefined"
                    :disabled="desktopBusy"
                    @click="connectProject(false, project.root)"
                  >
                    <AppIcon name="folder" />
                    <span class="shell__known-project-label">
                      <span>{{
                        settings.privacyRedactNames ? 'Project' : project.project_name
                      }}</span>
                      <code v-if="!settings.privacyRedactNames" :title="project.root">{{
                        shortenProjectPath(project.root)
                      }}</code>
                    </span>
                    <AppIcon
                      v-if="selectedProject?.root === project.root"
                      class="shell__known-project-check"
                      name="check"
                    />
                  </button>
                </li>
              </ul>
            </div>
          </section>
        </template>
      </ProjectDashboard>

      <SecretMetadataList
        v-else-if="currentView === 'secrets'"
        :rows="secretRows"
        :versions="versions"
        :profile-name="activeContext?.profile_name"
        :profile-label="profileLabel"
        :can-access-values="secretAccess.enabled"
        :connected="agentOnline"
        :can-start="desktopAvailable && !agentOnline"
        :starting="desktopBusy"
        :privacy-mode="settings.privacyRedactNames"
        :loading="secretsLoading || loading"
        :load-error="variableViewError"
        :copy-verification="settings.verification?.copy"
        :last-refreshed-at="secretsLastRefreshed"
        :metadata-loaded="secretAccess.enabled"
        :action-guidance="secretAccess.guidance"
        @select="selectSecret"
        @copy-value="handleListCopy"
        @reveal-value="handleEditorReveal"
        @refresh="retryVariables"
        @retry="retryVariables"
        @start="startAgent"
        @add="addVariable"
      />

      <DiscoverSecrets
        v-else-if="currentView === 'discover'"
        :privacy-mode="settings.privacyRedactNames || settingsLoading"
        :known-project-ids="knownProjects.map((project) => project.project_id)"
        :current-project-id="selectedProject?.project_id ?? status?.project_id"
        :current-profile-id="activeContext?.profile_id"
        :switching="profileSwitchInProgress"
        :switch-error="profileSwitchError"
        @open-project="openDiscoveredProject"
        @switch-environment="switchDiscoveredEnvironment"
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

      <template v-else-if="currentView === 'versions'">
        <div
          v-if="selectedSecret && secretAccess.enabled"
          class="shell__toolbar"
          aria-label="Variable actions"
        >
          <CopyReference :reference="selectedReference" />
          <button type="button" @click="handleCopySelectedSecret">Copy value</button>
          <button type="button" @click="handleRevealSelectedSecret">Reveal</button>
        </div>
        <SecretVersionHistory
          :rows="versions.filter((row) => row.secretName === selectedSecret?.name)"
          :secret-label="secretLabel(selectedSecret, settings.privacyRedactNames)"
          :loading="versionsLoading"
          :error-message="versionsError"
          :last-refreshed-at="versionsLastRefreshed"
          @refresh="refreshVersions"
        />
      </template>

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
        :initial-target="discoverProfileTarget"
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
        :confirm-dangerous="confirmDangerousAction"
        :require-accept-user-verification="settings.verification?.team_accept ?? false"
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
        <p v-if="backupError" role="alert" class="shell__notice shell__notice--error">
          <AppIcon name="alert" />{{ backupError }}
        </p>
      </template>

      <Settings
        v-else-if="currentView === 'settings'"
        :state="settings"
        :loading="settingsLoading"
        :error-message="settingsError"
        :save-message="settingsNotice"
        :can-edit-vault="settingsReady && status?.lock_state === 'unlocked'"
        :project-connected="projectConnected"
        @update="handleSettingsPatch"
      />

      <p v-if="revealError" role="alert" class="shell__notice shell__notice--error">
        <AppIcon name="alert" />{{ revealError }}
      </p>
      <p v-if="paletteMessage" role="status" class="shell__notice">{{ paletteMessage }}</p>
      <p v-if="copyNotice" role="status" class="shell__notice">{{ copyNotice }}</p>
      <p v-if="copyError" role="alert" class="shell__notice shell__notice--error">
        <AppIcon name="alert" />{{ copyError }}
      </p>
    </main>

    <dialog ref="dangerousConfirmDialog" aria-labelledby="dangerous-action-title">
      <form method="dialog">
        <h2 id="dangerous-action-title">{{ dangerousAction }}</h2>
        <p>Allow this action in the dangerous profile {{ profileLabel }}?</p>
        <button value="cancel" autofocus>Cancel</button>
        <button value="confirm">Allow action</button>
      </form>
    </dialog>
    <CommandPalette
      v-model:open="paletteOpen"
      :actions="paletteActions"
      :blocked="unlockOpen || policyFormMode !== null"
      @execute="runPaletteAction"
    />
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
body,
html,
#app {
  margin: 0;
  min-height: 100vh;
  background: var(--bg-app);
  color: var(--text-primary);
}

.shell {
  display: grid;
  grid-template-columns: 182px minmax(0, 1fr);
  min-height: 100vh;
}

.shell__nav {
  min-width: 0;
  background: color-mix(in srgb, var(--bg-surface), var(--bg-app) 40%);
  border-right: 1px solid var(--border-subtle);
  padding: 1rem 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
}

.shell__masthead {
  display: grid;
  gap: 0.65rem;
}

.shell__masthead h1 {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  margin: 0 0 0.15rem;
  font-size: 1.1rem;
  letter-spacing: -0.025em;
}

.shell__masthead h1 .app-icon {
  color: var(--accent);
}

.shell__context {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  justify-content: space-between;
  min-width: 0;
  text-align: start;
  padding-inline: 0.45rem;
}

.shell__context span:not(.shell__context-dot) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.shell__context-dot,
.shell__audit-pill {
  display: none;
}

.shell__agent {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0 0.25rem;
  font-size: 0.75rem;
}

.shell__vault,
.shell__connection {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  white-space: nowrap;
}

.shell__vault {
  color: var(--text-secondary);
}
.shell__vault[data-unlocked='true'] {
  color: var(--status-unlocked);
}

.shell__vault .app-icon {
  width: 14px;
}

.shell__connection {
  color: var(--danger);
  font-weight: 600;
}

.shell__connection::before {
  content: '';
  flex: none;
  width: 0.375rem;
  height: 0.375rem;
  margin-inline: 0.23rem;
  border-radius: 50%;
  background: currentColor;
}

.shell__connection[data-connected='true'] {
  color: var(--success);
}

.shell__connection time {
  color: var(--text-secondary);
  font-weight: 400;
}

.shell__activity {
  padding: 0.7rem 0.25rem 0;
  border-top: 1px solid var(--border-subtle);
}

.shell__activity-head {
  display: flex;
  justify-content: space-between;
  gap: 0.25rem;
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.shell__activity-head span:first-child {
  font-weight: 650;
}

.shell__activity-error {
  color: var(--danger);
}

.shell__activity dl {
  margin: 0.45rem 0 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem;
}

.shell__activity dt {
  font-size: 0.7rem;
  color: var(--text-secondary);
}

.shell__activity dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
  font-weight: 650;
}

.shell__activity-value--ok {
  color: var(--success);
}

.shell__activity-value--warn {
  color: var(--warn);
}

.shell__primary-list,
.shell__more-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.shell__more {
  display: none;
}

.shell__nav-item {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  width: 100%;
  min-height: 2.125rem;
  text-align: start;
  background: transparent;
  border: 1px solid transparent;
  padding: 0.4rem 0.55rem;
  border-radius: var(--radius-sm);
  font: inherit;
  font-size: 0.8125rem;
  color: var(--text-secondary);
  cursor: pointer;
  white-space: nowrap;
}

.shell__nav-item:hover {
  background: var(--bg-subtle);
  color: var(--text-primary);
}

.shell__nav-item:focus-visible {
  outline-offset: -2px;
}

.shell__nav-item--active,
.shell__nav-item--active:hover {
  border-color: color-mix(in srgb, var(--accent), transparent 65%);
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 650;
}

.shell__main {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
  min-width: 0;
  padding: 1rem clamp(0.85rem, 2vw, 1.75rem) 1.5rem;
}

.shell__topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-width: 0;
  gap: 0.75rem;
}

.shell__palette-button {
  margin-inline-start: auto;
}

.shell__palette-button kbd,
.shell__palette-mobile kbd {
  font-size: 0.75rem;
  color: var(--text-secondary);
  white-space: nowrap;
}

.shell__masthead .shell__palette-mobile {
  display: none;
}

.shell__segments {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.15rem;
  min-width: 0;
  padding: 0.15rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-subtle);
}

.shell__segments button {
  flex: none;
  padding: 0.3rem 0.575rem;
  min-height: 1.8rem;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-secondary);
  font: inherit;
  font-size: 0.8rem;
  white-space: nowrap;
  cursor: pointer;
}

.shell__segments button[aria-current='page'] {
  border-color: var(--border-subtle);
  background: var(--bg-surface);
  color: var(--text-primary);
  font-weight: 650;
  box-shadow: var(--shadow-sm);
}

.shell__segments button:focus-visible {
  outline-offset: -2px;
}

.shell dialog:not(.palette) {
  max-width: min(28rem, 85vw);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-lg);
  background: var(--bg-elevated);
  color: var(--text-primary);
  box-shadow: var(--shadow-lg);
}

.shell dialog:not(.palette)::backdrop {
  background: var(--backdrop);
}

.shell__toolbar,
.shell__project-form,
.shell__path-input {
  display: flex;
  align-items: end;
  gap: 0.5rem;
}

.shell__toolbar,
.shell__project-form {
  flex-wrap: wrap;
}

.shell__panel {
  min-width: 0;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 0.9rem 1rem;
}

.shell__panel h2 {
  margin: 0;
  font-size: 1rem;
}

.shell__panel p {
  margin: 0.45rem 0 0.65rem;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.shell__panel label {
  display: inline-flex;
  flex-direction: column;
  gap: 0.3rem;
  margin: 0.35rem 0.5rem 0.35rem 0;
  font-size: 0.8125rem;
}

.shell__main :where(input[type='text']) {
  box-sizing: border-box;
  max-width: 100%;
  min-height: 2.125rem;
  padding: 0.35rem 0.6rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  color: var(--text-primary);
  font: inherit;
}

.shell__panel button:not(.companion-button),
.shell__toolbar button:not(.companion-button) {
  min-height: 2.125rem;
  padding: 0.3rem 0.65rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  color: var(--text-primary);
  font: inherit;
  font-size: 0.8125rem;
  cursor: pointer;
}

.shell__main button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.shell__project-field {
  flex: 1 0 100%;
  min-width: 0;
  max-width: 36rem;
}

.shell__path-input {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.35rem;
  align-items: center;
}

.shell__path-input input {
  width: 100%;
  min-width: 0;
  font-size: 0.875rem;
}
.shell__path-input input:not(:focus) {
  text-overflow: ellipsis;
}

.shell__path-input button {
  white-space: nowrap;
}

.shell__path-input small {
  grid-column: 1 / -1;
  margin-top: 0.25rem;
}

.shell__known-projects h3 {
  margin: 0.75rem 0 0.35rem;
  font-size: 0.8125rem;
  font-weight: 650;
}

.shell__known-projects ul {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 13rem), 1fr));
  gap: 0.35rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

@container dashboard (min-width: 62rem) {
  .shell__known-projects ul {
    grid-template-columns: minmax(0, 1fr);
  }
}

.shell__known-project {
  display: flex;
  justify-content: space-between;
  gap: 0.35rem;
  align-items: center;
  width: 100%;
  min-width: 0;
  text-align: start;
}

.shell__known-project-label {
  display: flex;
  flex: 1;
  flex-direction: column;
  min-width: 0;
  gap: 0.15rem;
}

.shell__known-project-label > span,
.shell__known-project code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell__known-project code {
  color: var(--text-secondary);
  font-size: 0.72rem;
}
.shell__known-project-check {
  flex-shrink: 0;
  margin-inline-start: auto;
}

.shell__known-project[aria-current='true'] {
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 650;
}

.shell__notice {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  margin: 0;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--border-subtle);
  background: var(--bg-surface);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  overflow-wrap: anywhere;
}

.shell__notice--warning {
  background: var(--warn-soft);
  color: var(--warn);
}

.shell__notice--error {
  background: var(--danger-soft);
  color: var(--danger);
}

.shell__notice--success {
  background: var(--success-soft);
  color: var(--success);
}

@media (max-width: 959px) {
  .shell {
    grid-template-columns: minmax(0, 1fr);
    align-content: start;
  }

  .shell__nav {
    gap: 0.2rem;
    padding: 0.35rem 0.7rem 0.25rem;
    border-right: 0;
    border-bottom: 1px solid var(--border-subtle);
  }

  .shell__masthead {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .shell__masthead h1 {
    margin: 0;
    font-size: 1rem;
  }

  .shell__context {
    margin-inline-end: auto;
    max-width: 100%;
  }

  .shell__connection,
  .shell__activity,
  .shell__topbar .shell__palette-button,
  .shell__main .shell__dashboard-search,
  .shell__topbar:not(.shell__topbar--has-sections) {
    display: none;
  }

  .shell__context-dot {
    display: inline-block;
    flex: none;
    width: 0.375rem;
    height: 0.375rem;
    border-radius: 50%;
    background: var(--danger);
  }

  .shell__context-dot[data-online='true'] {
    background: var(--success);
  }

  .shell__audit-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    padding: 0.2rem 0.45rem;
    border-radius: 999px;
    background: var(--success-soft);
    color: var(--success);
    font-size: 0.72rem;
    font-weight: 650;
    white-space: nowrap;
  }

  .shell__audit-pill[data-tone='warn'] {
    background: var(--warn-soft);
    color: var(--warn);
  }

  .shell__audit-icon {
    display: none;
  }

  .shell__agent {
    flex-direction: row;
    align-items: center;
    gap: 0.45rem;
    padding: 0;
  }

  .shell__vault {
    padding: 0.2rem 0.4rem;
    border: 1px solid var(--border-subtle);
    border-radius: 999px;
    background: var(--bg-surface);
  }

  .shell__masthead .shell__palette-mobile {
    display: inline-flex;
    padding-inline: 0.4rem;
  }

  .shell__primary-list {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 0.2rem;
  }

  .shell__main {
    gap: 0.55rem;
    padding: 0.5rem 0.75rem 1rem;
  }
}

@media (max-width: 639px) {
  .shell__masthead h1 span,
  .shell__audit-label {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }

  .shell__audit-icon {
    display: block;
  }

  .shell__agent {
    gap: 0.25rem;
  }

  .shell__vault {
    padding: 0.15rem 0.35rem;
    font-size: 0.7rem;
  }

  .shell__connection[data-connected='true'] {
    display: none;
  }

  .shell__connection[data-connected='false'] {
    display: inline-flex;
    align-items: center;
    padding: 0.15rem 0.35rem;
    border-radius: 999px;
    background: var(--danger-soft);
    color: var(--danger);
    font-size: 0.7rem;
    font-weight: 650;
  }

  .shell__agent:has(.shell__connection[data-connected='false']) .shell__vault {
    display: none;
  }

  .shell__masthead .shell__palette-mobile {
    flex: none;
  }

  .shell__primary-list {
    display: grid;
    grid-template-columns: repeat(4, minmax(max-content, 1fr));
  }

  .shell__primary-list > li > .shell__nav-item {
    justify-content: center;
    gap: 0.2rem;
    min-width: max-content;
    min-height: 1.9rem;
    padding-inline: 0.1rem;
    font-size: 0.75rem;
  }

  .shell__primary-list > li > .shell__nav-item .app-icon {
    width: 0.8125rem;
  }

  .shell__primary-list .shell__wide-destination {
    display: none;
  }

  .shell__more {
    position: relative;
    display: block;
  }

  .shell__more-list {
    position: absolute;
    z-index: 2;
    inset-block-start: calc(100% + 0.25rem);
    inset-inline-end: 0;
    min-width: 8.75rem;
    padding: 0.25rem;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    box-shadow: var(--shadow-lg);
  }

  .shell__segments button {
    min-height: 1.65rem;
    padding-block: 0.2rem;
  }
}
</style>
