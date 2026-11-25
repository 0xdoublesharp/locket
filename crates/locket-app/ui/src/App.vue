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
import type { DesktopFolderInspection, DesktopProjectContext, UnlockRequest } from './agent/types';
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
  desktopMcpConfigSnippet,
  desktopPickDirectory,
  previewParams,
  desktopListProjects,
  desktopOpenProject,
  desktopOpenSharedVault,
  desktopInspectProjectFolder,
  desktopInitializeProject,
  desktopImportEnv,
  desktopPickFile,
  desktopStartAgent,
  desktopRunPolicy,
  desktopScanProject,
  desktopCreateProfile,
  desktopDeleteSecret,
  desktopCopySecretToShared,
  desktopDetectCommands,
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
import { dotenvMigrationPrompt, mcpClientSnippets } from './agent/agentPrompts';
import type { SetSecretRequest, SetSecretResponse } from './agent/client';
import type { PolicyFormMode, PolicyFormState } from './policy/form';
import { isValidProfileName, rememberTarget, type ProfileSwitchState } from './profile/switcher';
import type { CommandPolicySnapshotWire } from './agent/types';
import { deviceMemberRow } from './agent/deviceMembers';
import { commandPolicyRow } from './agent/policies';
import { runtimeSessionRow } from './agent/runtimeSessions';
import { secretRow, secretSourceWire } from './agent/secrets';
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
import WelcomeView from './views/WelcomeView.vue';
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
  DetectedCommandRow,
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
const selectedIsShared = computed(() => Boolean(selectedProject.value?.is_shared));
const projectPath = ref('');
const pendingInitFolder = ref<DesktopFolderInspection | null>(null);
const pendingInitHeading = ref<HTMLElement | null>(null);
const manualConnectOpen = ref(false);
const manualConnectPath = ref<HTMLInputElement | null>(null);
const connectProjectTrigger = ref<HTMLButtonElement | null>(null);
const activeProjectFolder = computed(() =>
  Boolean(
    selectedProject.value &&
    !selectedProject.value.is_shared &&
    projectPath.value.trim() === selectedProject.value.root,
  ),
);
const knownProjects = ref<DesktopProjectContext[]>([]);
const knownFolderProjects = computed(() =>
  knownProjects.value.filter((project) => !project.is_shared),
);
const hasSharedVault = computed(() => knownProjects.value.some((project) => project.is_shared));
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
const unlockWithPassphrase = ref(false);
const unlockRequests = createRequestLifetime();
watch(
  selectionGeneration,
  () => {
    unlockRequests.invalidate();
    unlockBusy.value = false;
    unlockOpen.value = false;
    unlockError.value = null;
    unlockWithPassphrase.value = false;
  },
  { flush: 'sync' },
);
const envPath = ref('.env');
const envImportOpen = ref(false);
const envImportHeading = ref<HTMLElement | null>(null);
const envPickerBusy = ref(false);
const envPickerFailed = ref(false);
const envPickerRequests = createRequestLifetime();
const importOverwrite = ref(false);
const importConfirmation = ref('');
const importLiteral = ref(false);
const envPathReady = computed(() => {
  const path = envPath.value.trim();
  return path !== '' && (!selectedIsShared.value || /^(?:\/|[a-z]:[\\/]|\\\\)/i.test(path));
});
const commandRunning = ref(false);
const commandRunError = ref<string | null>(null);
const commandRunNotice = ref<string | null>(null);
useTray(status, error);

const agentOnline = computed(
  () => connected.value && !error.value && !isAgentUnavailable(secretsLoadError.value),
);
const canImportEnv = computed(
  () => desktopAvailable && projectConnected.value && agentOnline.value,
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
  'profiles',
  'execution',
  'audit',
  'team',
  'recovery',
  'settings',
];
const currentView = ref<ViewKey>(
  previewViews.find((view) => view === previewParams?.get('view')) ?? 'dashboard',
);
const rotationTarget = ref<SecretRowMeta | null>(null);
watch(
  [
    currentView,
    selectionGeneration,
    () => activeContext.value?.project_id,
    () => activeContext.value?.profile_id,
  ],
  resetEnvImport,
  { flush: 'sync' },
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
  { key: 'secrets', label: 'Secrets', icon: 'key' },
  { key: 'policies', label: 'Commands', icon: 'terminal' },
  { key: 'execution', label: 'Activity', icon: 'activity' },
  { key: 'settings', label: 'Settings', icon: 'settings' },
];
const vaultSwitcherOpen = ref(false);
const vaultSwitcherRef = ref<HTMLElement | null>(null);
const vaultSwitcherTrigger = ref<HTMLButtonElement | null>(null);
const secondaryItems = computed<Array<{ key: ViewKey; label: string }>>(() => {
  if (['secrets', 'discover', 'secret-editor', 'versions'].includes(currentView.value))
    return [
      { key: 'secrets', label: 'Secrets' },
      { key: 'secret-editor', label: 'Add or rotate' },
      { key: 'discover', label: 'Discover' },
      ...(selectedSecret.value ? [{ key: 'versions' as const, label: 'Secret history' }] : []),
    ];
  if (['execution', 'audit', 'scan'].includes(currentView.value))
    return [
      { key: 'execution', label: 'Runs' },
      { key: 'audit', label: 'Audit' },
      { key: 'scan', label: 'Scan in terminal' },
    ];
  if (
    ['settings', 'profiles', 'team', 'devices', 'recovery'].includes(currentView.value) ||
    (currentView.value === 'dashboard' && projectConnected.value)
  )
    return [
      { key: 'settings', label: 'Preferences' },
      ...(selectedIsShared.value ? [] : [{ key: 'profiles' as const, label: 'Environments' }]),
      { key: 'team', label: 'Team' },
      { key: 'devices', label: 'Devices' },
      { key: 'recovery', label: 'Backup' },
      ...(projectConnected.value && !selectedIsShared.value
        ? [{ key: 'dashboard' as const, label: 'Project' }]
        : []),
    ];
  return [];
});

function closeVaultSwitcher(): void {
  vaultSwitcherOpen.value = false;
}

function dismissVaultSwitcher(): void {
  if (!vaultSwitcherOpen.value) return;
  closeVaultSwitcher();
  vaultSwitcherTrigger.value?.focus?.();
}

function onSwitcherFocusout(event: FocusEvent): void {
  if (event.relatedTarget && !vaultSwitcherRef.value?.contains(event.relatedTarget as Node)) {
    closeVaultSwitcher();
  }
}

function onSwitcherPointerdown(event: PointerEvent): void {
  if (vaultSwitcherOpen.value && !vaultSwitcherRef.value?.contains(event.target as Node)) {
    closeVaultSwitcher();
  }
}

const lockLabel = computed<string>(() => {
  if (loading.value && status.value === null && error.value === null) {
    return 'Connecting…';
  }
  if (selectedProject.value && !status.value) return 'Unknown';
  if (!connected.value || agentStatus.value === null) {
    return 'Unavailable';
  }
  if (status.value === null) {
    return 'No project';
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
const switcherLabel = computed<string>(() => {
  if (!projectConnected.value) return 'Choose a vault…';
  if (selectedIsShared.value) {
    return settings.value.privacyRedactNames ? projectLabel.value : 'Global Vault';
  }
  return `${projectLabel.value} · ${profileLabel.value}`;
});

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
const backupRequests = createRequestLifetime();
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
  agentVersion: status.value?.agent_version ?? agentStatus.value?.agent_version ?? 'unknown',
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
    agentVersion:
      status.value?.agent_version ??
      agentStatus.value?.agent_version ??
      settings.value.agentVersion,
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
  [status, agentStatus],
  () => {
    settings.value = {
      ...settings.value,
      agentVersion: status.value?.agent_version ?? agentStatus.value?.agent_version ?? 'unknown',
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
  if (key === 'secret-editor') rotationTarget.value = null;
  currentView.value = key;
  dismissVaultSwitcher();
}

async function addSecret(): Promise<void> {
  selectView('secret-editor');
  await nextTick();
  document.getElementById('secret-editor-set-heading')?.focus();
}

async function rotateListedSecret(row: SecretRowMeta): Promise<void> {
  if (!secretMutationAvailable.value) return;
  selectView('secret-editor');
  rotationTarget.value = row;
  await nextTick();
  document.getElementById('secret-editor-rotate-value')?.focus();
}

async function handleTrayMenuAction(action: TrayMenuAction): Promise<void> {
  switch (action) {
    case 'open-app':
      currentView.value = projectConnected.value ? 'secrets' : 'dashboard';
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
      if (selectedIsShared.value) break;
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

async function paletteMcpJson(): Promise<string> {
  const snippet = await desktopMcpConfigSnippet();
  if (snippet.ok && typeof snippet.value?.json === 'string') return snippet.value.json;
  return mcpClientSnippets('locket', ['mcp']).json;
}

async function copyPaletteText(text: string | Promise<string>, label: string): Promise<void> {
  const isCurrent = metadataClipboardRequests.begin();
  const value = await text;
  if (!isCurrent()) return;
  const result = await desktopCopyTextPlain(value);
  if (!isCurrent()) return;
  paletteMessage.value = result.ok ? `Copied ${label}.` : `Could not copy ${label}.`;
}

type RunnablePaletteAction = PaletteAction & { run: () => void | Promise<void> };
const paletteActions = computed<RunnablePaletteAction[]>(() => {
  const redact = settings.value.privacyRedactNames;
  const views = [
    ...primaryItems,
    { key: 'discover' as const, label: 'Discover', icon: 'compass' as const },
    { key: 'team' as const, label: 'Team', icon: 'users' as const },
    ...(projectConnected.value && !selectedIsShared.value
      ? [{ key: 'dashboard' as const, label: 'Project overview', icon: 'folder' as const }]
      : []),
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
    id: 'add-secret',
    group: 'Quick actions',
    icon: 'plus',
    badge: 'Action',
    label: 'Add secret',
    run: addSecret,
  });
  if (desktopAvailable) {
    actions.push(
      {
        id: 'copy-agent-prompt',
        group: 'Quick actions',
        icon: 'copy',
        label: 'Copy AI agent .env migration prompt',
        keywords: 'dotenv import claude codex',
        run: () =>
          copyPaletteText(
            dotenvMigrationPrompt({ isShared: selectedIsShared.value }),
            'AI migration prompt',
          ),
      },
      {
        id: 'copy-mcp-json',
        group: 'Quick actions',
        icon: 'copy',
        label: 'Copy MCP config JSON',
        run: () => copyPaletteText(paletteMcpJson(), 'MCP JSON'),
      },
    );
  }
  actions.push({
    id: 'project:shared',
    group: 'Projects',
    icon: 'key',
    badge: 'Vault',
    label: redact ? 'Global Vault' : 'Global Vault (@shared)',
    detail: 'Personal secrets across projects and MCP',
    keywords: 'shared global vault personal',
    run: async () => {
      if (await openSharedVault({ autoUnlock: !hasSharedVault.value })) selectView('secrets');
    },
  });
  knownFolderProjects.value.forEach((project, index) => {
    actions.push({
      id: `project:${index}`,
      group: 'Projects',
      icon: 'folder',
      badge: 'Project',
      label: redact ? `Project ${index + 1}` : project.project_name,
      detail: redact ? 'Open project' : project.root,
      keywords: 'open project',
      run: async () => {
        if (await connectProject(false, project.root)) selectView('secrets');
      },
    });
  });
  if (!secretAccess.value.enabled) return actions;
  secretRows.value.forEach((row, index) => {
    const name = secretLabel(row, redact);
    actions.push({
      id: `secret:${index}`,
      group: 'Secrets',
      icon: 'key',
      badge: 'Secret',
      label: name,
      run: () => selectSecret(row),
    });
    const reference = secretReference(activeContext.value?.profile_name, row.name, redact);
    if (reference) {
      actions.push({
        id: `reference:${index}`,
        group: 'Secrets',
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
  const known = knownProjects.value.find((project) => project.project_id === row.project_id);
  if (known?.is_shared) {
    if (await openSharedVault({ projectId: known.project_id })) selectView('secrets');
    return;
  }
  const root =
    known?.root ?? (settings.value.privacyRedactNames ? undefined : row.trusted_roots[0]);
  if (root && (await connectProject(false, root))) selectView('secrets');
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
const dangerousProfileName = ref('');
const dangerousProfileInput = ref('');
const dangerousProfileMatches = computed(
  () =>
    dangerousProfileName.value !== '' && dangerousProfileInput.value === dangerousProfileName.value,
);

function submitDangerousConfirmation(): void {
  if (dangerousProfileMatches.value) dangerousConfirmDialog.value?.close('confirm');
}

async function confirmDangerousAction(
  action: string,
  force = false,
): Promise<string | false | undefined> {
  if (!force && !settings.value.dangerousProfileFlag) return false;
  const dialog = dangerousConfirmDialog.value;
  if (!dialog || dangerousProfileName.value) return;
  const generation = selectionGeneration.value;
  const profile = activeContext.value;
  if (!profile?.profile_name) return;
  dangerousAction.value = action;
  dangerousProfileName.value = profile.profile_name;
  dangerousProfileInput.value = '';
  dialog.returnValue = '';
  const approved = await new Promise<boolean>((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), {
      once: true,
    });
    dialog.showModal();
  });
  const typed = dangerousProfileInput.value;
  dangerousProfileName.value = '';
  dangerousProfileInput.value = '';
  if (
    approved &&
    generation === selectionGeneration.value &&
    profile.profile_id === activeContext.value?.profile_id &&
    profile.profile_name === activeContext.value?.profile_name &&
    typed === profile.profile_name
  ) {
    return typed;
  }
}

watch(
  [
    selectionGeneration,
    () => activeContext.value?.profile_id,
    () => activeContext.value?.profile_name,
    () => status.value?.lock_state,
  ],
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
    ...(approved && { confirm_dangerous_profile: approved }),
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
      return err.code === 'ConfirmationFailed' ? err.message : err.code;
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
    ...(approved && { confirm_dangerous_profile: approved }),
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
  const generation = selectionGeneration.value;
  await refresh();
  if (generation !== selectionGeneration.value) return;
  await Promise.all([
    refreshSecrets(),
    refreshVersions(),
    refreshRuntimeSessions(),
    refreshDeviceMembers(),
    refreshPolicies(),
    refreshAuditLog(),
  ]);
  if (generation === selectionGeneration.value) await verifyAuditChain();
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
  if (!projectId || selectedIsShared.value) {
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

const detectedCommands = ref<DetectedCommandRow[]>([]);
const detectingCommands = ref(false);
const detectionError = ref<string | null>(null);
const detectionRequests = createRequestLifetime();
const detectionProject = computed(() =>
  currentView.value === 'policies' &&
  !!activeContext.value?.root &&
  !selectedIsShared.value &&
  !desktopBusy.value &&
  agentOnline.value &&
  settingsReady.value &&
  !settings.value.privacyRedactNames
    ? activeContext.value?.project_id
    : undefined,
);

async function refreshDetectedCommands(): Promise<void> {
  const isCurrent = detectionRequests.begin();
  const projectId = detectionProject.value;
  detectingCommands.value = Boolean(projectId);
  detectionError.value = null;
  if (!projectId) return;
  const result = await desktopDetectCommands({ project_id: projectId });
  if (!isCurrent()) return;
  detectingCommands.value = false;
  detectedCommands.value = result.ok ? result.value : [];
  if (!result.ok) detectionError.value = actionError(result.error);
}

watch(
  [selectionGeneration, detectionProject],
  () => {
    detectedCommands.value = [];
    void refreshDetectedCommands();
  },
  { immediate: true, flush: 'sync' },
);

async function refreshCommandView(): Promise<void> {
  await Promise.all([refreshPolicies(), refreshDetectedCommands()]);
}

const profileSwitchState = ref<ProfileSwitchState>({
  activeProfile: null,
  activeDangerous: false,
  recentTargets: [],
});
const profileSwitchInProgress = ref<boolean>(false);
const profileSwitchError = ref<string | null>(null);
const profileSwitchLastAt = ref<string | undefined>(undefined);
const discoverProfileTarget = ref<{ name: string; dangerous: boolean } | null>(null);
const profileCreateBusy = ref(false);
const profileCreateNotice = ref<string | null>(null);
const profileCreateError = ref<string | null>(null);
const profileCreateRequests = createRequestLifetime();
const profileListRevision = ref(0);
const canCreateProfile = computed(
  () =>
    desktopAvailable &&
    !!activeContext.value?.root &&
    !selectedIsShared.value &&
    agentOnline.value &&
    settingsReady.value &&
    status.value?.lock_state === 'unlocked' &&
    !desktopBusy.value &&
    !profileSwitchInProgress.value,
);

watch(
  [settingsContextKey, () => settings.value.privacyRedactNames],
  () => {
    profileCreateRequests.invalidate();
    profileCreateBusy.value = false;
    profileCreateNotice.value = null;
    profileCreateError.value = null;
  },
  { flush: 'sync' },
);

async function handleProfileCreate(name: string): Promise<void> {
  const context = activeContext.value;
  if (!context || !canCreateProfile.value || profileCreateBusy.value || !isValidProfileName(name))
    return;
  const isCurrent = profileCreateRequests.begin();
  profileCreateBusy.value = true;
  profileCreateNotice.value = null;
  profileCreateError.value = null;
  const result = await desktopCreateProfile({
    project_id: context.project_id,
    profile_name: name.trim(),
  });
  if (!isCurrent()) return;
  profileCreateBusy.value = false;
  if (!result.ok) {
    profileCreateError.value =
      result.error.kind === 'rejected' && result.error.code === 'SecretAlreadyExists'
        ? 'An environment with this name already exists.'
        : actionError(result.error);
    return;
  }
  profileListRevision.value++;
  const label = settings.value.privacyRedactNames ? '' : ` ${result.value.profile_name}`;
  profileCreateNotice.value = result.value.created
    ? `Created environment${label}.`
    : `Environment${label} already exists.`;
}

watch(currentView, (view) => {
  if (view !== 'profiles') discoverProfileTarget.value = null;
  profileSwitchError.value = null;
});

watch(
  [currentView, settingsContextKey, () => settings.value.privacyRedactNames, profileListRevision],
  async ([view, context, redact], [previousView, previousContext, previousRedact], onCleanup) => {
    if (view !== previousView || context !== previousContext || redact !== previousRedact)
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
  if (
    !captured ||
    !activeContext.value ||
    profileSwitchInProgress.value ||
    profileCreateBusy.value
  ) {
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
const policyFormDraft = ref<Pick<
  PolicyFormState,
  'name' | 'commandKind' | 'commandPreview'
> | null>(null);
const policyFormSubmitting = ref<boolean>(false);
const policyFormError = ref<string | null>(null);
const policyFormRequests = createRequestLifetime();

function openPolicyCreate(detected?: DetectedCommandRow): void {
  if (!policyAccess.value.enabled) return;
  if (detected && !detectionProject.value) return;
  policyFormMode.value = 'create';
  policyFormRow.value = null;
  policyFormDraft.value = detected
    ? { name: detected.name, commandKind: 'argv', commandPreview: detected.command_preview }
    : null;
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
  policyFormRequests.invalidate();
  policyFormMode.value = null;
  policyFormRow.value = null;
  policyFormDraft.value = null;
  policyFormSubmitting.value = false;
  policyFormError.value = null;
}

watch(settingsContextKey, dismissPolicyForm, { flush: 'sync' });

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
  if (policyFormSubmitting.value) return;
  const isCurrent = policyFormRequests.begin();
  policyFormSubmitting.value = true;
  policyFormError.value = null;
  const result = await desktopSavePolicy({
    project_id: projectId,
    mode: payload.mode,
    original_name: payload.originalName,
    policy: payload.snapshot,
    confirmation: payload.confirmation,
  });
  if (!isCurrent()) return;
  policyFormSubmitting.value = false;
  if (!result.ok) {
    policyFormError.value = actionError(result.error);
    return;
  }
  dismissPolicyForm();
  await refreshCommandView();
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

async function verifyAuditChain(): Promise<void> {
  const request = auditRequest.value;
  const generation = selectionGeneration.value;
  auditChainOk.value = null;
  if (request === null) return;
  const result = await verifyAudit({ project_id: request.project_id });
  if (
    generation !== selectionGeneration.value ||
    auditRequest.value?.project_id !== request.project_id
  )
    return;
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
  if (
    selectedIsShared.value ||
    scanLaunching.value ||
    desktopBusy.value ||
    profileSwitchInProgress.value
  )
    return;
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
      return error.code === 'ConfirmationFailed' ? error.message : error.code;
    default:
      return 'Backup request failed.';
  }
}

async function triggerBackupAction(action: BundleAction): Promise<void> {
  if (backupBusy.value) return;
  backupNotice.value = null;
  backupError.value = null;
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    backupError.value = 'Active project unavailable.';
    return;
  }

  const isCurrent = backupRequests.begin();
  backupBusy.value = true;
  try {
    switch (action.kind) {
      case 'export': {
        if (
          !action.request.previewOnly &&
          backupPreviewKey.value !== exportSelectionKey(action.request)
        ) {
          backupError.value = 'Preview the current export scope before exporting.';
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
          confirm_dangerous_profile: action.request.confirmDangerousProfile || undefined,
        });
        if (!isCurrent()) return;
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
          confirm_dangerous_profile: action.request.confirmDangerousProfile || undefined,
        });
        if (!isCurrent()) return;
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
        if (!isCurrent()) return;
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
        if (!isCurrent()) return;
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
  } finally {
    if (isCurrent()) backupBusy.value = false;
  }
}

async function handleSetSecret(
  payload: SetSecretRequest,
): Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }> {
  const context = settingsContextKey.value;
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Save secret')
    : false;
  if (approved === undefined || context !== settingsContextKey.value)
    return { ok: false, error: { kind: 'protocol', reason: 'Action canceled.' } };
  const result = await setSecret(
    approved ? { ...payload, confirm_dangerous_profile: approved } : payload,
  );
  if (result.ok && context === settingsContextKey.value) {
    await refreshSecrets();
  }
  return result;
}

async function handleRotateSecret(
  payload: SetSecretRequest,
): Promise<{ ok: true; value: SetSecretResponse } | { ok: false; error: AgentClientError }> {
  const context = settingsContextKey.value;
  const approved = settings.value.dangerousProfileFlag
    ? await confirmDangerousAction('Rotate secret')
    : false;
  if (approved === undefined || context !== settingsContextKey.value)
    return { ok: false, error: { kind: 'protocol', reason: 'Action canceled.' } };
  const result = await rotateSecret(
    approved ? { ...payload, confirm_dangerous_profile: approved } : payload,
  );
  if (result.ok && context === settingsContextKey.value) {
    await refreshSecrets();
    await refreshVersions();
  }
  return result;
}

const secretMutationBusy = ref(false);
const secretMutationError = ref<{ id: string; message: string } | null>(null);
const secretMutationRequests = createRequestLifetime();
const secretMutationAvailable = computed(
  () =>
    desktopAvailable &&
    secretAccess.value.enabled &&
    settingsReady.value &&
    !settings.value.privacyRedactNames &&
    !desktopBusy.value &&
    !secretMutationBusy.value,
);

watch(
  [settingsContextKey, () => settings.value.privacyRedactNames],
  () => {
    secretMutationRequests.invalidate();
    rotationTarget.value = null;
    secretMutationBusy.value = false;
    secretMutationError.value = null;
    if (settings.value.privacyRedactNames) desktopNotice.value = null;
  },
  { flush: 'sync' },
);

async function handleDeleteSecret(row: SecretRowMeta, confirmation?: string): Promise<void> {
  const context = activeContext.value;
  if (!context || !secretMutationAvailable.value) return;
  const dangerous = settings.value.dangerousProfileFlag;
  if (dangerous && confirmation !== context.profile_name) return;

  const isCurrent = secretMutationRequests.begin();
  secretMutationBusy.value = true;
  secretMutationError.value = null;
  desktopNotice.value = null;
  const result = await desktopDeleteSecret({
    project_id: context.project_id,
    profile_id: context.profile_id,
    secret_name: row.name,
    source: secretSourceWire(row.source),
    ...(dangerous && { confirmation: context.profile_name }),
  });
  if (!isCurrent()) return;
  secretMutationBusy.value = false;
  if (!result.ok || !result.value.deleted) {
    secretMutationError.value = {
      id: row.id,
      message: result.ok ? 'The secret could not be deleted.' : actionError(result.error),
    };
    return;
  }
  if (selectedSecret.value?.id === row.id) selectedSecret.value = null;
  desktopNotice.value = `Deleted ${row.name}.`;
  await Promise.all([refreshSecrets(), refreshVersions()]);
}

function copyToSharedError(error: AgentClientError, name: string): string {
  if (error.kind === 'rejected') {
    if (error.code === 'SecretAlreadyExists') {
      return `${name} already exists in Global Vault. Open Global Vault to review the existing secret.`;
    }
    if (error.code === 'UnlockRequired' && error.message.includes('Global Vault')) {
      return 'Open and unlock Global Vault (@shared), then return here and try again.';
    }
    if (error.code === 'ProjectNotFound' && error.message.includes('Global Vault')) {
      return 'Set up Global Vault (@shared), then return here and try again.';
    }
  }
  return actionError(error);
}

async function handleCopyToShared(row: SecretRowMeta): Promise<void> {
  const context = activeContext.value;
  if (!context || selectedIsShared.value || !secretMutationAvailable.value) return;
  const isCurrent = secretMutationRequests.begin();
  secretMutationBusy.value = true;
  secretMutationError.value = null;
  desktopNotice.value = null;
  const approved = await confirmDangerousAction('Copy secret to Global Vault');
  if (!isCurrent()) return;
  if (approved === undefined) {
    secretMutationBusy.value = false;
    return;
  }
  const result = await desktopCopySecretToShared({
    from_project_id: context.project_id,
    from_profile_id: context.profile_id,
    secret_name: row.name,
    source: secretSourceWire(row.source),
    ...(approved && { confirmation: approved }),
  });
  if (!isCurrent()) return;
  secretMutationBusy.value = false;
  if (!result.ok) {
    secretMutationError.value = { id: row.id, message: copyToSharedError(result.error, row.name) };
    return;
  }
  desktopNotice.value = `Copied ${row.name} to Global Vault.`;
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
      ? (result.value.find((project) => !project.is_shared) ?? result.value[0])
      : initialProjectSelection(result.value, selectedProject.value);
    if (!selectedProject.value && initial) {
      if (initial.is_shared) {
        await openSharedVault({ projectId: initial.project_id });
      } else {
        await connectProject(false, initial.root);
      }
    }
  } else if (generation === selectionGeneration.value && desktopAvailable)
    desktopError.value = actionError(result.error);
}

async function openSharedVault({
  projectId,
  autoUnlock = false,
}: { projectId?: string; autoUnlock?: boolean } = {}): Promise<boolean> {
  if (desktopBusy.value) return false;
  selectionGeneration.value++;
  profileSwitchInProgress.value = false;
  profileSwitchError.value = null;
  pendingInitFolder.value = null;
  manualConnectOpen.value = false;
  dismissVaultSwitcher();
  desktopBusy.value = true;
  desktopError.value = null;
  desktopNotice.value = null;
  const result = await desktopOpenSharedVault(projectId ? { project_id: projectId } : undefined);
  if (!result.ok) {
    desktopError.value = actionError(result.error);
    desktopBusy.value = false;
    return false;
  }
  const showPreviewUnlock = !selectedProject.value && previewParams?.get('modal') === 'unlock';
  selectedProject.value = result.value;
  const generation = selectionGeneration.value;
  selectedSecret.value = null;
  unlockOpen.value = showPreviewUnlock;
  projectPath.value = '';
  if (autoUnlock || currentView.value === 'dashboard' || currentView.value === 'profiles') {
    currentView.value = 'secrets';
  }
  await refreshProjectConnections();
  await refresh();
  desktopBusy.value = false;
  if (autoUnlock) await unlockAfterOpening(generation);
  return generation === selectionGeneration.value;
}

async function inspectAndConnectPath(rawPath = projectPath.value): Promise<void> {
  const trimmed = rawPath.trim();
  if (desktopBusy.value || !trimmed) return;
  desktopError.value = null;
  desktopNotice.value = null;
  desktopBusy.value = true;
  const inspected = await desktopInspectProjectFolder({ path: trimmed });
  desktopBusy.value = false;
  if (!inspected.ok) {
    pendingInitFolder.value = null;
    desktopError.value = actionError(inspected.error);
    return;
  }
  projectPath.value = inspected.value.path;
  if (inspected.value.has_config) {
    pendingInitFolder.value = null;
    await connectProject(false, inspected.value.path);
  } else {
    pendingInitFolder.value = inspected.value;
    await nextTick();
    pendingInitHeading.value?.focus?.();
  }
}

async function handleWelcomePickFolder(path: string): Promise<void> {
  projectPath.value = path;
  await inspectAndConnectPath(path);
}

async function confirmInitializeFolder(): Promise<void> {
  const folder = pendingInitFolder.value;
  if (!folder) return;
  pendingInitFolder.value = null;
  await connectProject(true, folder.path);
}

async function cancelFolderConnection(): Promise<void> {
  const returnToPath = manualConnectOpen.value && pendingInitFolder.value;
  pendingInitFolder.value = null;
  if (!returnToPath) {
    manualConnectOpen.value = false;
    projectPath.value = selectedProject.value?.root ?? '';
  }
  await nextTick();
  const target = returnToPath
    ? manualConnectPath.value
    : (connectProjectTrigger.value ?? vaultSwitcherTrigger.value);
  target?.focus?.();
}

async function pickProjectFolder(): Promise<void> {
  dismissVaultSwitcher();
  if (!desktopAvailable || desktopBusy.value) return;
  desktopBusy.value = true;
  const picked = await desktopPickDirectory('Choose a project folder');
  desktopBusy.value = false;
  if (!picked.ok) {
    if (projectConnected.value) {
      pendingInitFolder.value = null;
      projectPath.value = '';
      manualConnectOpen.value = true;
      await nextTick();
      manualConnectPath.value?.focus?.();
    } else {
      selectView('dashboard');
    }
    return;
  }
  if (picked.value) await inspectAndConnectPath(picked.value);
}

async function connectProject(initialize = false, path = projectPath.value): Promise<boolean> {
  if (desktopBusy.value || !path.trim()) return false;
  const wasUnconnected = selectedProject.value === null;
  selectionGeneration.value++;
  profileSwitchInProgress.value = false;
  profileSwitchError.value = null;
  pendingInitFolder.value = null;
  dismissVaultSwitcher();
  desktopBusy.value = true;
  desktopError.value = null;
  desktopNotice.value = null;
  const result = initialize
    ? await desktopInitializeProject({ path: path.trim() })
    : await desktopOpenProject({ path: path.trim() });
  if (!result.ok) {
    desktopError.value = actionError(result.error);
    desktopBusy.value = false;
    return false;
  }
  const showPreviewUnlock = !selectedProject.value && previewParams?.get('modal') === 'unlock';
  selectedProject.value = result.value;
  const generation = selectionGeneration.value;
  selectedSecret.value = null;
  unlockOpen.value = showPreviewUnlock;
  projectPath.value = result.value.root;
  manualConnectOpen.value = false;
  if (
    initialize ||
    (wasUnconnected &&
      currentView.value === 'dashboard' &&
      (!previewParams || previewParams.get('state') === 'welcome'))
  ) {
    currentView.value = 'secrets';
  }
  await refreshProjectConnections();
  await refresh();
  desktopBusy.value = false;
  if (initialize) await unlockAfterOpening(generation);
  return generation === selectionGeneration.value;
}

async function unlockAfterOpening(generation: number): Promise<void> {
  if (
    generation === selectionGeneration.value &&
    agentOnline.value &&
    lockLabel.value === 'Locked'
  ) {
    await handleUnlock({ kind: 'os-keychain' }, 'silent');
  }
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
function openUnlock(preferPassphrase = false): void {
  unlockError.value = null;
  if (!projectConnected.value) {
    currentView.value = 'dashboard';
    desktopError.value = 'Connect a project before unlocking.';
    return;
  }
  unlockWithPassphrase.value = preferPassphrase;
  unlockOpen.value = true;
}
async function handleUnlock(
  source: UnlockRequest['source'],
  onError: 'show' | 'open-modal' | 'silent' = 'show',
): Promise<void> {
  const projectId = selectedProject.value?.project_id ?? status.value?.project_id;
  if (!projectId || unlockBusy.value || desktopBusy.value) return;
  const isCurrent = unlockRequests.begin();
  unlockBusy.value = true;
  unlockError.value = null;
  const profileId = selectedProject.value?.profile_id;
  try {
    const result = await unlockVault({
      project_id: projectId,
      ttl_seconds: unlockTtl(settings.value.unlockTtlSeconds),
      source,
      ...(profileId ? { audit: { profile_id: profileId } } : {}),
    });
    if (source.kind === 'passphrase') source.passphrase = '';
    if (!isCurrent()) return;
    if (result.ok) {
      unlockOpen.value = false;
      await triggerVerify();
    } else if (onError !== 'silent') {
      if (onError === 'open-modal') openUnlock();
      unlockError.value = actionError(result.error);
    }
  } finally {
    if (isCurrent()) unlockBusy.value = false;
  }
}
function resetEnvImport(): void {
  envPickerRequests.invalidate();
  envPickerBusy.value = false;
  envPickerFailed.value = false;
  envImportOpen.value = false;
  envPath.value = selectedIsShared.value ? '' : '.env';
  importOverwrite.value = false;
  importConfirmation.value = '';
  importLiteral.value = false;
}

async function pickEnvForImport(): Promise<void> {
  if (!canImportEnv.value || envPickerBusy.value || desktopBusy.value) return;
  const isCurrent = envPickerRequests.begin();
  envPickerBusy.value = true;
  const result = await desktopPickFile({ title: 'Browse for an env file' });
  if (!isCurrent()) return;
  envPickerBusy.value = false;
  if (result.ok && !result.value) return;
  envPickerFailed.value = !result.ok;
  if (result.ok && result.value) envPath.value = result.value;
  envImportOpen.value = true;
  await nextTick();
  envImportHeading.value?.focus?.();
}

const canSubmitEnvImport = computed(
  () =>
    envImportOpen.value &&
    canImportEnv.value &&
    !desktopBusy.value &&
    !envPickerBusy.value &&
    settingsReady.value &&
    secretAccess.value.enabled &&
    envPathReady.value &&
    (!settings.value.dangerousProfileFlag ||
      importConfirmation.value === activeContext.value?.profile_name),
);

async function importEnv(): Promise<void> {
  const projectId = activeContext.value?.project_id;
  if (!projectId || !canSubmitEnvImport.value) return;
  desktopBusy.value = true;
  desktopError.value = null;
  desktopNotice.value = null;
  const context = settingsContextKey.value;
  try {
    const result = await desktopImportEnv({
      project_id: projectId,
      path: envPath.value.trim(),
      overwrite: importOverwrite.value,
      literal: importLiteral.value,
      confirmation: importConfirmation.value || undefined,
    });
    if (context !== settingsContextKey.value) return;
    if (!result.ok) desktopError.value = actionError(result.error);
    else {
      desktopNotice.value = result.value.summary;
      resetEnvImport();
      await refreshSecrets();
    }
  } finally {
    desktopBusy.value = false;
  }
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
  },
);

watch(
  settingsContextKey,
  () => {
    backupRequests.invalidate();
    backupBusy.value = false;
    backupNotice.value = null;
    backupError.value = null;
    backupPreviewKey.value = null;
    backupPreviewMessage.value = null;
  },
  { flush: 'sync' },
);

onMounted(() => {
  window.addEventListener('pointerdown', onSwitcherPointerdown);
  void refreshProjectConnections();
  if (previewParams) {
    if (previewParams.get('state') === 'welcome') void refresh();
    return;
  }
  void listen<TrayMenuAction>('tray-menu-action', (event) => {
    void handleTrayMenuAction(event.payload);
  })
    .then((unlisten) => {
      unlistenTrayMenu = unlisten;
    })
    .catch(() => {});
});

onBeforeUnmount(() => {
  window.removeEventListener('pointerdown', onSwitcherPointerdown);
  clearTimeout(desktopNoticeTimer);
  metadataClipboardRequests.dispose();
  backupRequests.dispose();
  copyRequests.dispose();
  settingsRequests.dispose();
  profileCreateRequests.dispose();
  secretMutationRequests.dispose();
  policyFormRequests.dispose();
  detectionRequests.dispose();
  scanRequests.dispose();
  unlockRequests.dispose();
  envPickerRequests.dispose();
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
        <div
          ref="vaultSwitcherRef"
          class="shell__switcher"
          @keydown.esc="dismissVaultSwitcher"
          @focusout="onSwitcherFocusout"
        >
          <button
            ref="vaultSwitcherTrigger"
            class="companion-button shell__context"
            type="button"
            :title="
              projectConnected
                ? `${switcherLabel} — ${connectionLabel} · Vault ${lockLabel}`
                : 'Choose a vault or connect a project folder'
            "
            :aria-label="
              projectConnected
                ? `Switch vault or project (${switcherLabel}). Agent ${connectionLabel}. Vault ${lockLabel}.`
                : 'Choose a vault or project'
            "
            :aria-expanded="vaultSwitcherOpen"
            :aria-controls="vaultSwitcherOpen ? 'vault-switcher-menu' : undefined"
            @click="vaultSwitcherOpen = !vaultSwitcherOpen"
          >
            <span class="shell__context-dot" :data-online="agentOnline" aria-hidden="true" />
            <span>{{ switcherLabel }}</span>
            <AppIcon name="chevron-down" :size="13" />
          </button>
          <div
            v-if="vaultSwitcherOpen"
            id="vault-switcher-menu"
            class="shell__switcher-menu"
            role="group"
            aria-label="Vaults and projects"
          >
            <div class="shell__switcher-group">
              <span class="shell__switcher-heading">Global Vault</span>
              <button
                type="button"
                class="shell__switcher-item"
                :aria-current="selectedIsShared ? 'true' : undefined"
                :disabled="desktopBusy || !desktopAvailable"
                @click="openSharedVault({ autoUnlock: !hasSharedVault })"
              >
                <AppIcon name="key" :size="14" />
                <span class="shell__switcher-text">
                  <strong>{{
                    settings.privacyRedactNames ? 'Global Vault' : 'Global Vault (@shared)'
                  }}</strong>
                  <small>{{ hasSharedVault ? 'Personal secrets & MCP' : 'Create now' }}</small>
                </span>
                <AppIcon v-if="selectedIsShared" name="check" :size="14" />
              </button>
            </div>
            <div v-if="knownFolderProjects.length" class="shell__switcher-group">
              <span class="shell__switcher-heading">Projects</span>
              <button
                v-for="project in knownFolderProjects"
                :key="project.project_id"
                type="button"
                class="shell__switcher-item"
                :aria-current="
                  selectedProject?.project_id === project.project_id ? 'true' : undefined
                "
                :disabled="desktopBusy"
                @click="connectProject(false, project.root)"
              >
                <AppIcon name="folder" :size="14" />
                <span class="shell__switcher-text">
                  <strong>{{
                    settings.privacyRedactNames ? 'Project' : project.project_name
                  }}</strong>
                  <small v-if="!settings.privacyRedactNames">{{
                    shortenProjectPath(project.root)
                  }}</small>
                </span>
                <AppIcon
                  v-if="selectedProject?.project_id === project.project_id"
                  name="check"
                  :size="14"
                />
              </button>
            </div>
            <div class="shell__switcher-group shell__switcher-actions">
              <button
                type="button"
                class="shell__switcher-item"
                :disabled="desktopBusy || !desktopAvailable"
                @click="pickProjectFolder"
              >
                <AppIcon name="plus" :size="14" />
                <span class="shell__switcher-text"><strong>Connect project folder…</strong></span>
              </button>
              <button
                v-if="projectConnected && !selectedIsShared"
                type="button"
                class="shell__switcher-item"
                @click="selectView('profiles')"
              >
                <AppIcon name="compass" :size="14" />
                <span class="shell__switcher-text">
                  <strong>Switch environment</strong>
                  <small>{{ profileLabel }}</small>
                </span>
              </button>
              <button
                v-if="projectConnected && !selectedIsShared"
                type="button"
                class="shell__switcher-item"
                @click="selectView('dashboard')"
              >
                <AppIcon name="folder" :size="14" />
                <span class="shell__switcher-text"><strong>Project overview</strong></span>
              </button>
            </div>
          </div>
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
          <li v-for="item in primaryItems" :key="item.key">
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
        </ul>
      </nav>

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
    </aside>

    <main class="shell__main">
      <div
        v-if="!(currentView === 'dashboard' && !projectConnected)"
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
        class="shell__unlock-bar"
        aria-label="Vault actions"
      >
        <div class="shell__unlock-copy">
          <AppIcon name="lock" :size="16" />
          <span>
            <strong>{{ switcherLabel }} is locked.</strong>
            Unlock to view and edit secrets.
          </span>
        </div>
        <div class="shell__unlock-actions">
          <button
            type="button"
            class="companion-button companion-button--primary icon-label"
            :disabled="!desktopAvailable || desktopBusy || unlockBusy"
            @click="handleUnlock({ kind: 'os-keychain' }, 'open-modal')"
          >
            <AppIcon name="unlock" />
            Unlock with keychain
          </button>
          <button
            type="button"
            class="companion-button"
            :disabled="!desktopAvailable || desktopBusy || unlockBusy"
            @click="openUnlock(true)"
          >
            Use passphrase
          </button>
        </div>
      </div>
      <section
        v-if="currentView === 'secrets' && envImportOpen"
        class="shell__panel"
        aria-labelledby="import-heading"
      >
        <h2 id="import-heading" ref="envImportHeading" tabindex="-1">
          Import .env · {{ profileLabel }}
        </h2>
        <p v-if="secretAccess.guidance" role="status">{{ secretAccess.guidance }}</p>
        <p v-if="envPickerFailed" role="status">Could not open the picker. Enter a path manually.</p>
        <form @submit.prevent="importEnv">
          <label>
            File path
            <input
              v-model="envPath"
              type="text"
              autocomplete="off"
              aria-describedby="env-path-hint"
              :placeholder="selectedIsShared ? '/path/to/.env' : undefined"
              :disabled="desktopBusy"
            />
          </label>
          <button
            class="companion-button icon-label"
            type="button"
            aria-label="Browse for an env file"
            :disabled="!canImportEnv || desktopBusy || envPickerBusy"
            @click="pickEnvForImport"
          >
            <AppIcon name="folder" /> Browse…
          </button>
          <p v-if="selectedIsShared" id="env-path-hint">
            Choose an absolute path to a <code>.env</code> file.
          </p>
          <p v-else id="env-path-hint">Relative paths start in the connected project.</p>
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
          <button type="submit" :disabled="!canSubmitEnvImport">
            {{ desktopBusy ? 'Importing…' : 'Import secrets' }}
          </button>
          <button type="button" :disabled="desktopBusy" @click="resetEnvImport">Cancel import</button>
        </form>
      </section>
      <p v-if="desktopError" role="alert" class="shell__notice shell__notice--error">
        <AppIcon name="alert" />{{ desktopError }}
      </p>
      <p v-if="desktopNotice" role="status" class="shell__notice shell__notice--success">
        <AppIcon name="check" />{{ desktopNotice }}
      </p>

      <section
        v-if="projectConnected && pendingInitFolder"
        class="shell__panel"
        aria-labelledby="initialize-folder-heading"
      >
        <h2 id="initialize-folder-heading" ref="pendingInitHeading" tabindex="-1">
          Initialize Locket in this folder?
        </h2>
        <p>
          {{ settings.privacyRedactNames ? 'This folder' : pendingInitFolder.folder_name }} has no
          <code>locket.toml</code> yet.
        </p>
        <div class="shell__toolbar">
          <button
            type="button"
            class="companion-button companion-button--primary"
            :disabled="desktopBusy"
            @click="confirmInitializeFolder"
          >
            Initialize &amp; open
          </button>
          <button type="button" class="companion-button" @click="cancelFolderConnection">
            Cancel
          </button>
        </div>
      </section>
      <section
        v-else-if="manualConnectOpen"
        class="shell__panel"
        aria-labelledby="manual-connect-heading"
      >
        <h2 id="manual-connect-heading">Connect a project folder</h2>
        <form class="shell__project-form" @submit.prevent="inspectAndConnectPath()">
          <div class="shell__project-field">
            <label for="manual-project-path">Project folder</label>
            <input
              id="manual-project-path"
              ref="manualConnectPath"
              v-model="projectPath"
              type="text"
              placeholder="/path/to/project"
              autocomplete="off"
              spellcheck="false"
              :disabled="desktopBusy"
            />
          </div>
          <div class="shell__toolbar">
            <button
              type="submit"
              class="companion-button companion-button--primary"
              :disabled="desktopBusy || !projectPath.trim()"
            >
              Connect folder
            </button>
            <button type="button" class="companion-button" @click="cancelFolderConnection">
              Cancel
            </button>
          </div>
        </form>
      </section>

      <WelcomeView
        v-if="currentView === 'dashboard' && !projectConnected"
        :agent-online="agentOnline"
        :agent-version="settings.agentVersion"
        :desktop-available="desktopAvailable"
        :busy="desktopBusy"
        :privacy-mode="settings.privacyRedactNames"
        :project-path="projectPath"
        :known-projects="knownProjects"
        :pending-init-folder="pendingInitFolder"
        @update:project-path="
          (value) => {
            projectPath = value;
            pendingInitFolder = null;
          }
        "
        @open-shared="openSharedVault({ autoUnlock: true })"
        @pick-folder="handleWelcomePickFolder"
        @connect-path="inspectAndConnectPath()"
        @confirm-init="confirmInitializeFolder"
        @cancel-init="pendingInitFolder = null"
        @open-known="
          (project) =>
            project.is_shared
              ? openSharedVault({ projectId: project.project_id, autoUnlock: true })
              : connectProject(false, project.root)
        "
        @start-agent="startAgent"
      />

      <ProjectDashboard
        v-else-if="currentView === 'dashboard'"
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
                      !activeProjectFolder &&
                      Boolean(projectPath.trim()) &&
                      (agentOnline || !shellAgentError),
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
            <div v-if="knownFolderProjects.length" class="shell__known-projects">
              <h3>Known projects</h3>
              <ul>
                <li v-for="project in knownFolderProjects" :key="project.project_id">
                  <button
                    class="companion-button shell__known-project"
                    type="button"
                    :aria-current="
                      selectedProject?.project_id === project.project_id ? 'true' : undefined
                    "
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
                      v-if="selectedProject?.project_id === project.project_id"
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
        :is-shared="selectedIsShared"
        :can-import-env="canImportEnv"
        :import-busy="desktopBusy || envPickerBusy"
        :dangerous-profile="settings.dangerousProfileFlag"
        :mutation-disabled="!secretMutationAvailable"
        :mutation-error="secretMutationError"
        :action-guidance="secretAccess.guidance"
        @select="selectSecret"
        @copy-value="handleListCopy"
        @reveal-value="handleEditorReveal"
        @copy-to-shared="handleCopyToShared"
        @delete-secret="handleDeleteSecret"
        @refresh="retryVariables"
        @retry="retryVariables"
        @start="startAgent"
        @add="addSecret"
        @rotate="rotateListedSecret"
        @import-env="pickEnvForImport"
        @open-agent-setup="selectView('settings')"
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
        :key="`${settingsContextKey}:${rotationTarget?.id ?? 'add'}`"
        :rows="secretRows"
        :privacy-mode="settings.privacyRedactNames"
        :loading="secretsLoading"
        :error-message="secretsError"
        :last-refreshed-at="secretsLastRefreshed"
        :metadata-loaded="secretAccess.enabled"
        :action-guidance="secretAccess.guidance"
        :project-id="activeContext?.project_id"
        :profile-id="activeContext?.profile_id"
        :rotation-target="rotationTarget"
        :on-set-secret="handleSetSecret"
        :on-rotate-secret="handleRotateSecret"
        @refresh="refreshSecrets"
        @manage="selectView('secrets')"
      />

      <template v-else-if="currentView === 'versions'">
        <div
          v-if="selectedSecret && secretAccess.enabled"
          class="shell__toolbar"
          aria-label="Secret actions"
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

      <section
        v-else-if="selectedIsShared && (currentView === 'policies' || currentView === 'scan')"
        class="shell__panel"
        aria-labelledby="project-required-heading"
      >
        <h2 id="project-required-heading">
          {{ currentView === 'policies' ? 'Commands' : 'Scan in terminal' }}
        </h2>
        <p>
          {{ currentView === 'policies' ? 'Approved commands belong to' : 'Terminal scans run in' }}
          connected project folders with a <code>locket.toml</code> file.
        </p>
        <button
          ref="connectProjectTrigger"
          type="button"
          class="companion-button"
          :disabled="!desktopAvailable || desktopBusy"
          @click="pickProjectFolder"
        >
          Connect a project folder
        </button>
      </section>

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
        :detected-commands="detectedCommands"
        :detecting-commands="detectingCommands"
        :detection-error="detectionError"
        @run="runCommand"
        @refresh="refreshCommandView"
        @create="openPolicyCreate"
        @add-detected="openPolicyCreate"
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
        :can-create="canCreateProfile"
        :creating="profileCreateBusy"
        :create-notice="profileCreateNotice"
        :create-error="profileCreateError"
        @switch="handleProfileSwitch"
        @create="handleProfileCreate"
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
          :context-key="settingsContextKey"
          :profile-name="activeContext?.profile_name"
          :dangerous-profile="settings.dangerousProfileFlag"
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
      <form @submit.prevent="submitDangerousConfirmation">
        <h2 id="dangerous-action-title">{{ dangerousAction }}</h2>
        <label for="dangerous-action-profile">
          Type the exact profile name <strong>{{ dangerousProfileName }}</strong> to allow this
          action.
        </label>
        <input
          id="dangerous-action-profile"
          v-model="dangerousProfileInput"
          type="text"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          autofocus
        />
        <button type="button" @click="dangerousConfirmDialog?.close()">Cancel</button>
        <button type="submit" :disabled="!dangerousProfileMatches">Allow action</button>
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
      :prefer-passphrase="unlockWithPassphrase"
      @submit="handleUnlock"
      @dismiss="unlockOpen = false"
    />
    <PolicyEditorForm
      v-if="policyFormMode !== null && policyAccess.enabled"
      :mode="policyFormMode"
      :row="policyFormRow"
      :initial-draft="policyFormDraft"
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
  height: 100vh;
  height: 100dvh;
  overflow: hidden;
  background: var(--bg-app);
}

.shell__nav {
  min-width: 0;
  min-height: 0;
  background: color-mix(in srgb, var(--bg-surface), var(--bg-app) 40%);
  border-right: 1px solid var(--border-subtle);
  padding: 1rem 0.75rem 1.1rem;
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
}

.shell__primary {
  min-height: 0;
  overflow-y: auto;
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

.shell__switcher {
  position: relative;
  min-width: 0;
}

.shell__context {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  justify-content: space-between;
  width: 100%;
  min-width: 0;
  text-align: start;
  padding-inline: 0.45rem;
}

.shell__switcher-menu {
  position: absolute;
  z-index: 20;
  inset-block-start: calc(100% + 0.35rem);
  inset-inline-start: 0;
  width: max-content;
  min-width: 15.5rem;
  max-width: min(20rem, calc(100vw - 1.5rem));
  max-height: min(26rem, 60dvh);
  box-sizing: border-box;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: 0.35rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--bg-elevated);
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.shell__switcher-group {
  display: flex;
  flex: none;
  flex-direction: column;
  gap: 0.15rem;
}

.shell__switcher-actions {
  padding-top: 0.35rem;
  border-top: 1px solid var(--border-subtle);
}

.shell__switcher-heading {
  padding: 0.2rem 0.5rem 0.1rem;
  font-size: 0.6875rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.shell__switcher-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.42rem 0.5rem;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-primary);
  font: inherit;
  font-size: 0.8125rem;
  text-align: start;
  cursor: pointer;
}

.shell__switcher-item:hover:not(:disabled) {
  background: var(--bg-subtle);
}

.shell__switcher-item:focus-visible {
  outline-offset: -2px;
}

.shell__switcher-item[aria-current='true'] {
  background: var(--accent-soft);
  border-color: color-mix(in srgb, var(--accent), transparent 55%);
  color: var(--accent);
}

.shell__switcher-item:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.shell__switcher-text {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
}

.shell__switcher-text strong {
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell__switcher-text small {
  color: var(--text-muted);
  font-size: 0.72rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell__unlock-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
  padding: 0.7rem 0.9rem;
  border: 1px solid color-mix(in srgb, var(--accent), var(--border-subtle) 55%);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--accent), var(--bg-surface) 93%);
}

.shell__unlock-copy {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}

.shell__unlock-copy strong {
  color: var(--text-primary);
  margin-right: 0.3rem;
}

.shell__unlock-copy .app-icon {
  color: var(--accent);
}

.shell__unlock-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
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
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.75rem 0.25rem 0.15rem;
  border-top: 1px solid var(--border-subtle);
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

.shell__primary-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
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
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  margin-bottom: 0.85rem;
  padding: 1rem clamp(0.85rem, 2vw, 1.75rem) 2.5rem;
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
    height: auto;
    min-height: 100vh;
    overflow: visible;
  }

  .shell__nav {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 0.2rem 0.35rem;
    padding: 0.35rem 0.7rem 0.25rem;
    border-right: 0;
    border-bottom: 1px solid var(--border-subtle);
  }

  .shell__primary {
    grid-column: 1 / -1;
    grid-row: 2;
    overflow-y: visible;
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
    max-width: 100%;
  }

  .shell__switcher {
    margin-inline-end: auto;
  }

  .shell__connection,
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
    grid-column: 2;
    grid-row: 1;
    margin-top: 0;
    border-top: 0;
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
    overflow-y: visible;
    margin-bottom: 0;
    padding: 0.5rem 0.75rem 2rem;
  }
}

@media (max-width: 639px) {
  .shell__unlock-actions .companion-button {
    padding-inline: 0.5rem;
  }

  .shell__masthead {
    position: relative;
  }

  .shell__switcher {
    position: static;
  }

  .shell__switcher-menu {
    inset-inline: 0;
    width: auto;
    min-width: 0;
    max-width: none;
  }

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
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }

  .shell__primary-list > li > .shell__nav-item {
    flex-direction: column;
    justify-content: center;
    gap: 0.15rem;
    min-height: 2.75rem;
    padding: 0.25rem 0.1rem;
    font-size: 0.75rem;
    line-height: 1.15;
  }

  .shell__primary-list > li > .shell__nav-item .app-icon {
    width: 0.8125rem;
  }

  .shell__segments button {
    min-height: 1.65rem;
    padding-block: 0.2rem;
  }
}
</style>
