import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke, type InvokeArgs } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import App from './App.vue';
import type {
  AgentStatus,
  DesktopProjectContext,
  RevealResponse,
  SecretWireRow,
} from './agent/types';
import type { SecretRowMeta } from './types/views';
import type RevealModal from './components/RevealModal.vue';
import { createMockRuntime } from './preview/mockRuntime';
import {
  button as renderedButton,
  byProp,
  check,
  click as clickRendered,
  control,
  deferred,
  findNode,
  input,
  mountComponent,
  nodeText,
  select,
  settle,
  submit,
} from './test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

interface AppState {
  selectedProject: DesktopProjectContext | null;
  activeContext: DesktopProjectContext | null;
  selectedSecret: SecretRowMeta | null;
  projectPath: string;
  envPath: string;
  desktopBusy: boolean;
  desktopError: string | null;
  revealError: string | null;
  revealModal: InstanceType<typeof RevealModal> | null;
  scanLaunching: boolean;
  scanError: string | null;
  scanNotice: string | null;
  status: AgentStatus | null;
  refresh: () => Promise<void>;
  connectProject: (initialize: boolean, path: string) => Promise<void>;
  handleEditorReveal: (row: SecretRowMeta) => Promise<void>;
  handleTrayMenuAction: (
    action:
      | 'open-app'
      | 'lock-vault'
      | 'unlock-vault'
      | 'switch-profile'
      | 'run-policy'
      | 'reveal-secret'
      | 'copy-secret'
      | 'start-scan',
  ) => Promise<void>;
  handleProfileSwitch: (payload: {
    profileName: string;
    confirmation: undefined;
    dangerous: boolean;
  }) => Promise<void>;
  selectView: (
    view:
      | 'dashboard'
      | 'secrets'
      | 'settings'
      | 'scan'
      | 'policies'
      | 'profiles'
      | 'secret-editor'
      | 'versions'
      | 'execution'
      | 'devices'
      | 'audit'
      | 'team'
      | 'recovery'
      | 'discover',
  ) => void;
}

const project = (name: string): DesktopProjectContext => ({
  root: `/fixture/${name}`,
  project_id: name,
  project_name: name,
  profile_id: `${name}-development-id`,
  profile_name: 'development',
});
const a = project('A');
const b = project('B');
const shared: DesktopProjectContext = {
  root: '',
  project_id: 'lk_proj_shared_test',
  project_name: '@shared',
  profile_id: 'lk_prof_shared_default',
  profile_name: 'default',
  is_shared: true,
};
const secret = (name = 'TOKEN'): SecretRowMeta => ({
  id: name,
  name,
  source: 'team',
  required: true,
  optional: false,
  createdAt: '2026-10-23T00:00:00Z',
  currentVersion: 1,
  hasDeprecatedGrace: false,
});
const revealed = (value = 'fixture-plaintext'): RevealResponse => ({ value, ttl_seconds: 30 });

let nativeSelection: DesktopProjectContext | null;
let lockState: AgentStatus['lock_state'];
let sessionMonitoring: string | undefined;
let windowEvents: EventTarget;
let calls: string[];
let overrides: Map<string, (args: InvokeArgs | undefined) => unknown>;
let mounts: ReturnType<typeof mountComponent<AppState>>[];

async function nativeInvoke(command: string, args?: InvokeArgs): Promise<unknown> {
  calls.push(command);
  const override = overrides.get(command);
  if (override) return override(args);
  switch (command) {
    case 'desktop_list_projects':
      return [];
    case 'desktop_open_shared_vault':
      nativeSelection = shared;
      return nativeSelection;
    case 'desktop_open_project':
    case 'desktop_initialize_project': {
      const path = (args as { request: { path: string } }).request.path;
      nativeSelection = path === b.root ? b : a;
      return nativeSelection;
    }
    case 'agent_status':
      return {
        lock_state: lockState,
        project_id: nativeSelection?.project_id ?? null,
        profile_name: nativeSelection?.profile_name ?? null,
        live_grant_count: 0,
        agent_version: 'test',
        unlock_ttl_seconds: 900,
        running_session_count: 0,
        scan_warning_count: 0,
        recent_audit_status: 'unknown',
        pinned_reference_warning_count: 0,
        session_monitoring: sessionMonitoring,
      } satisfies AgentStatus;
    case 'agent_read_config':
      return {
        privacy_redact_names: false,
        agent_unlock_ttl: '15m',
        user_verification_required_for: {},
        dangerous_profile: null,
      };
    case 'agent_list_secrets':
    case 'agent_list_versions':
    case 'agent_list_runtime_sessions':
    case 'agent_list_policies':
    case 'agent_list_device_members':
      return { rows: [] };
    case 'desktop_list_duplicates':
      return { groups: [] };
    case 'desktop_list_shared_usages':
      return { usages: [] };
    case 'agent_list_audit':
      return {
        rows: [],
        chain_status: { locked: false, hmac_ok: null, first_break_sequence: null },
      };
    case 'agent_verify_audit':
      return {
        locked: false,
        hmac_ok: true,
        first_break_sequence: null,
        first_break_reason: null,
        rows_verified: 0,
      };
    case 'agent_reveal':
      return revealed();
    case 'desktop_scan_project':
      return { launched: true, command: 'locket scan --require-known' };
    case 'agent_scan':
      return { findings: [], locked: true };
    case 'desktop_detect_commands':
      return [];
    case 'agent_lock':
      lockState = 'locked';
      return;
    case 'agent_subscribe_status':
    case 'tray_set_state':
    case 'tray_set_selection':
    case 'tray_set_privacy_context':
      return;
    default:
      throw new Error(`Unexpected test IPC: ${command}`);
  }
}

beforeEach(() => {
  vi.resetAllMocks();
  nativeSelection = null;
  lockState = 'unlocked';
  sessionMonitoring = 'active: macOS native notifications';
  calls = [];
  overrides = new Map();
  mounts = [];
  windowEvents = new EventTarget();
  vi.stubGlobal('window', windowEvents);
  vi.stubGlobal('Document', class {});
  vi.stubGlobal('ShadowRoot', class {});
  vi.mocked(invoke).mockImplementation(nativeInvoke as typeof invoke);
  vi.mocked(listen).mockResolvedValue(() => {});
});

afterEach(() => {
  for (const mount of mounts) mount.unmount();
  vi.unstubAllGlobals();
});

function mountApp() {
  const app = mountComponent<AppState>(App);
  mounts.push(app);
  return app;
}

async function connectedApp() {
  const app = mountApp();
  await settle();
  await app.state.connectProject(false, a.root);
  await settle();
  expect(app.state.activeContext).toEqual(a);
  return app;
}

function plaintext(app: ReturnType<typeof mountApp>): string | undefined {
  return findNode(app.root, (node) => node.props['data-testid'] === 'reveal-value')?.text;
}

describe('desktop environment, secret, and command actions', () => {
  type MountedApp = Awaited<ReturnType<typeof connectedApp>>;
  const byId = (app: MountedApp, id: string) =>
    findNode(app.root, (node) => node.props['data-testid'] === id);
  const button = (app: MountedApp, label: string) =>
    findNode(
      app.root,
      (node) =>
        node.tag === 'button' && !!findNode(node, (content) => content.text.trim() === label),
    );
  const click = (app: MountedApp, label: string) => {
    const action = button(app, label);
    expect(action).toBeDefined();
    expect(action?.props.disabled).toBeFalsy();
    (action?.props.onClick as () => void)();
  };
  const row: SecretWireRow = {
    id: 'token',
    profile_id: a.profile_id,
    name: 'TOKEN',
    source: 'team-managed',
    source_precedence: 1,
    origin: 'local',
    current_version: 1,
    state: 'active',
    required: true,
    created_at: 0,
    updated_at: 0,
    last_rotated_at: null,
  };
  const detected = {
    name: 'test:unit',
    argv: ['pnpm', 'run', 'test:unit'],
    command_preview: 'pnpm run test:unit',
    source_file: 'package.json',
    already_configured: false,
  };

  async function inspectSecret(app: MountedApp) {
    Object.assign(windowEvents, { matchMedia: () => ({ matches: false }) });
    app.state.selectView('secrets');
    await settle();
    expect(button(app, 'Copy to Global Vault')).toBeUndefined();
    const details = findNode(app.root, (node) => node.props['aria-label'] === 'Details for TOKEN');
    await (details?.props.onClick as (event: MouseEvent) => Promise<void>)(
      new Event('click') as MouseEvent,
    );
    await settle();
  }

  it('creates an environment and refreshes the switcher without switching into it', async () => {
    let created = false;
    overrides.set('agent_list_projects', () => [
      {
        project_id: a.project_id,
        profiles: created ? [{ id: 'A-qa', name: 'qa', dangerous: false }] : [],
      },
    ]);
    overrides.set('desktop_create_profile', () => {
      created = true;
      return { profile_id: 'A-qa', profile_name: 'qa', dangerous: false, created };
    });
    const app = await connectedApp();
    app.state.selectView('profiles');
    await settle();
    const name = byId(app, 'profile-create-name');
    expect(name).toBeDefined();
    name!.value = 'invalid name';
    name!.dispatchEvent(new Event('input'));
    await settle();
    expect(button(app, 'Create environment')?.props.disabled).toBe(true);
    name!.value = ' qa ';
    name!.dispatchEvent(new Event('input'));
    await settle();
    await (byId(app, 'profile-create-form')?.props.onSubmit as (event: Event) => Promise<void>)(
      new Event('submit'),
    );
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_create_profile', {
      request: { project_id: a.project_id, profile_name: 'qa' },
    });
    expect(byId(app, 'profile-entry-qa')).toBeDefined();
    expect(
      findNode(app.root, (node) => node.text.trim() === 'Created environment qa.'),
    ).toBeDefined();
    expect(app.state.activeContext).toEqual(a);
  });

  it('keeps a failed environment draft available for correction', async () => {
    const app = await connectedApp();
    app.state.selectView('profiles');
    await settle();
    const field = byId(app, 'profile-create-name')!;
    const form = byId(app, 'profile-create-form')!;
    overrides.set('desktop_create_profile', () =>
      Promise.reject({ kind: 'rejected', code: 'SecretAlreadyExists' }),
    );
    await input(field, 'existing');
    await submit(form);
    expect(nodeText(app.root)).toContain('An environment with this name already exists.');
    expect(field.value).toBe('existing');
    expect(button(app, 'Create environment')?.props.disabled).toBe(false);
  });

  it('allows retrying a rejected Global Vault link and refreshes its metadata', async () => {
    const linked = { ...row, id: 'api-link', name: 'API_TOKEN', source: 'shared-link' };
    let created = false;
    overrides.set('agent_list_secrets', () => ({ rows: created ? [linked] : [] }));
    const app = await connectedApp();
    app.state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(app.root, 'Link from Global Vault'));
    await input(control(app.root, 'Local variable name'), 'API_TOKEN');
    await input(control(app.root, 'Global Vault secret name'), 'SHARED_TOKEN');
    overrides.set('desktop_link_secret', () => Promise.reject('Global Vault secret was not found'));
    await submit(app.root);
    expect(nodeText(app.root)).toContain('Global Vault secret was not found.');
    expect(control(app.root, 'Local variable name').value).toBe('API_TOKEN');
    overrides.set('desktop_link_secret', () => {
      created = true;
      return { link_id: linked.id };
    });
    await submit(app.root);
    expect(invoke).toHaveBeenCalledWith('desktop_link_secret', {
      request: {
        project_id: a.project_id,
        profile_id: a.profile_id,
        local_name: 'API_TOKEN',
        target_secret_name: 'SHARED_TOKEN',
      },
    });
    expect(nodeText(app.root)).toContain('Linked API_TOKEN to @shared/SHARED_TOKEN.');
  });

  it('requires inline confirmation and the exact dangerous environment name before deleting', async () => {
    let deleted = false;
    overrides.set('agent_list_secrets', () => ({ rows: deleted ? [] : [row] }));
    overrides.set('agent_read_config', () => ({
      privacy_redact_names: false,
      agent_unlock_ttl: '15m',
      user_verification_required_for: {},
      dangerous_profile: { dangerous: true },
    }));
    overrides.set('desktop_delete_secret', () => {
      deleted = true;
      return { secret_name: row.name, source: row.source, version: 1, deleted };
    });
    const app = await connectedApp();
    await inspectSecret(app);
    click(app, 'Delete');
    await settle();
    expect(button(app, 'Confirm delete')?.props.disabled).toBe(true);
    click(app, 'Cancel');
    await settle();
    expect(calls).not.toContain('desktop_delete_secret');
    click(app, 'Delete');
    await settle();
    const name = byId(app, 'secret-delete-confirmation')!;
    name.value = a.profile_name;
    name.dispatchEvent(new Event('input'));
    await settle();
    click(app, 'Confirm delete');
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_delete_secret', {
      request: {
        project_id: a.project_id,
        profile_id: a.profile_id,
        secret_name: row.name,
        source: 'team-managed',
        confirmation: a.profile_name,
      },
    });
    expect(
      findNode(app.root, (node) => node.props['aria-label'] === 'Details for TOKEN'),
    ).toBeUndefined();
    expect(findNode(app.root, (node) => node.text.trim() === 'Deleted TOKEN.')).toBeDefined();
  });

  it('copies the selected source to the Global Vault with no overwrite', async () => {
    overrides.set('agent_list_secrets', () => ({ rows: [row] }));
    overrides.set('desktop_copy_secret_to_shared', () => ({
      target_project_id: shared.project_id,
      target_profile_id: shared.profile_id,
      secret_name: row.name,
      version: 1,
      action: 'create',
    }));
    const app = await connectedApp();
    await inspectSecret(app);
    click(app, 'Copy to Global Vault');
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_copy_secret_to_shared', {
      request: {
        from_project_id: a.project_id,
        from_profile_id: a.profile_id,
        secret_name: row.name,
        source: 'team-managed',
      },
    });
    expect(
      findNode(app.root, (node) => node.text.trim() === 'Copied TOKEN to Global Vault.'),
    ).toBeDefined();
  });

  it('unlinks a project alias only after dangerous-profile approval', async () => {
    let unlinked = false;
    overrides.set('agent_list_secrets', () => ({
      rows: unlinked
        ? []
        : [
            {
              ...row,
              source: 'shared-link',
              linked_target_secret_id: 'global',
              linked_target_name: 'GLOBAL_TOKEN',
            },
          ],
    }));
    overrides.set('agent_read_config', () => ({
      privacy_redact_names: false,
      agent_unlock_ttl: '15m',
      user_verification_required_for: {},
      dangerous_profile: { dangerous: true },
    }));
    overrides.set('desktop_unlink_secret', () => {
      unlinked = true;
      return { local_name: 'TOKEN', unlinked };
    });
    const app = await connectedApp();
    const dialog = byProp(app.root, 'aria-labelledby', 'dangerous-action-title');
    Object.assign(dialog, {
      open: false,
      returnValue: '',
      showModal() {
        this.open = true;
      },
      close(result = '') {
        this.open = false;
        this.returnValue = result;
        dialog.dispatchEvent(new Event('close'));
      },
    });
    await inspectSecret(app);
    expect(nodeText(app.root)).toContain('Linked → @shared/GLOBAL_TOKEN');
    expect(button(app, 'Rotate')).toBeUndefined();
    await clickRendered(renderedButton(app.root, 'Unlink'));
    await clickRendered(renderedButton(dialog, 'Cancel'));
    expect(calls).not.toContain('desktop_unlink_secret');
    await clickRendered(renderedButton(app.root, 'Unlink'));
    await input(byProp(dialog, 'id', 'dangerous-action-profile'), a.profile_name);
    await submit(dialog);
    expect(invoke).toHaveBeenCalledWith('desktop_unlink_secret', {
      request: {
        project_id: a.project_id,
        profile_id: a.profile_id,
        local_name: 'TOKEN',
        confirmation: a.profile_name,
      },
    });
    expect(nodeText(app.root)).toContain('Removed the Global Vault link for TOKEN.');
    expect(nodeText(app.root)).not.toContain('Linked → @shared/GLOBAL_TOKEN');
  });

  it('promotes an alias and consolidates matching duplicates from the Secrets panel', async () => {
    let promoted = false;
    const local = { ...row, source: 'user-local' as const };
    overrides.set('agent_list_secrets', () => ({
      rows: [
        promoted ? { ...row, source: 'shared-link', linked_target_name: 'GLOBAL_TOKEN' } : local,
      ],
    }));
    const member = {
      secret_id: row.id,
      name: row.name,
      source: local.source,
      project_id: a.project_id,
      project_name: a.project_name,
      is_shared: false,
      profile_id: a.profile_id,
      profile_name: a.profile_name,
      profile_dangerous: false,
      current_version: 1,
      updated_at: 0,
    };
    overrides.set('desktop_list_duplicates', () => ({
      groups: promoted
        ? []
        : [
            {
              group_id: 'dup-1',
              members: [
                member,
                {
                  ...member,
                  secret_id: 'global',
                  name: 'GLOBAL_TOKEN',
                  project_id: shared.project_id,
                  project_name: shared.project_name,
                  is_shared: true,
                  profile_id: shared.profile_id,
                  profile_name: shared.profile_name,
                },
                {
                  ...member,
                  secret_id: 'other',
                  name: 'ALT_TOKEN',
                  project_id: b.project_id,
                  project_name: b.project_name,
                  profile_id: b.profile_id,
                },
              ],
            },
          ],
    }));
    overrides.set('desktop_copy_secret_to_shared', () => {
      promoted = true;
      return {
        target_project_id: shared.project_id,
        target_profile_id: shared.profile_id,
        secret_name: 'GLOBAL_TOKEN',
        version: 1,
        action: 'reuse',
        linked: true,
        consolidated_count: 1,
        skipped_locked_count: 1,
      };
    });
    vi.stubGlobal('document', { getElementById: () => null });
    const { root, state } = await connectedApp();
    state.selectView('secrets');
    await settle();
    expect(nodeText(root)).toContain('Duplicate values across projects');
    expect(nodeText(root)).toContain('Global Vault match');
    expect(nodeText(root)).toContain('B / development / ALT_TOKEN');
    await clickRendered(renderedButton(root, 'Review promotion'));
    const inspector = byProp(root, 'id', 'variable-inspector');
    expect(control(inspector, 'Global Vault target name').value).toBe('GLOBAL_TOKEN');
    await input(control(inspector, 'Global Vault target name'), 'invalid-alias');
    expect(renderedButton(inspector, 'Promote & link').props.disabled).toBe(true);
    await input(control(inspector, 'Global Vault target name'), 'GLOBAL_TOKEN');
    await check(control(inspector, 'Also link matching duplicates'));
    await submit(inspector);
    expect(invoke).toHaveBeenCalledWith('desktop_copy_secret_to_shared', {
      request: {
        from_project_id: a.project_id,
        from_profile_id: a.profile_id,
        secret_name: 'TOKEN',
        source: 'user-local',
        target_name: 'GLOBAL_TOKEN',
        replace_with_link: true,
        consolidate_duplicates: true,
      },
    });
    expect(nodeText(root)).toContain(
      'Linked 1 additional copy. Skipped 1 locked or dangerous copy.',
    );
    expect(nodeText(root)).not.toContain('Duplicate values across projects');
    expect(nodeText(root)).toContain('Linked → @shared/GLOBAL_TOKEN');
  });

  it.each([
    [
      'UnlockRequired',
      'unlock the Global Vault before copying the secret',
      'Open and unlock Global Vault (@shared), then return here and try again.',
    ],
    [
      'SecretAlreadyExists',
      'a user-local secret with this name already exists in the Global Vault',
      'TOKEN already exists in Global Vault. Open Global Vault to review the existing secret.',
    ],
  ])('shows actionable copy feedback for %s', async (code, message, notice) => {
    overrides.set('agent_list_secrets', () => ({ rows: [row] }));
    overrides.set('desktop_copy_secret_to_shared', () =>
      Promise.reject({ kind: 'rejected', code, message }),
    );
    const app = await connectedApp();
    await inspectSecret(app);
    click(app, 'Copy to Global Vault');
    await settle();
    expect(
      findNode(app.root, (node) => node.props.role === 'alert' && node.text === notice),
    ).toBeDefined();
    expect(calls.filter((call) => call === 'desktop_copy_secret_to_shared')).toHaveLength(1);
  });

  it('opens a prefilled argv draft for an unconfigured detected command', async () => {
    let saved = false;
    overrides.set('desktop_detect_commands', () => [
      { ...detected, already_configured: saved },
      { ...detected, name: 'dev', already_configured: true },
    ]);
    overrides.set('desktop_save_policy', () => {
      saved = true;
    });
    const app = await connectedApp();
    app.state.selectView('policies');
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_detect_commands', {
      request: { project_id: a.project_id },
    });
    expect(findNode(app.root, (node) => node.text === 'package.json')).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'dev')).toBeUndefined();
    click(app, 'Add command');
    await settle();
    expect(byId(app, 'policy-form-name')?.value).toBe('test:unit');
    const kind = byId(app, 'policy-form-kind')!;
    expect(kind.options[kind.selectedIndex]?.value).toBe('argv');
    expect(byId(app, 'policy-form-command')?.value).toBe('pnpm run test:unit');
    expect(calls).not.toContain('desktop_save_policy');
    expect(button(app, 'Create')?.props.disabled).toBe(false);
    await (byId(app, 'policy-form')?.props.onSubmit as (event: Event) => Promise<void>)(
      new Event('submit'),
    );
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_save_policy', {
      request: expect.objectContaining({
        project_id: a.project_id,
        mode: 'create',
        original_name: 'test:unit',
        policy: expect.objectContaining({
          command_kind: 'argv',
          command_preview: 'pnpm run test:unit',
        }),
      }),
    });
    expect(button(app, 'Add command')).toBeUndefined();
  });

  it.each([
    ['fixture IPC failure', 'Reveal request failed.'],
    [{ kind: 'unavailable' }, 'Agent unavailable.'],
    [{ kind: 'rejected', code: 'SecretNotFound' }, 'SecretNotFound'],
    [
      {
        kind: 'rejected',
        code: 'ConfirmationFailed',
        message: 'Type the exact active profile name.',
      },
      'Type the exact active profile name.',
    ],
  ])('reports reveal and copy failures without presenting a value', async (error, message) => {
    overrides.set('agent_list_secrets', () => ({ rows: [row] }));
    overrides.set('agent_reveal', () => Promise.reject(error));
    overrides.set('agent_copy_secret', () => Promise.reject(error));
    const { root, state } = await connectedApp();
    state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(root, 'Reveal'));
    expect(nodeText(root)).toContain(message);
    expect(findNode(root, (node) => node.props['data-testid'] === 'reveal-value')).toBeUndefined();
    await clickRendered(renderedButton(root, 'Copy value'));
    expect(nodeText(root)).toContain(message);
    expect(nodeText(root)).not.toContain('Copied value temporarily.');
  });

  it('uses a redacted row identifier for value access and keeps the alias on reveal', async () => {
    const settings = deferred<{ privacy_redact_names: boolean }>();
    overrides.set('agent_read_config', () => settings.promise);
    overrides.set('agent_list_secrets', (args) => ({
      rows: [
        (args as { request: { redact_names: boolean } }).request.redact_names
          ? { ...row, name: 'secret-1234abcd' }
          : row,
      ],
    }));
    overrides.set('agent_copy_secret', () => ({ kind: 'copied', ttl_seconds: 10 }));
    const { root, state } = await connectedApp();
    state.selectView('secrets');
    await settle();
    expect(nodeText(root)).not.toContain('TOKEN');
    settings.resolve({ privacy_redact_names: true });
    await settle();
    await clickRendered(renderedButton(root, 'Reveal'));
    await clickRendered(renderedButton(root, 'Copy value'));
    for (const command of ['agent_reveal', 'agent_copy_secret']) {
      expect(invoke).toHaveBeenCalledWith(command, {
        request: expect.objectContaining({ secret_name: 'secret-1234abcd', secret_id: row.id }),
      });
    }
    expect(nodeText(root)).not.toContain('TOKEN');
  });

  it.each([
    ['fixture transport failure', 'Profile switch failed.'],
    [{ kind: 'unavailable' }, 'Agent unavailable.'],
    [{ kind: 'rejected', code: 'ProfileNotFound' }, 'ProfileNotFound'],
  ])(
    'reports environment switch failure and keeps the previous environment',
    async (error, message) => {
      const { root, state } = await connectedApp();
      state.selectView('profiles');
      overrides.set('agent_set_active_profile', () => Promise.reject(error));
      await state.handleProfileSwitch({
        profileName: 'qa',
        confirmation: undefined,
        dangerous: false,
      });
      await settle();
      expect(nodeText(root)).toContain(message);
      expect(state.activeContext?.profile_name).toBe(a.profile_name);
    },
  );

  it('drops command suggestions that arrive after changing projects', async () => {
    const first = deferred<(typeof detected)[]>();
    overrides.set('desktop_detect_commands', (args) =>
      (args as { request: { project_id: string } }).request.project_id === a.project_id
        ? first.promise
        : [{ ...detected, name: 'build', command_preview: 'pnpm run build' }],
    );
    const app = await connectedApp();
    app.state.selectView('policies');
    await settle();
    expect(calls).toContain('desktop_detect_commands');
    await app.state.connectProject(false, b.root);
    await settle();
    first.resolve([detected]);
    await settle();
    expect(
      findNode(app.root, (node) => node.props['aria-label'] === 'Add command build'),
    ).toBeDefined();
    expect(
      findNode(app.root, (node) => node.props['aria-label'] === 'Add command test:unit'),
    ).toBeUndefined();
  });
});

describe('vault unlock in the mounted app', () => {
  type MountedApp = ReturnType<typeof mountApp>;

  const button = (app: MountedApp, label: string) =>
    findNode(
      app.root,
      (node) =>
        node.tag === 'button' && !!findNode(node, (content) => content.text.trim() === label),
    );
  const click = (app: MountedApp, label: string) => {
    const action = button(app, label);
    expect(action).toBeDefined();
    expect(action?.props.disabled).toBeFalsy();
    (action?.props.onClick as () => void)();
  };
  const unlockBar = (app: MountedApp) =>
    findNode(app.root, (node) => node.props['aria-label'] === 'Vault actions');
  const unlockDialog = (app: MountedApp) =>
    findNode(app.root, (node) => node.props['aria-labelledby'] === 'unlock-title');
  const keychainDenied = () => {
    throw {
      kind: 'rejected',
      code: 'KeychainDenied',
      display_reason: 'Keychain access was denied.',
    };
  };
  const allowKeychainUnlock = () => {
    lockState = 'unlocked';
  };
  const expectKeychainRequest = (target: DesktopProjectContext) =>
    expect(invoke).toHaveBeenCalledWith('agent_unlock', {
      request: {
        project_id: target.project_id,
        ttl_seconds: 900,
        source: { kind: 'os-keychain' },
        audit: { profile_id: target.profile_id },
      },
    });

  describe.each([
    { label: 'Create Global Vault (@shared)', target: shared },
    { label: 'Open Global Vault (@shared)', target: shared },
    { label: 'Initialize & open', target: a },
  ])('$label', ({ label, target }) => {
    it.each(['success', 'failure'] as const)(
      'tries the keychain after status refresh and handles %s',
      async (outcome) => {
        lockState = 'locked';
        if (label.startsWith('Open')) overrides.set('desktop_list_projects', () => [a, shared]);
        overrides.set('agent_unlock', outcome === 'success' ? allowKeychainUnlock : keychainDenied);
        const app = mountApp();
        await settle();
        if (target === a) {
          overrides.set('desktop_inspect_project_folder', () => ({
            path: a.root,
            has_config: false,
            folder_name: 'A',
          }));
          app.state.projectPath = a.root;
          await settle();
          const form = findNode(app.root, (node) => node.tag === 'form' && !!node.props.onSubmit);
          (form!.props.onSubmit as (event: Event) => void)(new Event('submit'));
          await settle();
        }
        expect(calls).not.toContain('agent_unlock');
        click(app, label);
        await settle();

        expect(app.state.activeContext).toEqual(target);
        expectKeychainRequest(target);
        expect(calls.indexOf('agent_status')).toBeLessThan(calls.indexOf('agent_unlock'));
        expect(unlockDialog(app)).toBeUndefined();
        expect(app.state.desktopError).toBeNull();
        expect(findNode(app.root, (node) => node.props.role === 'alert')).toBeUndefined();
        if (outcome === 'success') {
          await vi.waitFor(() =>
            expect(invoke).toHaveBeenCalledWith('agent_verify_audit', {
              request: { project_id: target.project_id },
            }),
          );
          expect(app.state.status?.lock_state).toBe('unlocked');
          expect(findNode(app.root, (node) => node.text === 'No secrets yet')).toBeDefined();
          expect(unlockBar(app)).toBeUndefined();
        } else {
          expect(app.state.status?.lock_state).toBe('locked');
          expect(unlockBar(app)).toBeDefined();
          expect(calls).not.toContain('agent_verify_audit');
        }
      },
    );
  });

  it.each([a, shared])(
    'opens known $project_name at startup without trying the keychain',
    async (target) => {
      lockState = 'locked';
      overrides.set('desktop_list_projects', () => [target]);
      const app = mountApp();
      await settle();
      expect(app.state.activeContext).toEqual(target);
      expect(unlockBar(app)).toBeDefined();
      expect(calls).not.toContain('agent_unlock');
    },
  );

  it('discards a successful auto-unlock completion after the user switches vaults', async () => {
    lockState = 'locked';
    const pending = deferred<void>();
    overrides.set('agent_unlock', () => pending.promise);
    const app = mountApp();
    await settle();
    click(app, 'Create Global Vault (@shared)');
    await settle();
    expectKeychainRequest(shared);
    await app.state.connectProject(false, b.root);
    await settle();
    expect(app.state.activeContext).toEqual(b);
    const statusCalls = calls.filter((call) => call === 'agent_status').length;
    pending.resolve();
    await settle();
    expect(calls.filter((call) => call === 'agent_status')).toHaveLength(statusCalls);
    expect(calls).not.toContain('agent_verify_audit');
    expect(unlockDialog(app)).toBeUndefined();
    expect(button(app, 'Unlock with keychain')?.props.disabled).toBe(false);
  });

  it('unlocks with one keychain click without opening the modal', async () => {
    lockState = 'locked';
    const pending = deferred<void>();
    overrides.set('agent_unlock', () => pending.promise);
    const app = await connectedApp();
    click(app, 'Unlock with keychain');
    await settle();
    expectKeychainRequest(a);
    expect(unlockDialog(app)).toBeUndefined();
    expect(button(app, 'Unlock with keychain')?.props.disabled).toBe(true);
    expect(button(app, 'Use passphrase')?.props.disabled).toBe(true);
    allowKeychainUnlock();
    pending.resolve();
    await settle();
    expect(app.state.status?.lock_state).toBe('unlocked');
    expect(unlockBar(app)).toBeUndefined();
    expect(unlockDialog(app)).toBeUndefined();
  });

  it('opens the unlock modal with the keychain error if one-click unlock fails', async () => {
    lockState = 'locked';
    overrides.set('agent_unlock', keychainDenied);
    const app = await connectedApp();
    click(app, 'Unlock with keychain');
    await settle();
    expectKeychainRequest(a);
    const dialog = unlockDialog(app);
    expect(dialog).toBeDefined();
    expect(findNode(dialog!, (node) => node.props.role === 'alert')?.text).toContain(
      'Keychain access was denied.',
    );
    expect(app.state.desktopError).toBeNull();
  });

  it('opens the modal in passphrase mode without calling the keychain', async () => {
    lockState = 'locked';
    const app = await connectedApp();
    click(app, 'Use passphrase');
    await settle();
    const dialog = unlockDialog(app);
    expect(dialog).toBeDefined();
    expect(findNode(dialog!, (node) => node.props.type === 'password')).toBeDefined();
    expect(findNode(dialog!, (node) => node.props.role === 'alert')).toBeUndefined();
    expect(calls).not.toContain('agent_unlock');
  });
});

describe('automatic locking availability', () => {
  it.each([undefined, 'unavailable: native observer unavailable'])(
    'shows manual-lock guidance when monitoring is %s',
    async (monitoring) => {
      sessionMonitoring = monitoring;
      const app = await connectedApp();
      const warning = () =>
        findNode(app.root, (node) => node.props['data-testid'] === 'session-lock-warning');
      expect(
        warning()?.children.some((node) =>
          node.text.includes('Lock the vault before leaving this device'),
        ),
      ).toBe(true);
      await app.state.connectProject(false, b.root);
      await settle();
      expect(warning()).toBeDefined();
      sessionMonitoring = 'active: macOS native notifications';
      await app.state.refresh();
      await settle();
      expect(warning()).toBeUndefined();
    },
  );
});

it('shows a retriable secrets error and marks the agent offline until recovery', async () => {
  const app = await connectedApp();
  overrides.set('agent_list_secrets', () => {
    throw {
      kind: 'rejected',
      code: 'AgentUnavailable',
      message: 'Offline',
      display_reason: 'Offline',
      next_action: 'Retry the request.',
      retryable: true,
    };
  });
  app.state.selectView('secrets');
  const getButton = (label: string, root = app.root) => {
    const textNode = findNode(root, (node) => node.text.trim() === label);
    const button = textNode?.tag === 'button' ? textNode : textNode?.parent;
    expect(button?.tag).toBe('button');
    return button!;
  };
  const clickButton = (label: string) => (getButton(label).props.onClick as () => void)();
  await settle();
  clickButton('Refresh');
  await settle();

  const status = () => findNode(app.root, (node) => node.props['aria-label'] === 'Agent status');
  expect(status()?.props['data-connected']).toBe('false');
  expect(findNode(status()!, (node) => node.text.trim() === 'Offline')).toBeDefined();
  expect(findNode(app.root, (node) => node.text === 'Secrets · development')).toBeDefined();
  expect(findNode(app.root, (node) => node.text === "Can't load secrets")).toBeDefined();
  expect(findNode(app.root, (node) => node.text === 'AgentUnavailable')).toBeDefined();
  const recovery = findNode(app.root, (node) => node.props.role === 'alert');
  expect(recovery).toBeDefined();
  expect(getButton('Start agent', recovery).props.class).toContain('companion-button--primary');
  expect(getButton('Retry', recovery).props.class).not.toContain('companion-button--primary');
  expect(
    findNode(app.root, (node) => node.props['aria-label'] === 'Refresh secrets')?.props.disabled,
  ).toBe(true);
  expect(getButton('Add secret').props.disabled).toBe(true);

  overrides.delete('agent_list_secrets');
  clickButton('Retry');
  await settle();
  expect(status()?.props['data-connected']).toBe('true');
  expect(findNode(app.root, (node) => node.text === "Can't load secrets")).toBeUndefined();
});

it('uses Secrets in the list, command palette, and history navigation', async () => {
  overrides.set('agent_list_secrets', () => ({
    rows: [
      {
        id: 'token',
        profile_id: a.profile_id,
        name: 'TOKEN',
        source: 'team-managed',
        source_precedence: 0,
        origin: 'team',
        current_version: 1,
        state: 'active',
        required: true,
        created_at: 0,
        updated_at: 0,
        last_rotated_at: null,
      } satisfies SecretWireRow,
    ],
  }));
  const app = await connectedApp();
  app.state.selectView('secrets');
  await settle();
  const heading = findNode(app.root, (node) => node.props.id === 'secret-metadata-list-heading');
  expect(heading).toBeDefined();
  expect(findNode(heading!, (node) => node.text === '1 secret · development')).toBeDefined();
  expect(findNode(app.root, (node) => node.props['aria-label'] === 'Search secrets')).toBeDefined();
  const paletteOption = (label: string) =>
    findNode(
      app.root,
      (node) =>
        node.props.role === 'option' && !!findNode(node, (content) => content.text === label),
    );
  expect(paletteOption('Add secret')?.parent?.props['aria-labelledby']).toBe(
    'palette-group-Quick-actions',
  );
  const token = paletteOption('TOKEN');
  expect(token?.parent?.props['aria-labelledby']).toBe('palette-group-Secrets');
  (token!.props.onClick as () => void)();
  await settle();
  expect(findNode(app.root, (node) => node.text === 'Secret history')).toBeDefined();
});

describe('reveal request lifetime in the mounted app', () => {
  it('sends dangerous-profile approval only after the user types the exact profile name', async () => {
    overrides.set('agent_read_config', () => ({
      privacy_redact_names: false,
      agent_unlock_ttl: '15m',
      user_verification_required_for: {},
      dangerous_profile: { dangerous: true },
    }));
    const app = await connectedApp();
    const dialog = findNode(app.root, (node) => node.tag === 'dialog');
    expect(dialog).toBeDefined();
    if (!dialog) return;
    const control = Object.assign(dialog, {
      open: false,
      returnValue: '',
      showModal() {
        this.open = true;
      },
      close(result = '') {
        this.open = false;
        this.returnValue = result;
        dialog.dispatchEvent(new Event('close'));
      },
    });

    const canceled = app.state.handleEditorReveal(secret());
    expect(control.open).toBe(true);
    expect(calls).not.toContain('agent_reveal');
    control.close();
    await canceled;
    expect(calls).not.toContain('agent_reveal');

    const approved = app.state.handleEditorReveal(secret());
    await settle();
    const name = byProp(dialog, 'id', 'dangerous-action-profile');
    const allow = renderedButton(dialog, 'Allow action');
    expect(nodeText(dialog)).toContain(a.profile_name);
    expect(allow.props.disabled).toBe(true);
    await input(name, `${a.profile_name} `);
    expect(allow.props.disabled).toBe(true);
    await submit(dialog);
    expect(calls).not.toContain('agent_reveal');
    await input(name, a.profile_name);
    expect(allow.props.disabled).toBe(false);
    await submit(dialog);
    await approved;
    expect(invoke).toHaveBeenCalledWith('agent_reveal', {
      request: {
        secret_name: 'TOKEN',
        profile_id: a.profile_id,
        confirm_dangerous_profile: a.profile_name,
      },
    });
  });

  it('shows a current response and keeps its TTL countdown', async () => {
    const app = await connectedApp();
    await app.state.handleEditorReveal(secret());
    await settle();
    expect(plaintext(app)).toBe('fixture-plaintext');
    expect(findNode(app.root, (node) => node.props.class === 'reveal__ttl')?.text).toBe(
      'Hides in 30s',
    );
  });

  const transitions = [
    'blur',
    'lock',
    'project',
    'profile',
    'view',
    'secret',
    'disconnect',
  ] as const;
  async function transition(app: ReturnType<typeof mountApp>, kind: (typeof transitions)[number]) {
    switch (kind) {
      case 'blur':
        windowEvents.dispatchEvent(new Event('blur'));
        // Refocusing must not resurrect the request that lost its lifetime.
        windowEvents.dispatchEvent(new Event('focus'));
        break;
      case 'lock':
        lockState = 'locked';
        await app.state.refresh();
        lockState = 'unlocked';
        await app.state.refresh();
        break;
      case 'project':
        await app.state.connectProject(false, b.root);
        await app.state.connectProject(false, a.root);
        break;
      case 'profile':
        nativeSelection = { ...a, profile_name: 'production', profile_id: 'A-production-id' };
        app.state.selectedProject = nativeSelection;
        await app.state.refresh();
        break;
      case 'view':
        app.state.selectView('settings');
        app.state.selectView('dashboard');
        break;
      case 'secret':
        app.state.selectedSecret = secret('OTHER');
        app.state.selectedSecret = secret();
        break;
      case 'disconnect':
        overrides.set('agent_status', () => Promise.reject('Agent disconnected'));
        await app.state.refresh();
        break;
    }
    await settle();
  }

  it.each(transitions)('discards a deferred response after %s', async (kind) => {
    const app = await connectedApp();
    const response = deferred<RevealResponse>();
    overrides.set('agent_reveal', () => response.promise);
    const revealing = app.state.handleEditorReveal(secret());
    expect(calls).toContain('agent_reveal');
    await transition(app, kind);
    response.resolve(revealed());
    await revealing;
    await settle();
    expect(plaintext(app)).toBeUndefined();
    expect(app.state.revealError).toBeNull();
  });

  it.each(transitions)('scrubs an already displayed value on %s', async (kind) => {
    const app = await connectedApp();
    await app.state.handleEditorReveal(secret());
    await settle();
    expect(plaintext(app)).toBe('fixture-plaintext');
    await transition(app, kind);
    expect(plaintext(app)).toBeUndefined();
  });

  it('invalidates at lock intent before the native lock finishes', async () => {
    const app = await connectedApp();
    const response = deferred<RevealResponse>();
    const locked = deferred<void>();
    overrides.set('agent_reveal', () => response.promise);
    overrides.set('agent_lock', () => locked.promise);
    const revealing = app.state.handleEditorReveal(secret());
    const locking = app.state.handleTrayMenuAction('lock-vault');
    response.resolve(revealed());
    await revealing;
    await settle();
    const valueWhileLocking = plaintext(app);
    locked.resolve();
    await locking;
    expect(valueWhileLocking).toBeUndefined();
  });

  it.each(['project', 'profile'] as const)(
    'invalidates when a %s switch starts before native completion',
    async (kind) => {
      const app = await connectedApp();
      const response = deferred<RevealResponse>();
      const switched = deferred<DesktopProjectContext>();
      overrides.set('agent_reveal', () => response.promise);
      overrides.set(
        kind === 'project' ? 'desktop_open_project' : 'agent_set_active_profile',
        () => switched.promise,
      );
      const revealing = app.state.handleEditorReveal(secret());
      const switching =
        kind === 'project'
          ? app.state.connectProject(false, b.root)
          : app.state.handleProfileSwitch({
              profileName: 'production',
              confirmation: undefined,
              dangerous: false,
            });
      response.resolve(revealed());
      await revealing;
      await settle();
      const valueWhileSwitching = plaintext(app);
      switched.resolve(b);
      await switching;
      expect(valueWhileSwitching).toBeUndefined();
    },
  );

  it('scrubs the previous value as soon as a newer reveal starts', async () => {
    const app = await connectedApp();
    const target = secret();
    await app.state.handleEditorReveal(target);
    await settle();
    const response = deferred<RevealResponse>();
    overrides.set('agent_reveal', () => response.promise);
    const revealing = app.state.handleEditorReveal(target);
    await settle();
    const valueWhilePending = plaintext(app);
    response.resolve(revealed('replacement'));
    await revealing;
    await settle();
    expect(valueWhilePending).toBeUndefined();
    expect(plaintext(app)).toBe('replacement');
  });

  it.each(['success', 'error'] as const)(
    'ignores an older %s after the newest reveal finishes',
    async (result) => {
      const app = await connectedApp();
      const first = deferred<RevealResponse>();
      const second = deferred<RevealResponse>();
      const target = secret();
      overrides.set('agent_reveal', () => first.promise);
      const older = app.state.handleEditorReveal(target);
      overrides.set('agent_reveal', () => second.promise);
      const newer = app.state.handleEditorReveal(target);
      second.resolve(revealed('newest'));
      await newer;
      if (result === 'success') first.resolve(revealed('obsolete'));
      else first.reject('Obsolete rejection');
      await older;
      await settle();
      expect(plaintext(app)).toBe('newest');
      expect(app.state.revealError).toBeNull();
    },
  );

  it.each(['success', 'error'] as const)('ignores a deferred %s after unmount', async (result) => {
    const app = await connectedApp();
    const response = deferred<RevealResponse>();
    overrides.set('agent_reveal', () => response.promise);
    const showing = vi.spyOn(app.state.revealModal!, 'show');
    const revealing = app.state.handleEditorReveal(secret());
    app.unmount();
    if (result === 'success') response.resolve(revealed());
    else response.reject('Late rejection');
    await revealing;
    expect(showing).not.toHaveBeenCalled();
    expect(app.state.revealError).toBeNull();
    expect(plaintext(app)).toBeUndefined();
  });

  it('allows a fresh reveal after a blur and a tray view transition', async () => {
    const app = await connectedApp();
    windowEvents.dispatchEvent(new Event('blur'));
    windowEvents.dispatchEvent(new Event('focus'));
    app.state.selectedSecret = secret();
    await app.state.handleTrayMenuAction('reveal-secret');
    await settle();
    expect(plaintext(app)).toBe('fixture-plaintext');
  });
});

describe('startup native project selection', () => {
  it('ignores an older vault listing that completes after a project is opened', async () => {
    const old = deferred<DesktopProjectContext[]>();
    overrides.set('desktop_list_projects', () => old.promise);
    const { root, state } = mountApp();
    await settle();
    overrides.set('desktop_list_projects', () => [a, b]);
    await state.connectProject(false, a.root);
    await settle();
    old.resolve([a]);
    await settle();
    const trigger = findNode(
      root,
      (node) =>
        typeof node.props['aria-label'] === 'string' &&
        node.props['aria-label'].startsWith('Switch vault or project'),
    )!;
    await clickRendered(trigger);
    expect(nodeText(byProp(root, 'id', 'vault-switcher-menu'))).toContain('B /…/B');
  });

  it('awaits native open of the sole known project before scoped status refresh', async () => {
    const opening = deferred<DesktopProjectContext>();
    overrides.set('desktop_list_projects', () => [a]);
    overrides.set('desktop_open_project', async () => {
      const result = await opening.promise;
      nativeSelection = result;
      return result;
    });
    const app = mountApp();
    await settle();
    expect(calls.filter((call) => call === 'desktop_open_project')).toHaveLength(1);
    expect(calls).not.toContain('agent_status');
    expect(app.state.selectedProject).toBeNull();
    opening.resolve(a);
    await settle();
    expect(nativeSelection).toEqual(a);
    expect(app.state.selectedProject).toEqual(a);
    expect(app.state.activeContext).toEqual(a);
    expect(app.state.projectPath).toBe(a.root);
    expect(calls.indexOf('desktop_open_project')).toBeLessThan(calls.indexOf('agent_status'));
    expect(app.state.desktopBusy).toBe(false);
  });

  it('keeps startup unselected when native opening fails', async () => {
    overrides.set('desktop_list_projects', () => [a]);
    overrides.set('desktop_open_project', () => Promise.reject('Folder unavailable'));
    const app = mountApp();
    await settle();
    expect(app.state.selectedProject).toBeNull();
    expect(app.state.activeContext).toBeNull();
    expect(app.state.desktopError).not.toBeNull();
    expect(app.state.desktopBusy).toBe(false);
    expect(calls).not.toContain('agent_status');
  });

  it.each([{ projects: [] }, { projects: [a, b] }])(
    'does not choose an ambiguous or empty list: $projects',
    async ({ projects }) => {
      overrides.set('desktop_list_projects', () => projects);
      const app = mountApp();
      await settle();
      expect(app.state.selectedProject).toBeNull();
      expect(calls).not.toContain('desktop_open_project');
      expect(calls).not.toContain('agent_status');
    },
  );

  it.each(['pending', 'completed', 'failed'] as const)(
    'does not overwrite a newer %s user selection with a late startup list',
    async (phase) => {
      const listing = deferred<DesktopProjectContext[]>();
      const opening = deferred<DesktopProjectContext>();
      overrides.set('desktop_list_projects', () => listing.promise);
      overrides.set('desktop_open_project', async () => {
        const result = await opening.promise;
        nativeSelection = result;
        return result;
      });
      const app = mountApp();
      await settle();
      const selecting = app.state.connectProject(false, b.root);
      if (phase === 'failed') opening.reject('Cannot open B');
      else if (phase === 'completed') opening.resolve(b);
      await settle();
      listing.resolve([a]);
      await settle();
      if (phase === 'pending') opening.resolve(b);
      await selecting;
      await settle();
      expect(
        vi.mocked(invoke).mock.calls.filter(([name]) => name === 'desktop_open_project'),
      ).toEqual([['desktop_open_project', { request: { path: b.root } }]]);
      expect(app.state.selectedProject).toEqual(phase === 'failed' ? null : b);
      expect(nativeSelection).toEqual(phase === 'failed' ? null : b);
    },
  );
});

describe('desktop scan terminal handoff in the mounted app', () => {
  const launch = { launched: true, command: 'locket scan --require-known' };

  async function scanButton(app: ReturnType<typeof mountApp>) {
    app.state.selectView('scan');
    await settle();
    const button = findNode(
      app.root,
      (node) =>
        node.tag === 'button' &&
        /Run scan again|Scan in terminal/.test(String(node.props['aria-label'])),
    );
    expect(button).toBeDefined();
    return button!;
  }

  function hasText(app: ReturnType<typeof mountApp>, text: string): boolean {
    return findNode(app.root, (node) => node.text.includes(text)) !== undefined;
  }

  it('routes the real scan button through the native project action and reports only launch', async () => {
    const app = await connectedApp();
    const button = await scanButton(app);
    expect(button.props.disabled).toBe(false);
    (button.props.onClick as () => void)();
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_scan_project', {
      request: { project_id: a.project_id },
    });
    expect(calls).not.toContain('agent_scan');
    expect(button.text).toBe('Scan in terminal');
    expect(hasText(app, 'locket scan --require-known')).toBe(true);
    expect(app.state.scanNotice).toContain('Opened in your terminal');
    expect(hasText(app, 'No scan findings')).toBe(false);
    expect(hasText(app, 'Last scan')).toBe(false);
    app.state.selectView('dashboard');
    await settle();
    expect(hasText(app, 'Scan: Not checked')).toBe(true);
  });

  it('disables the button without a selected project and guards the tray action', async () => {
    const app = mountApp();
    await settle();
    const button = await scanButton(app);
    expect(button.props.disabled).toBe(true);
    await app.state.handleTrayMenuAction('start-scan');
    expect(calls).not.toContain('desktop_scan_project');
    expect(calls).not.toContain('agent_scan');
    expect(app.state.scanError).toContain('Connect a project');
  });

  it.each(['locked', 'disconnected'] as const)(
    'hands a selected project to the interactive CLI when %s',
    async (state) => {
      const app = await connectedApp();
      if (state === 'locked') lockState = 'locked';
      else overrides.set('agent_status', () => Promise.reject('Agent disconnected'));
      await app.state.refresh();
      const button = await scanButton(app);
      expect(button.props.disabled).toBe(false);
      (button.props.onClick as () => void)();
      await settle();
      expect(invoke).toHaveBeenCalledWith('desktop_scan_project', {
        request: { project_id: a.project_id },
      });
      expect(calls).not.toContain('agent_scan');
    },
  );

  it.each(['rejected', 'not-launched'] as const)(
    'shows a %s launch failure without success',
    async (failure) => {
      const app = await connectedApp();
      overrides.set('desktop_scan_project', () =>
        failure === 'rejected'
          ? Promise.reject('Cannot open Terminal')
          : { ...launch, launched: false },
      );
      const button = await scanButton(app);
      (button.props.onClick as () => void)();
      await settle();
      expect(app.state.scanError).toContain(
        failure === 'rejected' ? 'Cannot open Terminal' : 'did not launch',
      );
      expect(app.state.scanNotice).toBeNull();
      expect(app.state.scanLaunching).toBe(false);
      expect(hasText(app, 'No scan findings')).toBe(false);
    },
  );

  it('disables and deduplicates the action while opening the terminal', async () => {
    const app = await connectedApp();
    const pending = deferred<typeof launch>();
    overrides.set('desktop_scan_project', () => pending.promise);
    const button = await scanButton(app);
    (button.props.onClick as () => void)();
    await settle();
    expect(button.props.disabled).toBe(true);
    expect(button.text).toBe('Opening terminal…');
    expect(hasText(app, 'Scanning project tree')).toBe(false);
    await app.state.handleTrayMenuAction('start-scan');
    expect(calls.filter((call) => call === 'desktop_scan_project')).toHaveLength(1);
    pending.resolve(launch);
    await settle();
    expect(button.props.disabled).toBe(false);
  });

  it.each(['success', 'error'] as const)(
    'ignores a stale %s after A to B to A selection and preserves the newer pending launch',
    async (outcome) => {
      const app = await connectedApp();
      const first = deferred<typeof launch>();
      overrides.set('desktop_scan_project', () => first.promise);
      const older = app.state.handleTrayMenuAction('start-scan');
      expect(calls).toContain('desktop_scan_project');
      await app.state.connectProject(false, b.root);
      await app.state.connectProject(false, a.root);
      const second = deferred<typeof launch>();
      overrides.set('desktop_scan_project', () => second.promise);
      const newer = app.state.handleTrayMenuAction('start-scan');
      if (outcome === 'success') first.resolve(launch);
      else first.reject('Obsolete launch failure');
      await older;
      expect(app.state.scanLaunching).toBe(true);
      expect(app.state.scanError).toBeNull();
      expect(app.state.scanNotice).toBeNull();
      second.resolve(launch);
      await newer;
      expect(app.state.scanLaunching).toBe(false);
      expect(app.state.scanNotice).toContain('Opened in your terminal');
    },
  );

  it('invalidates a pending launch at project switch intent and disables another launch until selection settles', async () => {
    const app = await connectedApp();
    const pending = deferred<typeof launch>();
    const opened = deferred<DesktopProjectContext>();
    overrides.set('desktop_scan_project', () => pending.promise);
    overrides.set('desktop_open_project', () => opened.promise);
    const launching = app.state.handleTrayMenuAction('start-scan');
    expect(calls).toContain('desktop_scan_project');
    const switching = app.state.connectProject(false, b.root);
    const button = await scanButton(app);
    expect(button.props.disabled).toBe(true);
    pending.resolve(launch);
    await launching;
    expect(app.state.scanNotice).toBeNull();
    expect(app.state.scanError).toBeNull();
    opened.resolve(b);
    await switching;
  });

  it.each(['success', 'error'] as const)(
    'discards a deferred %s after unmount',
    async (outcome) => {
      const app = await connectedApp();
      const pending = deferred<typeof launch>();
      overrides.set('desktop_scan_project', () => pending.promise);
      const launching = app.state.handleTrayMenuAction('start-scan');
      expect(calls).toContain('desktop_scan_project');
      app.unmount();
      if (outcome === 'success') pending.resolve(launch);
      else pending.reject('Late launch failure');
      await launching;
      expect(app.state.scanNotice).toBeNull();
      expect(app.state.scanError).toBeNull();
    },
  );

  it('shows live agent version and No project instead of Unavailable before a project is opened', async () => {
    overrides.set('desktop_list_projects', () => []);
    overrides.set('agent_status', () => ({
      lock_state: 'locked',
      project_id: null,
      profile_name: null,
      live_grant_count: 0,
      agent_version: '0.1.1',
      unlock_ttl_seconds: 900,
      running_session_count: 0,
      scan_warning_count: 0,
      recent_audit_status: 'unknown',
      pinned_reference_warning_count: 0,
    }));
    const app = mountApp();
    await settle();
    await app.state.refresh();
    await settle();
    expect(findNode(app.root, (node) => node.text.trim() === 'No project')).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'Agent live · 0.1.1')).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'Unavailable')).toBeUndefined();
    expect(findNode(app.root, (node) => node.text === 'Welcome to Locket')).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'Start with Global Vault')).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'Configuration checks')).toBeUndefined();
    expect(findNode(app.root, (node) => node.text === 'Recent')).toBeUndefined();
    app.unmount();
  });

  it('opens Global Vault from Welcome and offers migration setup from the empty vault', async () => {
    overrides.set('desktop_list_projects', () => (nativeSelection ? [shared] : []));
    overrides.set('desktop_copy_text_plain', () => undefined);
    const app = mountApp();
    await settle();
    const button = findNode(
      app.root,
      (node) =>
        node.tag === 'button' &&
        !!findNode(node, (content) => content.text.includes('Create Global Vault')),
    );
    expect(button).toBeDefined();
    (button!.props.onClick as () => void)();
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_open_shared_vault', {});
    expect(app.state.selectedProject).toEqual(shared);
    expect(findNode(app.root, (node) => node.text.includes('default'))).toBeDefined();
    expect(findNode(app.root, (node) => node.text === 'Welcome to Locket')).toBeUndefined();

    const copy = findNode(
      app.root,
      (node) =>
        node.tag === 'button' &&
        !!findNode(node, (content) => content.text.trim() === 'Copy AI migration prompt'),
    );
    expect(copy).toBeDefined();
    (copy!.props.onClick as () => void)();
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_copy_text_plain', {
      text: expect.stringContaining('Global Vault (@shared)'),
    });
    expect(
      findNode(
        app.root,
        (node) => node.props.role === 'status' && node.text === 'Copied AI migration prompt.',
      ),
    ).toBeDefined();
    const setup = findNode(
      app.root,
      (node) =>
        node.tag === 'button' &&
        !!findNode(node, (content) => content.text.trim() === 'AI agent & MCP setup'),
    );
    expect(setup).toBeDefined();
    (setup!.props.onClick as () => void)();
    await settle();
    expect(findNode(app.root, (node) => node.props.id === 'settings-mcp')).toBeDefined();
    app.unmount();
  });

  it('copies migration instructions and the native MCP JSON from Quick actions', async () => {
    const locket = { command: '/Applications/Locket Dev.app/locket', args: ['mcp'] };
    const json = JSON.stringify({ mcpServers: { locket } }, null, 2);
    overrides.set('desktop_copy_text_plain', () => undefined);
    overrides.set('desktop_mcp_config_snippet', () => ({ ...locket, json }));
    const app = mountApp();
    await settle();

    for (const [label, text] of [
      ['Copy AI agent .env migration prompt', expect.stringContaining('locket env scan --json')],
      ['Copy MCP config JSON', json],
    ] as const) {
      const action = findNode(
        app.root,
        (node) =>
          node.props.role === 'option' && !!findNode(node, (content) => content.text === label),
      );
      expect(action?.parent?.props['aria-labelledby']).toBe('palette-group-Quick-actions');
      (action!.props.onClick as () => void)();
      await settle();
      expect(invoke).toHaveBeenLastCalledWith('desktop_copy_text_plain', { text });
    }
    expect(
      findNode(
        app.root,
        (node) => node.props.role === 'status' && node.text === 'Copied MCP JSON.',
      ),
    ).toBeDefined();
    app.unmount();
  });

  it('auto-detects missing locket.toml and prompts to initialize instead of guessing', async () => {
    overrides.set('desktop_list_projects', () => []);
    overrides.set('desktop_inspect_project_folder', () => ({
      path: '/fixture/fresh-app',
      has_config: false,
      folder_name: 'fresh-app',
    }));
    const app = mountApp();
    await settle();
    app.state.projectPath = '/fixture/fresh-app';
    await settle();
    const form = findNode(app.root, (node) => node.tag === 'form' && !!node.props.onSubmit);
    expect(form).toBeDefined();
    (form!.props.onSubmit as (event: Event) => void)(new Event('submit'));
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_inspect_project_folder', {
      request: { path: '/fixture/fresh-app' },
    });
    expect(calls).not.toContain('desktop_open_project');
    expect(findNode(app.root, (node) => node.text.includes('Initialize & open'))).toBeDefined();
    app.unmount();
  });
});

describe('Global Vault workspace actions', () => {
  type MountedApp = ReturnType<typeof mountApp>;

  function click(app: MountedApp, label: string) {
    const button = findNode(app.root, (node) => node.tag === 'button' && node.text.includes(label));
    expect(button).toBeDefined();
    expect(button?.props.disabled).toBeFalsy();
    (button?.props.onClick as () => void)();
  }

  async function switchToShared(app: MountedApp) {
    const switcher = findNode(
      app.root,
      (node) =>
        node.props['aria-expanded'] === false &&
        node.props.class === 'companion-button shell__context',
    );
    expect(switcher).toBeDefined();
    (switcher?.props.onClick as () => void)();
    await settle();
    const item = findNode(
      app.root,
      (node) => node.tag === 'strong' && node.text === 'Global Vault (@shared)',
    );
    expect(item).toBeDefined();
    (item?.parent?.parent?.props.onClick as () => void)();
    await settle();
    expect(app.state.activeContext).toEqual(shared);
  }

  it('reviews each live usage and requires fresh approval before unlinking all and deleting', async () => {
    const row = {
      id: 'global-token',
      profile_id: shared.profile_id,
      source: 'user-local',
      name: 'GLOBAL_TOKEN',
      created_at: 0,
      updated_at: 0,
      current_version: 1,
      link_count: 2,
    };
    const usage = {
      link_id: 'link-dev',
      project_id: a.project_id,
      project_name: 'API',
      profile_id: a.profile_id,
      profile_name: 'development',
      profile_dangerous: false,
      local_name: 'API_TOKEN',
      target_secret_id: row.id,
      target_secret_name: row.name,
      created_at: 0,
      updated_at: 0,
    };
    const usages = [
      usage,
      {
        ...usage,
        link_id: 'link-prod',
        project_name: 'Jobs',
        profile_name: 'production',
        profile_dangerous: true,
        local_name: 'JOB_TOKEN',
      },
    ];
    let deleted = false;
    overrides.set('desktop_list_projects', () => [a, shared]);
    overrides.set('agent_list_secrets', () => ({
      rows: !deleted && nativeSelection?.project_id === shared.project_id ? [row] : [],
    }));
    overrides.set('desktop_list_shared_usages', () => ({ usages: [...usages] }));
    overrides.set('desktop_delete_secret', (args) => {
      if (usages.length === 2) {
        expect(args).toMatchObject({
          request: { expected_link_ids: usages.map((entry) => entry.link_id) },
        });
        // Simulate a new link after App's last usage read but before the delete commits.
        usages.push({
          ...usage,
          link_id: 'third',
          project_name: 'Tasks',
          profile_name: 'release',
          profile_dangerous: true,
          local_name: 'TASK_TOKEN',
        });
        return Promise.reject({
          kind: 'rejected',
          code: 'LinkSetChanged',
          message: 'Linked projects changed while you were reviewing them.',
        });
      }
      deleted = true;
      return { deleted, unlinked_count: usages.length };
    });
    Object.assign(windowEvents, { matchMedia: () => ({ matches: false }) });
    const app = await connectedApp();
    app.state.selectView('secrets');
    await switchToShared(app);
    await clickRendered(renderedButton(app.root, 'Details for GLOBAL_TOKEN'));
    const inspector = byProp(app.root, 'id', 'variable-inspector');
    expect(nodeText(app.root)).toContain('Used by 2 projects');
    expect(nodeText(inspector)).toContain('Linked projects');
    expect(nodeText(inspector)).toContain('API / development → API_TOKEN');
    expect(nodeText(inspector)).toContain('Jobs / production → JOB_TOKEN');

    await clickRendered(renderedButton(inspector, 'Delete'));
    const warning = byProp(inspector, 'role', 'alert');
    expect(nodeText(warning)).toContain('removes the live link');
    expect(renderedButton(inspector, 'Unlink all & delete').props.disabled).toBe(true);
    const confirmation = byProp(inspector, 'data-testid', 'secret-delete-confirmation');
    await input(confirmation, 'production');
    await clickRendered(renderedButton(inspector, 'Unlink all & delete'));
    expect(calls).toContain('desktop_delete_secret');
    expect(deleted).toBe(false);
    expect(usages).toHaveLength(3);
    expect(nodeText(app.root)).toContain('Linked projects changed');
    const refreshed = byProp(app.root, 'id', 'variable-inspector');
    await clickRendered(renderedButton(refreshed, 'Delete'));
    expect(nodeText(refreshed)).toContain('Tasks / release → TASK_TOKEN');
    const renewed = byProp(refreshed, 'data-testid', 'secret-delete-confirmation');
    await input(renewed, 'production');
    expect(renderedButton(refreshed, 'Unlink all & delete').props.disabled).toBe(true);
    await input(renewed, 'GLOBAL_TOKEN');
    await clickRendered(renderedButton(refreshed, 'Unlink all & delete'));
    expect(invoke).toHaveBeenCalledWith('desktop_delete_secret', {
      request: {
        project_id: shared.project_id,
        profile_id: shared.profile_id,
        secret_name: 'GLOBAL_TOKEN',
        source: 'user-local',
        unlink_all: true,
        expected_link_ids: [usage.link_id, 'link-prod', 'third'],
        confirmation: 'GLOBAL_TOKEN',
      },
    });
    expect(nodeText(app.root)).toContain('Removed 3 links.');
  });

  it('clears a project import path and requires an absolute env path in Global Vault', async () => {
    overrides.set('desktop_list_projects', () => [a, shared]);
    const app = await connectedApp();
    overrides.set('desktop_import_env', () => ({ summary: 'Imported 1 variable.' }));
    overrides.set('desktop_pick_file', () => 'config/.env');
    app.state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(app.root, 'Import .env'));
    expect(app.state.envPath).toBe('config/.env');
    expect(findNode(app.root, (node) => node.text.includes('Relative paths start'))).toBeDefined();

    await switchToShared(app);
    expect(app.state.envPath).toBe('');
    expect(findNode(app.root, (node) => node.props.id === 'import-heading')).toBeUndefined();
    app.state.selectView('secrets');
    await settle();
    overrides.set('desktop_pick_file', () => Promise.reject('Picker unavailable'));
    await clickRendered(renderedButton(app.root, 'Import .env'));
    expect(
      findNode(app.root, (node) => node.text.includes('Choose an absolute path')),
    ).toBeDefined();
    expect(
      findNode(app.root, (node) => node.text.includes('Relative paths start')),
    ).toBeUndefined();

    const importForm = findNode(
      app.root,
      (node) => node.props['aria-labelledby'] === 'import-heading',
    );
    const submit = findNode(
      importForm!,
      (node) => node.tag === 'button' && node.props.type === 'submit',
    );
    expect(submit?.text).toContain('Import secrets');
    const submitImport = () =>
      (submit?.parent?.props.onSubmit as (event: Event) => void)(new Event('submit'));
    app.state.envPath = '.env';
    await settle();
    expect(submit?.props.disabled).toBe(true);
    submitImport();
    await settle();
    expect(calls).not.toContain('desktop_import_env');

    app.state.envPath = '/fixture/Downloads/.env';
    await settle();
    expect(submit?.props.disabled).toBe(false);
    submitImport();
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_import_env', {
      request: expect.objectContaining({
        project_id: shared.project_id,
        path: '/fixture/Downloads/.env',
      }),
    });

    await app.state.connectProject(false, b.root);
    expect(app.state.envPath).toBe('.env');
  });

  it.each(['policies', 'scan'] as const)('connects a folder from the %s callout', async (view) => {
    const app = await connectedApp();
    await switchToShared(app);
    app.state.selectView(view);
    await settle();
    expect(
      findNode(app.root, (node) => node.props['aria-labelledby'] === 'project-required-heading'),
    ).toBeDefined();

    if (view === 'scan') await app.state.handleTrayMenuAction('start-scan');
    expect(calls).not.toContain('desktop_scan_project');
    expect(invoke).not.toHaveBeenCalledWith('agent_list_policies', {
      request: { project_id: shared.project_id, privacy_redact_names: false },
    });

    overrides.set('desktop_pick_directory', () => b.root);
    overrides.set('desktop_inspect_project_folder', () => ({
      path: b.root,
      has_config: true,
      folder_name: 'B',
    }));
    click(app, 'Connect a project folder');
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_open_project', { request: { path: b.root } });
    expect(app.state.activeContext).toEqual(b);
    expect(
      findNode(app.root, (node) => node.props['aria-labelledby'] === 'project-required-heading'),
    ).toBeUndefined();
  });

  it('asks before initializing a folder picked from Global Vault', async () => {
    const app = await connectedApp();
    await switchToShared(app);
    app.state.selectView('policies');
    await settle();
    overrides.set('desktop_pick_directory', () => b.root);
    overrides.set('desktop_inspect_project_folder', () => ({
      path: b.root,
      has_config: false,
      folder_name: 'B',
    }));
    overrides.set('desktop_initialize_project', () => (nativeSelection = b));
    click(app, 'Connect a project folder');
    await settle();
    expect(calls).not.toContain('desktop_initialize_project');
    expect(app.state.activeContext).toEqual(shared);

    click(app, 'Initialize & open');
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_initialize_project', {
      request: { path: b.root },
    });
    expect(app.state.activeContext).toEqual(b);
  });

  it('accepts a typed project path when the native picker is unavailable', async () => {
    const app = await connectedApp();
    await switchToShared(app);
    app.state.selectView('policies');
    await settle();
    overrides.set('desktop_pick_directory', () => Promise.reject('Picker unavailable'));
    overrides.set('desktop_inspect_project_folder', () => ({
      path: b.root,
      has_config: true,
      folder_name: 'B',
    }));
    click(app, 'Connect a project folder');
    await settle();
    expect(findNode(app.root, (node) => node.props.id === 'manual-project-path')).toBeDefined();

    app.state.projectPath = b.root;
    await settle();
    const form = findNode(app.root, (node) => node.tag === 'form' && !!node.props.onSubmit);
    (form?.props.onSubmit as (event: Event) => void)(new Event('submit'));
    await settle();
    expect(app.state.activeContext).toEqual(b);
    expect(findNode(app.root, (node) => node.props.id === 'manual-project-path')).toBeUndefined();
  });
});

function usePreviewFixtures(params = new URLSearchParams()) {
  const fixtureInvoke = createMockRuntime(params);
  vi.mocked(invoke).mockImplementation((async (command: string, args?: InvokeArgs) => {
    calls.push(command);
    const override = overrides.get(command);
    if (override) return override(args);
    if (command === 'agent_subscribe_status' || command.startsWith('tray_set_')) return;
    return fixtureInvoke(command, (args ?? {}) as Record<string, unknown>);
  }) as typeof invoke);
  return fixtureInvoke;
}

describe('connected desktop journeys through the preview fixture agent', () => {
  async function openFixtureProject() {
    const fixtureInvoke = usePreviewFixtures();
    Object.assign(windowEvents, { matchMedia: () => ({ matches: false }) });
    const app = mountApp();
    await settle();
    const projects = (await fixtureInvoke('desktop_list_projects', {})) as DesktopProjectContext[];
    await app.state.connectProject(
      false,
      projects.find((project) => project.project_id === 'acme-api')!.root,
    );
    await settle();
    expect(app.state.activeContext?.project_id).toBe('acme-api');
    return app;
  }

  it('checks .env duplicates without importing, then sends per-key link and promote choices', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('secrets');
    await settle();
    const view = byProp(root, 'aria-labelledby', 'secret-metadata-list-heading');
    await clickRendered(renderedButton(view, 'Import .env'));
    const panel = byProp(root, 'aria-labelledby', 'import-heading');
    await clickRendered(renderedButton(panel, 'Check for duplicates'));
    expect(invoke).toHaveBeenCalledWith('desktop_import_env', {
      request: {
        project_id: 'acme-api',
        path: '/Users/justin/Workspaces/acme-api/.env',
        overwrite: false,
        literal: false,
        confirmation: undefined,
        dry_run: true,
      },
    });
    let choices = byProp(panel, 'aria-label', 'Duplicate check results');
    expect(nodeText(choices)).toContain('@shared / default / POSTMARK_TOKEN');
    expect(nodeText(choices)).toContain('web-app / dev / SENTRY_DSN');
    expect(nodeText(choices)).not.toContain('preview-imported-value');
    expect(nodeText(view)).not.toContain('REDIS_URL');
    await check(control(choices, 'Link to @shared/POSTMARK_TOKEN'));
    await input(control(panel, 'File path'), 'service.env');
    expect(
      findNode(panel, (node) => node.props['aria-label'] === 'Duplicate check results'),
    ).toBeUndefined();
    await clickRendered(renderedButton(panel, 'Check for duplicates'));
    choices = byProp(panel, 'aria-label', 'Duplicate check results');
    await check(control(choices, 'Link to @shared/POSTMARK_TOKEN'));
    await check(control(choices, 'Promote to @shared/ERROR_TRACKING_DSN'));
    await submit(panel);
    expect(invoke).toHaveBeenCalledWith('desktop_import_env', {
      request: {
        project_id: 'acme-api',
        path: 'service.env',
        overwrite: false,
        literal: false,
        confirmation: undefined,
        link_to_shared: { MAIL_TOKEN: 'POSTMARK_TOKEN' },
        promote_to_shared: { ERROR_TRACKING_DSN: 'ERROR_TRACKING_DSN' },
      },
    });
    expect(nodeText(root)).toContain('Imported 1, linked 1, promoted 1');
    expect(nodeText(root)).toContain('Linked → @shared/ERROR_TRACKING_DSN');
  });

  it('opens a duplicate in another vault and focuses the requested row details', async () => {
    const { root, state } = await openFixtureProject();
    const focus = vi.fn();
    vi.stubGlobal('document', {
      getElementById: (id: string) => (id === 'variable-inspector-title' ? { focus } : null),
    });
    state.selectView('secrets');
    await settle();
    const global = renderedButton(root, 'View in Global Vault');
    await clickRendered(global);
    expect(state.activeContext?.is_shared).toBe(true);
    await vi.waitFor(() => {
      expect(nodeText(byProp(root, 'id', 'variable-inspector'))).toContain('Secret details');
    });
    expect(focus).toHaveBeenCalledOnce();
  });

  it('requires a trusted folder before opening a duplicate from another project', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('settings');
    await settle();
    overrides.set('desktop_list_duplicates', () => ({
      groups: [
        {
          group_id: 'fixture',
          members: [
            {
              secret_id: 'remote-variable',
              name: 'FIXTURE_TOKEN',
              project_id: 'remote',
              project_name: 'Remote',
              profile_id: 'remote-profile',
              profile_name: 'qa',
            },
          ],
        },
      ],
    }));
    state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(root, 'Open secret'));
    expect(nodeText(root)).toContain(
      'Open the matching project from a trusted folder to review this secret.',
    );
    expect(state.activeContext?.project_id).toBe('acme-api');
  });

  it.each([
    ['acme-api-staging', 'staging', false],
    ['acme-api-prod', 'prod', true],
  ] as const)(
    'routes another environment’s duplicate through its switch flow (%s)',
    async (profile_id, profile_name, profile_dangerous) => {
      const { root, state } = await openFixtureProject();
      state.selectView('settings');
      await settle();
      overrides.set('desktop_list_duplicates', () => ({
        groups: [
          {
            group_id: 'fixture',
            members: [
              {
                secret_id: 'other-env-variable',
                name: 'FIXTURE_TOKEN',
                project_id: 'acme-api',
                project_name: 'acme-api',
                profile_id,
                profile_name,
                profile_dangerous,
              },
            ],
          },
        ],
      }));
      state.selectView('secrets');
      await settle();
      await clickRendered(renderedButton(root, 'Open secret'));
      if (profile_dangerous) {
        expect(nodeText(root)).toContain('Switch environment');
        expect(calls).not.toContain('agent_set_active_profile');
      } else {
        await vi.waitFor(() => expect(state.activeContext?.profile_id).toBe(profile_id));
        expect(invoke).toHaveBeenCalledWith('agent_set_active_profile', {
          request: expect.objectContaining({ profile_name }),
        });
      }
    },
  );

  it('requires fresh Global Vault confirmation when import choices change', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('secrets');
    await settle();
    await clickRendered(
      renderedButton(
        byProp(root, 'aria-labelledby', 'secret-metadata-list-heading'),
        'Import .env',
      ),
    );
    const panel = byProp(root, 'aria-labelledby', 'import-heading');
    await clickRendered(renderedButton(panel, 'Check for duplicates'));
    const choices = byProp(panel, 'aria-label', 'Duplicate check results');
    await check(control(choices, 'Promote to @shared/ERROR_TRACKING_DSN'));
    overrides.set('desktop_import_env', (args) => {
      const request = (args as { request: { target_confirmation?: string } }).request;
      if (request.target_confirmation !== 'default') {
        return Promise.reject({
          kind: 'rejected',
          code: 'ConfirmationFailed',
          message: 'Type default to confirm promotion into the Global Vault.',
        });
      }
      return { summary: 'Imported and promoted.' };
    });
    await submit(panel);
    const confirmation = control(panel, 'Type default');
    await input(confirmation, 'default');
    await check(control(choices, 'Link to @shared/POSTMARK_TOKEN'));
    expect(confirmation.value).toBe('');
    await input(confirmation, 'default');
    await submit(panel);
    expect(invoke).toHaveBeenCalledWith('desktop_import_env', {
      request: expect.objectContaining({ target_confirmation: 'default' }),
    });
    expect(nodeText(root)).toContain('Imported and promoted.');
  });

  it('connects monitoring, device, audit and version views to project-scoped metadata', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    app.state.selectView('execution');
    await settle();
    expect(nodeText(root)).toContain('running dev-server run-1');
    expect(nodeText(root)).toContain('failed deploy-prod run-3');
    overrides.set('agent_list_runtime_sessions', () => Promise.reject('Runtime transport lost'));
    await clickRendered(renderedButton(root, 'Refresh'));
    expect(nodeText(root)).toContain('Runtime transport lost.');
    overrides.delete('agent_list_runtime_sessions');

    app.state.selectView('devices');
    await settle();
    expect(nodeText(root)).toContain('Work MacBook device — 62a8b220c5f4 local');
    overrides.set('agent_list_device_members', () =>
      Promise.reject('Privacy-sensitive fixture detail'),
    );
    await clickRendered(renderedButton(root, 'Refresh'));
    expect(nodeText(root)).toContain('Device request failed.');
    expect(nodeText(root)).not.toContain('Privacy-sensitive fixture detail');
    overrides.delete('agent_list_device_members');

    app.state.selectView('audit');
    await settle();
    expect(nodeText(root)).toContain('RUN_POLICY');
    expect(nodeText(root)).toContain('Audit chain verified.');
    overrides.set('agent_verify_audit', () => Promise.reject('Verification interrupted'));
    await clickRendered(renderedButton(root, 'Verify audit chain'));
    expect(nodeText(root)).toContain('Verification interrupted.');
    overrides.delete('agent_verify_audit');
    await clickRendered(renderedButton(root, 'Verify audit chain'));
    expect(invoke).toHaveBeenCalledWith('agent_verify_audit', {
      request: { project_id: 'acme-api' },
    });
    expect(nodeText(root)).toContain('Audit chain verified.');

    app.state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(root, 'Open metadata for STRIPE_SECRET_KEY'));
    expect(nodeText(root)).toContain('v3 current');
    expect(nodeText(root)).toContain('v2 deprecated');
    await clickRendered(renderedButton(root, 'Copy value'));
    expect(nodeText(root)).toContain('Clipboard unavailable:');
    overrides.set('agent_copy_secret', () => ({ kind: 'copied' }));
    await clickRendered(renderedButton(root, 'Copy value'));
    expect(nodeText(root)).toContain('Copied value temporarily.');
    expect(nodeText(root)).not.toContain('preview-only-value');
    await clickRendered(renderedButton(root, 'Reveal'));
    expect(plaintext(app)).toBe('preview-only-value');
    windowEvents.dispatchEvent(new Event('blur'));
    await settle();
    expect(plaintext(app)).toBeUndefined();
    overrides.set('agent_list_versions', () => Promise.reject('Fixture transport detail'));
    await clickRendered(renderedButton(root, 'Refresh'));
    expect(nodeText(root)).toContain('Version request failed.');
    expect(nodeText(root)).not.toContain('Fixture transport detail');
  });

  it('previews and exports a scoped backup, then reviews and verifies its file before recovery rotation', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    app.state.selectView('recovery');
    await settle();
    expect(renderedButton(root, 'Export').props.disabled).toBe(true);
    await input(control(root, 'Recipient descriptor', 'textarea'), 'lkdev2_preview_fixture');
    await clickRendered(renderedButton(root, 'Preview scope'));
    expect(invoke).toHaveBeenCalledWith('agent_export_bundle', {
      request: expect.objectContaining({
        project_id: 'acme-api',
        profile_id: 'acme-api-dev',
        preview_only: true,
        scope: 'active-profile',
      }),
    });
    expect(nodeText(root)).toContain('6 variables and 1 environment selected.');
    await clickRendered(renderedButton(root, 'Export'));
    expect(nodeText(root)).toContain('Sealed bundle exported.');
    expect(invoke).toHaveBeenCalledWith('agent_export_bundle', {
      request: expect.objectContaining({ preview_only: false }),
    });
    await clickRendered(renderedButton(root, 'Browse for a bundle to import'));
    await input(control(root, 'To import into dangerous'), 'dev');
    await clickRendered(renderedButton(root, 'Review bundle'));
    expect(nodeText(root)).toContain('Sealed bundle imported.');
    expect(invoke).toHaveBeenCalledWith('agent_import_bundle', {
      request: expect.objectContaining({
        conflict_mode: 'review',
        confirm_dangerous_profile: 'dev',
      }),
    });

    await clickRendered(renderedButton(root, 'Browse for a bundle to verify'));
    overrides.set('agent_verify_bundle', () => Promise.reject('fixture-untrusted-detail'));
    await clickRendered(renderedButton(root, 'Verify'));
    expect(nodeText(root)).toContain('Backup request failed.');
    expect(nodeText(root)).not.toContain('fixture-untrusted-detail');
    overrides.delete('agent_verify_bundle');
    await clickRendered(renderedButton(root, 'Verify'));
    expect(nodeText(root)).toContain('Bundle verified.');
    await check(control(root, 'One-time display acknowledged'));
    await clickRendered(renderedButton(root, 'Rotate'));
    expect(invoke).toHaveBeenCalledWith('agent_recovery_rotate', {
      request: {
        project_id: 'acme-api',
        verification: 'platform',
        acknowledged_one_time_display: true,
        clear_after_display: true,
      },
    });
    expect(nodeText(root)).toContain('Recovery code rotated.');
  });

  it('discards a delayed backup preview when switching projects, even with the same draft', async () => {
    const { root, state } = await openFixtureProject();
    const pending = deferred<{ status: string; message: string }>();
    const projects = await invoke<DesktopProjectContext[]>('desktop_list_projects', {});
    const next = projects.find((project) => project.project_id === 'web-app')!;
    overrides.set('agent_export_bundle', () => pending.promise);
    state.selectView('recovery');
    await settle();
    await input(control(root, 'Recipient descriptor', 'textarea'), 'lkdev2_fixture');
    await clickRendered(renderedButton(root, 'Preview scope'));
    expect(nodeText(root)).toContain('Backup action running…');
    await state.connectProject(false, next.root);
    await settle();
    expect(state.activeContext?.project_id).toBe(next.project_id);
    pending.resolve({ status: 'preview', message: 'Old project preview' });
    await settle();
    expect(nodeText(root)).not.toContain('Old project preview');
    expect(renderedButton(root, 'Export').props.disabled).toBe(true);
    expect(renderedButton(root, 'Preview scope').props.disabled).toBe(false);
  });

  it('writes settings patches, applies privacy to connected metadata, and opens command runs in the terminal', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    app.state.selectView('settings');
    await settle();
    await clickRendered(renderedButton(root, '4h'));
    expect(nodeText(root)).toContain('Vault session duration saved.');
    expect(invoke).toHaveBeenCalledWith('agent_write_config', {
      request: {
        project_id: 'acme-api',
        profile_name: 'dev',
        changes: { agent_unlock_ttl: '4h' },
      },
    });
    const privacy = byProp(root, 'aria-labelledby', 'settings-privacy');
    await check(control(privacy, 'Redact'));
    expect(nodeText(root)).toContain('Settings saved.');
    app.state.selectView('execution');
    await settle();
    expect(nodeText(root)).toContain('Command 1 run-1 Environment');
    expect(nodeText(root)).not.toContain('dev-server');
    app.state.selectView('devices');
    await settle();
    expect(nodeText(root)).toContain('Member 1');
    expect(nodeText(root)).not.toMatch(/Work MacBook|62a8b220c5f4/);
    app.state.selectView('audit');
    await settle();
    expect(nodeText(root)).not.toMatch(/DATABASE_URL|STRIPE_SECRET_KEY|acme-api-dev/);
    app.state.selectView('settings');
    await settle();
    await check(control(byProp(root, 'aria-labelledby', 'settings-privacy'), 'Redact'), false);
    app.state.selectView('policies');
    await settle();
    expect(nodeText(root)).toContain('db-migrate');
    overrides.set('desktop_run_policy', () => ({ launched: false }));
    await clickRendered(renderedButton(root, 'Run in terminal'));
    expect(nodeText(root)).toContain('The terminal did not launch.');
    overrides.delete('desktop_run_policy');
    await clickRendered(renderedButton(root, 'Run in terminal'));
    expect(invoke).toHaveBeenCalledWith('desktop_run_policy', {
      request: { project_id: 'acme-api', policy_name: 'db-migrate' },
    });
    expect(nodeText(root)).toContain('Opened in your terminal. Complete any approval there.');
  });

  it('drops pending command launch feedback after switching to another project', async () => {
    const { root, state } = await openFixtureProject();
    const pending = deferred<{ launched: boolean }>();
    overrides.set('desktop_run_policy', () => pending.promise);
    state.selectView('policies');
    await settle();
    await clickRendered(renderedButton(root, 'Run in terminal'));
    expect(invoke).toHaveBeenCalledWith('desktop_run_policy', {
      request: { project_id: 'acme-api', policy_name: 'db-migrate' },
    });
    const next = (await createMockRuntime(new URLSearchParams())(
      'desktop_list_projects',
      {},
    )) as DesktopProjectContext[];
    await state.connectProject(
      false,
      next.find(({ project_id }) => project_id === 'web-app')!.root,
    );
    await settle();
    expect(state.activeContext?.project_id).toBe('web-app');
    pending.reject('Old project terminal refused launch');
    await settle();
    expect(nodeText(root)).not.toContain('Old project terminal refused launch');
  });

  it('requires a fresh export preview after a repeated preview fails', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('recovery');
    await settle();
    await input(control(root, 'Recipient descriptor', 'textarea'), 'lkdev2_fixture');
    await clickRendered(renderedButton(root, 'Preview scope'));
    expect(renderedButton(root, 'Export').props.disabled).toBe(false);

    overrides.set('agent_export_bundle', () => Promise.reject('preview failed'));
    await clickRendered(renderedButton(root, 'Preview scope'));
    expect(nodeText(root)).toContain('Backup request failed.');
    expect(renderedButton(root, 'Export').props.disabled).toBe(true);
  });

  it('opens the selected secret for rotation with its source and focuses the new value', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    const focus = vi.fn();
    vi.stubGlobal('document', {
      getElementById: (id: string) => (id === 'secret-editor-rotate-value' ? { focus } : null),
    });
    app.state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(root, 'Details for JWT_SIGNING_KEY'));
    await clickRendered(renderedButton(byProp(root, 'id', 'variable-inspector'), 'Rotate'));
    const rotate = byProp(root, 'aria-labelledby', 'secret-editor-rotate-heading');
    expect(byProp(rotate, 'data-testid', 'secret-editor-rotate-name').value).toBe(
      'JWT_SIGNING_KEY',
    );
    expect(nodeText(rotate)).toContain('This machine');
    expect(focus).toHaveBeenCalledOnce();
    await input(byProp(rotate, 'data-testid', 'secret-editor-rotate-value'), 'fixture-rotation');
    await submit(rotate);
    expect(invoke).toHaveBeenCalledWith('agent_rotate_secret', {
      request: expect.objectContaining({ secret_name: 'JWT_SIGNING_KEY', source: 'machine-local' }),
    });
    await clickRendered(renderedButton(root, 'Back to Secrets'));
    expect(nodeText(root)).toContain('JWT_SIGNING_KEY');
    await clickRendered(renderedButton(root, 'Details for JWT_SIGNING_KEY'));
    await clickRendered(renderedButton(byProp(root, 'id', 'variable-inspector'), 'Rotate'));
    const reopened = byProp(root, 'aria-labelledby', 'secret-editor-rotate-heading');
    await clickRendered(renderedButton(reopened, 'Generate'));
    expect(byProp(reopened, 'data-testid', 'secret-editor-rotate-value').value).toHaveLength(43);
    await clickRendered(renderedButton(root, 'Back to Secrets'));
    await clickRendered(renderedButton(root, 'Details for JWT_SIGNING_KEY'));
    await clickRendered(renderedButton(byProp(root, 'id', 'variable-inspector'), 'Rotate'));
    const newDraft = byProp(root, 'data-testid', 'secret-editor-rotate-value');
    expect(newDraft.value).toBe('');
    expect(newDraft.props.type).toBe('password');
  });

  it('discards a pending env picker result when switching vaults', async () => {
    const { root, state } = await openFixtureProject();
    const selection = deferred<string>();
    overrides.set('desktop_pick_file', () => selection.promise);
    state.selectView('secrets');
    await settle();
    const trigger = renderedButton(root, 'Import .env');
    await clickRendered(trigger);
    expect(trigger.props.disabled).toBe(true);
    const projects = await invoke<DesktopProjectContext[]>('desktop_list_projects', {});
    await state.connectProject(
      false,
      projects.find((project) => project.project_id === 'web-app')!.root,
    );
    selection.resolve('/fixture/old-vault/.env');
    await settle();
    expect(state.activeContext?.project_id).toBe('web-app');
    expect(findNode(root, (node) => node.props.id === 'import-heading')).toBeUndefined();
    expect(calls).not.toContain('desktop_import_env');
  });

  it('sets, rotates, and refreshes variable metadata through the editor without rendering its values', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    app.state.selectView('secret-editor');
    await settle();
    const create = byProp(root, 'aria-labelledby', 'secret-editor-set-heading');
    await input(byProp(create, 'data-testid', 'secret-editor-set-name'), 'FIXTURE_VALUE');
    await input(byProp(create, 'data-testid', 'secret-editor-set-value'), 'fixture-create-value');
    await submit(create);
    expect(nodeText(root)).toContain('Created FIXTURE_VALUE v1.');
    expect(nodeText(root)).not.toContain('fixture-create-value');

    const rotate = byProp(root, 'aria-labelledby', 'secret-editor-rotate-heading');
    await input(byProp(rotate, 'data-testid', 'secret-editor-rotate-name'), 'FIXTURE_VALUE');
    await input(
      byProp(rotate, 'data-testid', 'secret-editor-rotate-value'),
      'fixture-rotate-value',
    );
    await submit(rotate);
    await settle();
    expect(nodeText(root)).toContain('Rotated FIXTURE_VALUE to v2.');
    expect(nodeText(root)).not.toMatch(/fixture-create-value|fixture-rotate-value/);
    expect(invoke).toHaveBeenCalledWith('agent_rotate_secret', {
      request: expect.objectContaining({ profile_id: 'acme-api-dev', source: 'user-local' }),
    });
    await clickRendered(renderedButton(root, 'Back to Secrets'));
    await clickRendered(renderedButton(root, 'Open metadata for FIXTURE_VALUE'));
    expect(nodeText(root)).toContain('v2 current');
  });

  it('clears secret drafts and ignores pending editor feedback after switching projects', async () => {
    const { root, state } = await openFixtureProject();
    const nextWrite = deferred<{
      action: string;
      secret_id: string;
      version: number;
      source: string;
    }>();
    overrides.set('agent_set_secret', () => nextWrite.promise);
    state.selectView('secret-editor');
    await settle();
    const field = (name: string) => byProp(root, 'data-testid', `secret-editor-${name}`);
    await input(field('set-name'), 'FIRST_VAULT_TOKEN');
    await input(field('set-value'), 'fixture-first-vault-value');
    await input(field('rotate-name'), 'DATABASE_URL');
    await input(field('rotate-value'), 'fixture-rotation-draft');
    await submit(byProp(root, 'aria-labelledby', 'secret-editor-set-heading'));
    expect(nodeText(root)).toContain('Submitting…');
    expect(invoke).toHaveBeenCalledWith('agent_set_secret', {
      request: expect.objectContaining({ project_id: 'acme-api', profile_id: 'acme-api-dev' }),
    });
    const projects = await invoke<DesktopProjectContext[]>('desktop_list_projects', {});
    await state.connectProject(
      false,
      projects.find((project) => project.project_id === 'web-app')!.root,
    );
    await settle();
    expect(state.activeContext?.project_id).toBe('web-app');
    expect(field('set-name').value).toBe('');
    expect(field('set-value').value).toBe('');
    expect(field('rotate-name').value).toBe('');
    expect(field('rotate-value').value).toBe('');
    nextWrite.resolve({ action: 'set', secret_id: 'test', version: 1, source: 'user-local' });
    await settle();
    expect(nodeText(root)).not.toContain('Created FIRST_VAULT_TOKEN');
    expect(nodeText(root)).not.toMatch(/fixture-first-vault-value|fixture-rotation-draft/);
  });

  it('discovers variables across vaults and routes dangerous environments through typed confirmation', async () => {
    const app = await openFixtureProject();
    const { root } = app;
    app.state.selectView('discover');
    await settle();
    const discover = byProp(root, 'aria-labelledby', 'discovery-title');
    await input(control(discover, 'Search'), 'DATABASE_URL');
    await input(control(discover, 'Tag'), 'database');
    await input(control(discover, 'Owner'), 'Platform');
    await submit(discover);
    expect(nodeText(discover)).toContain('2 results');
    expect(nodeText(discover)).not.toContain('STRIPE_SECRET_KEY');
    await clickRendered(renderedButton(discover, 'Switch to staging'));
    await settle();
    expect(app.state.activeContext?.profile_name).toBe('staging');

    await input(control(discover, 'Search'), 'STRIPE_SECRET_KEY');
    await input(control(discover, 'Tag'), '');
    await input(control(discover, 'Owner'), '');
    await submit(discover);
    await clickRendered(renderedButton(discover, 'Switch to prod'));
    expect(nodeText(root)).toContain(
      'Type the target environment name to confirm dangerous switch',
    );
    expect(renderedButton(root, 'Switch environment').props.disabled).toBe(true);
    const form = byProp(root, 'data-testid', 'profile-switcher-form');
    await input(control(form, 'Type the target environment'), 'prod');
    await submit(form);
    await settle();
    expect(app.state.activeContext?.profile_name).toBe('prod');

    app.state.selectView('discover');
    await settle();
    const searchView = byProp(root, 'aria-labelledby', 'discovery-title');
    await input(control(searchView, 'Search'), 'web-app');
    await submit(searchView);
    await clickRendered(renderedButton(searchView, 'Open project'));
    await settle();
    expect(app.state.activeContext?.project_id).toBe('web-app');
  });

  it('updates and deletes the selected command, preserving the draft when a save fails', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('policies');
    await settle();
    await clickRendered(byProp(root, 'aria-label', 'Inspect policy deploy-prod'));
    await clickRendered(renderedButton(root, 'Edit'));
    const form = byProp(root, 'data-testid', 'policy-form');
    const name = byProp(form, 'data-testid', 'policy-form-name');
    expect(name.value).toBe('deploy-prod');
    expect(byProp(form, 'data-testid', 'policy-form-required').value).toBe('STRIPE_SECRET_KEY');
    expect(byProp(form, 'data-testid', 'policy-form-command').value).toContain(
      'lk://dev/STRIPE_SECRET_KEY@v2',
    );
    await input(name, 'deploy-preview');
    overrides.set('desktop_save_policy', () => Promise.reject('Write refused'));
    await submit(form);
    expect(nodeText(form)).toContain('Write refused.');
    expect(name.value).toBe('deploy-preview');
    overrides.delete('desktop_save_policy');
    await submit(form);
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_save_policy', {
      request: expect.objectContaining({
        mode: 'edit',
        original_name: 'deploy-prod',
        policy: expect.objectContaining({ name: 'deploy-preview' }),
      }),
    });
    expect(findNode(root, (node) => node.props['data-testid'] === 'policy-form')).toBeUndefined();
    await clickRendered(byProp(root, 'aria-label', 'Inspect policy deploy-preview'));
    await clickRendered(renderedButton(root, 'Delete'));
    const remove = byProp(root, 'data-testid', 'policy-form');
    expect(nodeText(remove)).toContain('Delete deploy-preview');
    await submit(remove);
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_save_policy', {
      request: expect.objectContaining({ mode: 'delete', original_name: 'deploy-preview' }),
    });
    expect(
      findNode(root, (node) => node.props['aria-label'] === 'Inspect policy deploy-preview'),
    ).toBeUndefined();
  });

  it('ignores errors from a prior project’s metadata refresh after changing selection', async () => {
    const { root, state } = await openFixtureProject();
    const pending = deferred<never>();
    const delayed = [
      'agent_list_runtime_sessions',
      'agent_list_device_members',
      'agent_list_versions',
      'agent_list_audit',
      'agent_list_policies',
    ];
    for (const command of delayed) overrides.set(command, () => pending.promise);
    state.selectView('audit');
    await settle();
    await clickRendered(renderedButton(root, 'Verify audit chain'));
    await settle();
    expect(nodeText(root)).toContain('Loading audit');
    for (const command of delayed) overrides.delete(command);
    const projects = await invoke<DesktopProjectContext[]>('desktop_list_projects', {});
    await state.connectProject(
      false,
      projects.find((project) => project.project_id === 'web-app')!.root,
    );
    await settle();
    pending.reject('fixture-old-project-transport-failure');
    await settle();
    expect(nodeText(root)).toContain('No audit rows.');
    expect(nodeText(root)).not.toContain('fixture-old-project-transport-failure');
    state.selectView('execution');
    await settle();
    expect(nodeText(root)).toContain('No runtime sessions yet.');
    state.selectView('policies');
    await settle();
    expect(nodeText(root)).toContain('No commands yet.');
    expect(nodeText(root)).not.toContain('fixture-old-project-transport-failure');
  });

  it('uses the project dashboard to navigate checks and configures signed team updates', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('dashboard');
    await settle();
    const dashboard = byProp(root, 'aria-labelledby', 'project-dashboard-heading');
    expect(nodeText(dashboard)).toContain('Setup complete');
    expect(nodeText(dashboard)).toContain('Failed or stale runs: 1');
    expect(nodeText(dashboard)).toContain('Secrets 7 4 required');
    expect(nodeText(dashboard)).toContain('Recorded runs 3 1 failed/stale');
    const metric = (label: string) =>
      findNode(dashboard, (node) => node.tag === 'button' && nodeText(node).startsWith(label))!;
    await clickRendered(metric('Recorded runs'));
    expect(nodeText(root)).toContain('Runtime sessions');
    state.selectView('dashboard');
    await settle();
    const refresh = renderedButton(
      byProp(root, 'aria-labelledby', 'project-dashboard-heading'),
      'Refresh',
    );
    const before = calls.filter((command) => command === 'agent_verify_audit').length;
    await clickRendered(refresh);
    await settle();
    expect(calls.filter((command) => command === 'agent_verify_audit')).toHaveLength(before + 1);

    state.selectView('team');
    await settle();
    expect(nodeText(root)).toContain('Showing the last verified update.');
    await input(control(root, 'Shared folder'), '/fixture/team-delivery');
    await clickRendered(renderedButton(root, 'Test connection'));
    expect(invoke).toHaveBeenCalledWith('desktop_team_sync_test_remote', {
      request: {
        project_id: 'acme-api',
        transport: { kind: 'folder', path: '/fixture/team-delivery' },
      },
    });
    expect(nodeText(root)).toContain('Connected · 3 encrypted packages found');
    await clickRendered(renderedButton(root, 'Save delivery backend & consent'));
    expect(invoke).toHaveBeenCalledWith('desktop_team_sync_configure', {
      request: { project_id: 'acme-api', folder: '/fixture/team-delivery', allow_dangerous: false },
    });
    expect(nodeText(root)).toContain('team-delivery');
    await clickRendered(renderedButton(root, 'Apply verified updates'));
    expect(invoke).toHaveBeenCalledWith('desktop_team_sync_now', {
      request: { project_id: 'acme-api' },
    });
  });

  it('tests WebDAV, requires the exact profile for consent, and hides delivery details in privacy mode', async () => {
    const { root, state } = await openFixtureProject();
    state.selectView('team');
    await settle();
    const dialog = byProp(root, 'aria-labelledby', 'dangerous-action-title');
    const prompt = Object.assign(dialog, {
      open: false,
      returnValue: '',
      showModal() {
        this.open = true;
      },
      close(result = '') {
        this.open = false;
        this.returnValue = result;
        dialog.dispatchEvent(new Event('close'));
      },
    });
    const url = 'https://dav.fixture.test/team';
    await clickRendered(renderedButton(root, 'WebDAV'));
    await input(control(root, 'HTTPS URL'), url);
    await select(control(root, 'Auth type', 'select'), 'basic');
    await input(control(root, 'Username'), 'fixture-user');
    const password = control(root, 'Password');
    await input(password, 'fixture-password');
    await clickRendered(renderedButton(root, 'Test connection'));
    const transport = {
      kind: 'webdav',
      url,
      auth_kind: 'basic',
      credential_mode: 'vault',
      username: 'fixture-user',
      secret: 'fixture-password',
    };
    expect(invoke).toHaveBeenCalledWith('desktop_team_sync_test_remote', {
      request: { project_id: 'acme-api', transport },
    });
    expect(nodeText(root)).toContain('Connected · 3 encrypted packages found');
    await check(control(root, 'Allow automatic delivery'));
    await clickRendered(renderedButton(root, 'Save delivery backend & consent'));
    expect(password.value).toBe('');
    expect(prompt.open).toBe(true);
    expect(nodeText(dialog)).toContain('Configure team sync');
    expect(calls).not.toContain('desktop_team_sync_configure');
    const profile = byProp(dialog, 'id', 'dangerous-action-profile');
    await input(profile, 'Dev');
    expect(renderedButton(dialog, 'Allow action').props.disabled).toBe(true);
    await submit(dialog);
    expect(calls).not.toContain('desktop_team_sync_configure');
    await input(profile, 'dev');
    await submit(dialog);
    expect(invoke).toHaveBeenCalledWith('desktop_team_sync_configure', {
      request: {
        project_id: 'acme-api',
        transport,
        allow_dangerous: true,
        confirm_dangerous_profile: 'dev',
      },
    });
    expect(nodeText(root)).toContain(`Delivery backend WebDAV ${url}`);
    await clickRendered(renderedButton(root, 'Test connection'));
    expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_test_remote', {
      request: { project_id: 'acme-api' },
    });

    state.selectView('settings');
    await settle();
    await check(control(byProp(root, 'aria-labelledby', 'settings-privacy'), 'Redact'));
    state.selectView('team');
    await settle();
    expect(nodeText(root)).toContain('Remote storage cannot prove');
    expect(nodeText(root)).not.toMatch(/dav\.fixture\.test|fixture-password|Set up this device/);
  });
});

describe('desktop activity while opening and using a project', () => {
  it('starts the agent, offers a retry after inspection failure, and initializes the folder chosen in Welcome', async () => {
    usePreviewFixtures(new URLSearchParams({ state: 'welcome' }));
    const app = mountApp();
    const { root } = app;
    await settle();
    overrides.set('desktop_start_agent', () => Promise.reject('Could not start fixture agent'));
    await clickRendered(renderedButton(root, 'Start agent'));
    expect(nodeText(root)).toContain('Could not start fixture agent.');
    overrides.delete('desktop_start_agent');
    await clickRendered(renderedButton(root, 'Start agent'));
    expect(nodeText(root)).toContain('Agent started.');
    expect(nodeText(root)).toContain('No project');

    const folder = '/fixture/new-project';
    overrides.set('desktop_pick_directory', () => folder);
    overrides.set('desktop_inspect_project_folder', () =>
      Promise.reject('Folder metadata unavailable'),
    );
    await clickRendered(renderedButton(root, 'Choose a project folder'));
    expect(nodeText(root)).toContain('Folder metadata unavailable.');
    overrides.delete('desktop_inspect_project_folder');
    await clickRendered(renderedButton(root, 'Choose a project folder'));
    expect(nodeText(root)).toContain('new-project has no locket.toml yet.');
    await clickRendered(renderedButton(root, 'Cancel'));
    expect(nodeText(root)).not.toContain('Initialize Locket in this folder?');
    await clickRendered(renderedButton(root, 'Choose a project folder'));
    await clickRendered(renderedButton(root, 'Initialize & open'));
    await settle();
    expect(invoke).toHaveBeenCalledWith('desktop_initialize_project', {
      request: { path: folder },
    });
    expect(invoke).toHaveBeenCalledWith('agent_unlock', {
      request: expect.objectContaining({ source: { kind: 'os-keychain' } }),
    });
    expect(app.state.activeContext?.root).toBe(folder);
  });

  it('applies tray view actions and guides copy, reveal, and unlock when no target is selected', async () => {
    const app = mountApp();
    await settle();
    await app.state.handleTrayMenuAction('unlock-vault');
    expect(nodeText(app.root)).toContain('Connect a project before unlocking.');
    await app.state.handleTrayMenuAction('copy-secret');
    expect(nodeText(app.root)).toContain('Select a secret in the list before copying.');
    await app.state.handleTrayMenuAction('reveal-secret');
    expect(nodeText(app.root)).toContain('Select a secret in the list before revealing.');
    await app.state.handleTrayMenuAction('open-app');
    await settle();
    expect(nodeText(app.root)).toContain('Connect a project folder');
    await app.state.connectProject(false, a.root);
    await app.state.handleTrayMenuAction('switch-profile');
    await settle();
    expect(nodeText(app.root)).toContain('Switch environment');
    await app.state.handleTrayMenuAction('run-policy');
    await settle();
    expect(nodeText(app.root)).toContain('No commands yet.');
    await app.state.handleTrayMenuAction('unlock-vault');
    await settle();
    expect(nodeText(app.root)).toContain('Use system keychain');
  });

  it('keeps the previous settings after a rejected write and re-enables editing', async () => {
    const app = await connectedApp();
    app.state.selectView('settings');
    await settle();
    overrides.set('agent_write_config', () =>
      Promise.reject({
        kind: 'rejected',
        code: 'SettingsDenied',
        message: 'fixture-sensitive-diagnostic',
      }),
    );
    await clickRendered(renderedButton(app.root, '8h'));
    expect(nodeText(app.root)).toContain('SettingsDenied');
    expect(nodeText(app.root)).not.toContain('fixture-sensitive-diagnostic');
    expect(renderedButton(app.root, '15m').props['aria-pressed']).toBe(true);
    expect(renderedButton(app.root, '8h').props.disabled).toBe(false);
  });
});

describe('desktop recovery feedback', () => {
  it('keeps backup failures scoped and maps each agent failure to safe user feedback', async () => {
    const { root, state } = await connectedApp();
    state.selectView('recovery');
    await settle();
    const unavailable = {
      kind: 'unavailable',
      reason: 'fixture-local-socket',
      socket_path: '/fixture/private',
    };
    const denied = { kind: 'rejected', code: 'RecoveryDenied', message: 'fixture-recovery-detail' };
    const exportPanel = byProp(root, 'aria-labelledby', 'backup-export-heading');
    await input(control(exportPanel, 'Recipient descriptor', 'textarea'), 'lkdev2_fixture');
    overrides.set('agent_export_bundle', () => Promise.reject(unavailable));
    await clickRendered(renderedButton(exportPanel, 'Preview scope'));
    expect(nodeText(root)).toContain('Agent unavailable.');
    expect(nodeText(root)).not.toMatch(/fixture-local-socket|fixture\/private/);
    expect(renderedButton(exportPanel, 'Export').props.disabled).toBe(true);
    const importPanel = byProp(root, 'aria-labelledby', 'backup-import-heading');
    await input(control(importPanel, 'Bundle path'), '/fixture/import.lkb');
    overrides.set('agent_import_bundle', () => Promise.reject(denied));
    await clickRendered(renderedButton(importPanel, 'Review bundle'));
    expect(nodeText(root)).toContain('RecoveryDenied');
    expect(nodeText(root)).not.toContain('fixture-recovery-detail');
    overrides.set('agent_import_bundle', () =>
      Promise.reject({
        kind: 'protocol',
        reason: 'request timed out; outcome is unknown. Refresh before retrying',
      }),
    );
    await clickRendered(renderedButton(importPanel, 'Review bundle'));
    expect(nodeText(root)).toContain('Check whether it completed before retrying.');
    overrides.set('agent_recovery_rotate', () => Promise.reject(denied));
    await check(control(root, 'One-time display acknowledged'));
    await clickRendered(renderedButton(root, 'Rotate'));
    expect(nodeText(root)).toContain('RecoveryDenied');
    expect(nodeText(root)).not.toContain('Backup action running');
    expect(renderedButton(root, 'Rotate').props.disabled).toBe(true);
    await check(control(root, 'One-time display acknowledged'));
    expect(renderedButton(root, 'Rotate').props.disabled).toBe(false);
  });

  it('dismisses the project switcher on Escape or outside focus and returns keyboard focus', async () => {
    const { root } = await connectedApp();
    const trigger = findNode(
      root,
      (node) =>
        typeof node.props['aria-label'] === 'string' &&
        node.props['aria-label'].startsWith('Switch vault or project'),
    )!;
    const wrapper = trigger.parent!;
    const focus = vi.fn();
    Object.assign(trigger, { focus });
    Object.assign(wrapper, { contains: (target: EventTarget) => target === trigger });
    await clickRendered(trigger);
    expect(trigger.props['aria-expanded']).toBe(true);
    wrapper.dispatchEvent(Object.assign(new Event('focusout'), { relatedTarget: trigger }));
    await settle();
    expect(trigger.props['aria-expanded']).toBe(true);
    wrapper.dispatchEvent(Object.assign(new Event('keydown'), { key: 'Escape' }));
    await settle();
    expect(trigger.props['aria-expanded']).toBe(false);
    expect(focus).toHaveBeenCalledOnce();
    await clickRendered(trigger);
    wrapper.dispatchEvent(Object.assign(new Event('focusout'), { relatedTarget: root }));
    await settle();
    expect(trigger.props['aria-expanded']).toBe(false);
    await clickRendered(trigger);
    windowEvents.dispatchEvent(new Event('pointerdown'));
    await settle();
    expect(trigger.props['aria-expanded']).toBe(false);
  });
});

describe('desktop metadata failure and recovery', () => {
  it('marks a broken audit chain with metadata-only status and retries after a transport failure', async () => {
    const timestamp = 1_750_000_000_000_000_000;
    const base = {
      timestamp,
      profile_id: a.profile_id,
      secret_name: 'TOKEN',
      command: 'fixture-command-metadata',
    };
    overrides.set('agent_list_audit', () => ({
      rows: [
        { ...base, sequence: 1, action: 'UNLOCK', status: 'SUCCESS' },
        { ...base, sequence: 2, action: 'REVEAL', status: 'DENIED' },
        { ...base, sequence: 3, action: 'COPY', status: 'FAILED' },
      ],
      chain_status: { locked: false, hmac_ok: false, first_break_sequence: 2 },
    }));
    overrides.set('agent_verify_audit', () => ({
      locked: false,
      hmac_ok: false,
      first_break_sequence: 2,
    }));
    const { root, state } = await connectedApp();
    state.selectView('audit');
    await settle();
    expect(nodeText(root)).toContain('Audit chain broken at row 2.');
    expect(nodeText(root)).toContain('REVEAL DENIED');
    expect(nodeText(root)).toContain('COPY FAILED');
    expect(nodeText(root)).not.toContain('fixture-command-metadata');
    const listAudit = overrides.get('agent_list_audit')!;
    overrides.set('agent_list_audit', () => Promise.reject('Audit transport failed'));
    await clickRendered(renderedButton(root, 'Verify audit chain'));
    await settle();
    expect(nodeText(root)).toContain('Audit transport failed.');
    expect(nodeText(root)).not.toContain('REVEAL DENIED');
    overrides.set('agent_list_audit', listAudit);
    await clickRendered(renderedButton(root, 'Verify audit chain'));
    await settle();
    expect(nodeText(root)).toContain('Audit chain broken at row 2.');
  });

  it('retries command loading and keeps detection failures separate from command approval', async () => {
    overrides.set('agent_list_policies', () => Promise.reject('Policy transport unavailable'));
    overrides.set('desktop_detect_commands', () => Promise.reject('Detection failed'));
    const { root, state } = await connectedApp();
    state.selectView('policies');
    await settle();
    expect(nodeText(root)).toContain('Policy transport unavailable.');
    expect(nodeText(root)).toContain('Detection failed.');
    expect(renderedButton(root, 'New command').props.disabled).toBe(true);
    overrides.delete('agent_list_policies');
    overrides.delete('desktop_detect_commands');
    await clickRendered(renderedButton(root, 'Refresh commands'));
    await settle();
    expect(nodeText(root)).not.toContain('Detection failed.');
    expect(nodeText(root)).toContain('No commands yet.');
    await clickRendered(renderedButton(root, 'New command'));
    expect(nodeText(byProp(root, 'data-testid', 'policy-form'))).toContain('Create command');
  });

  it('focuses the add form from onboarding and sends an env import only after project confirmation', async () => {
    overrides.set('agent_read_config', () => ({
      privacy_redact_names: false,
      agent_unlock_ttl: '15m',
      user_verification_required_for: {},
      dangerous_profile: {
        profile_name: a.profile_name,
        profile_label: a.profile_name,
        dangerous: true,
      },
    }));
    const { root, state } = await connectedApp();
    const focus = vi.fn();
    vi.stubGlobal('document', {
      getElementById: (id: string) => (id === 'secret-editor-set-heading' ? { focus } : null),
    });
    state.selectView('secrets');
    await settle();
    await clickRendered(renderedButton(root, 'Add secret'));
    expect(focus).toHaveBeenCalledOnce();
    expect(nodeText(root)).toContain('Add or rotate secret');
    expect(findNode(root, (node) => node.props.id === 'import-heading')).toBeUndefined();
    await clickRendered(renderedButton(root, 'Back to Secrets'));
    overrides.set('desktop_pick_file', () => null);
    await clickRendered(renderedButton(root, 'Import .env'));
    expect(findNode(root, (node) => node.props.id === 'import-heading')).toBeUndefined();
    overrides.set('desktop_pick_file', () => '/fixture/config/.env');
    const onboarding = byProp(root, 'aria-labelledby', 'variables-onboarding-heading');
    await clickRendered(renderedButton(onboarding, 'Import .env'));
    expect(invoke).toHaveBeenCalledWith('desktop_pick_file', { title: 'Browse for an env file' });
    const panel = byProp(root, 'aria-labelledby', 'import-heading');
    const confirmation = control(panel, 'Type development to confirm');
    expect(renderedButton(panel, 'Import secrets').props.disabled).toBe(true);
    await input(confirmation, 'wrong-environment');
    await submit(panel);
    expect(calls).not.toContain('desktop_import_env');
    await input(confirmation, 'development');
    await check(control(panel, 'Replace existing values'));
    await check(control(panel, 'Keep expansion syntax'));
    overrides.set('desktop_import_env', () => Promise.reject('Import refused'));
    await submit(panel);
    expect(nodeText(root)).toContain('Import refused.');
    expect(confirmation.value).toBe('development');
    overrides.set('desktop_import_env', () => ({ summary: 'Imported 1 variable.' }));
    await submit(panel);
    expect(invoke).toHaveBeenCalledWith('desktop_import_env', {
      request: {
        project_id: a.project_id,
        path: '/fixture/config/.env',
        overwrite: true,
        literal: true,
        confirmation: 'development',
      },
    });
    expect(nodeText(root)).toContain('Imported 1 variable.');
    expect(findNode(root, (node) => node.props.id === 'import-heading')).toBeUndefined();
  });
});

it('requires fresh dangerous approval for saving and rotation, and drops approval on project switch', async () => {
  overrides.set('agent_read_config', () => ({
    privacy_redact_names: false,
    agent_unlock_ttl: '15m',
    user_verification_required_for: {},
    dangerous_profile: { dangerous: true },
  }));
  overrides.set('agent_set_secret', () => ({
    action: 'set',
    secret_id: 'fixture-id',
    version: 1,
    source: 'user-local',
  }));
  const { root, state } = await connectedApp();
  const dialog = byProp(root, 'aria-labelledby', 'dangerous-action-title');
  const prompt = Object.assign(dialog, {
    open: false,
    returnValue: '',
    showModal() {
      this.open = true;
    },
    close(result = '') {
      this.open = false;
      this.returnValue = result;
      dialog.dispatchEvent(new Event('close'));
    },
  });
  state.selectView('secret-editor');
  await settle();
  const create = byProp(root, 'aria-labelledby', 'secret-editor-set-heading');
  await input(byProp(create, 'data-testid', 'secret-editor-set-name'), 'FIXTURE_APPROVAL');
  await input(byProp(create, 'data-testid', 'secret-editor-set-value'), 'fixture-only-draft');
  await submit(create);
  expect(prompt.open).toBe(true);
  expect(nodeText(dialog)).toContain('Save secret');
  expect(calls).not.toContain('agent_set_secret');
  prompt.close('cancel');
  await settle();
  expect(calls).not.toContain('agent_set_secret');
  expect(nodeText(create)).toContain('Request failed.');
  expect(nodeText(create)).not.toContain('fixture-only-draft');
  expect(byProp(create, 'data-testid', 'secret-editor-set-value').value).toBe('');
  await input(byProp(create, 'data-testid', 'secret-editor-set-value'), 'fixture-only-draft');
  await submit(create);
  await input(byProp(dialog, 'id', 'dangerous-action-profile'), a.profile_name);
  await submit(dialog);
  await settle();
  expect(invoke).toHaveBeenCalledWith('agent_set_secret', {
    request: {
      project_id: a.project_id,
      profile_id: a.profile_id,
      secret_name: 'FIXTURE_APPROVAL',
      value: 'fixture-only-draft',
      source: 'user-local',
      grant_id: undefined,
      confirm_dangerous_profile: a.profile_name,
    },
  });
  expect(byProp(create, 'data-testid', 'secret-editor-set-value').value).toBe('');

  const rotate = byProp(root, 'aria-labelledby', 'secret-editor-rotate-heading');
  await input(byProp(rotate, 'data-testid', 'secret-editor-rotate-name'), 'FIXTURE_APPROVAL');
  await input(byProp(rotate, 'data-testid', 'secret-editor-rotate-value'), 'fixture-only-rotation');
  await submit(rotate);
  expect(prompt.open).toBe(true);
  expect(nodeText(dialog)).toContain('Rotate secret');
  await state.connectProject(false, b.root);
  await settle();
  expect(prompt.open).toBe(false);
  expect(calls).not.toContain('agent_rotate_secret');
  expect(byProp(root, 'data-testid', 'secret-editor-rotate-value').value).toBe('');
});

it('releases the tray listener if registration finishes after unmount', async () => {
  const pending = deferred<() => void>();
  const unlisten = vi.fn();
  vi.mocked(listen).mockImplementation((event) =>
    event === 'tray-menu-action' ? pending.promise : Promise.resolve(() => {}),
  );
  const app = mountApp();
  await settle();
  expect(listen).toHaveBeenCalledWith('tray-menu-action', expect.any(Function));
  app.unmount();
  pending.resolve(unlisten);
  await settle();
  expect(unlisten).toHaveBeenCalledOnce();
});

it('refreshes after a native tray lock without locking the agent again', async () => {
  const { state } = await connectedApp();
  const registration = vi.mocked(listen).mock.calls.find(([event]) => event === 'tray-menu-action');
  expect(registration).toBeDefined();
  lockState = 'locked';
  registration![1]({ event: 'tray-menu-action', id: 1, payload: 'lock-vault' });
  await settle();
  expect(state.status?.lock_state).toBe('locked');
  expect(calls).not.toContain('agent_lock');
});

it.each([
  ['agent_read_config', 'settings', { kind: 'unavailable' }, 'Agent unavailable.'],
  ['agent_read_config', 'settings', 'config transport failed', 'Settings request failed.'],
  [
    'agent_list_device_members',
    'devices',
    { kind: 'rejected', code: 'AccessDenied' },
    'AccessDenied',
  ],
  ['agent_list_device_members', 'devices', { kind: 'unavailable' }, 'Agent unavailable.'],
  ['agent_list_versions', 'versions', { kind: 'rejected', code: 'AccessDenied' }, 'AccessDenied'],
  ['agent_list_versions', 'versions', { kind: 'unavailable' }, 'Agent unavailable.'],
] as const)('shows scoped metadata errors for %s on %s', async (command, view, error, label) => {
  overrides.set(command, () => Promise.reject(error));
  const { root, state } = await connectedApp();
  state.selectView(view);
  await settle();
  expect(nodeText(root)).toContain(label);
});

it('offers useful picker and clipboard feedback in desktop quick actions', async () => {
  usePreviewFixtures();
  const { root, state } = mountApp();
  await settle();
  const choose = async (label: string) => {
    const action = findNode(
      root,
      (node) =>
        node.props.role === 'option' && !!findNode(node, (content) => content.text === label),
    )!;
    expect(action).toBeDefined();
    await clickRendered(action);
  };
  const projects = await invoke<DesktopProjectContext[]>('desktop_list_projects');
  const selected = projects.find((project) => project.project_id === 'acme-api')!;
  await state.connectProject(false, selected.root);
  await settle();
  await choose('Commands');
  expect(nodeText(root)).toContain('Run in terminal');
  overrides.set('desktop_copy_text_plain', () => undefined);
  overrides.set('desktop_mcp_config_snippet', () =>
    Promise.reject('native MCP snippet unavailable'),
  );
  await choose('Copy MCP config JSON');
  expect(invoke).toHaveBeenCalledWith('desktop_copy_text_plain', {
    text: expect.stringContaining('"command": "locket"'),
  });
  overrides.set('desktop_copy_text_plain', () => Promise.reject('clipboard unavailable'));
  await choose('Copy lk://dev/DATABASE_URL');
  expect(nodeText(root)).toContain('Could not copy reference.');
  overrides.set('desktop_copy_text_plain', () => undefined);
  await choose('Copy lk://dev/DATABASE_URL');
  expect(nodeText(root)).toContain('Copied lk://dev/DATABASE_URL');
  overrides.set('desktop_open_shared_vault', () => Promise.reject('Vault open unavailable'));
  await choose('Global Vault (@shared)');
  expect(nodeText(root)).toContain('Vault open unavailable.');
  overrides.delete('desktop_open_shared_vault');
  await choose('Global Vault (@shared)');
  await vi.waitFor(() => expect(state.activeContext?.is_shared).toBe(true));
  await choose('acme-api');
  await vi.waitFor(() => expect(state.activeContext?.project_id).toBe('acme-api'));
  await choose('Lock vault');
  await vi.waitFor(() => expect(state.status?.lock_state).toBe('locked'));
});
