import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke, type InvokeArgs } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import App from './App.vue';
import type { AgentStatus, DesktopProjectContext, RevealResponse } from './agent/types';
import type { SecretRowMeta } from './types/views';
import type RevealModal from './components/RevealModal.vue';
import { deferred, findNode, mountComponent, settle } from './test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

interface AppState {
  selectedProject: DesktopProjectContext | null;
  activeContext: DesktopProjectContext | null;
  selectedSecret: SecretRowMeta | null;
  projectPath: string;
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
  handleTrayMenuAction: (action: 'lock-vault' | 'reveal-secret' | 'start-scan') => Promise<void>;
  handleProfileSwitch: (payload: {
    profileName: string;
    confirmation: undefined;
    dangerous: boolean;
  }) => Promise<void>;
  selectView: (view: 'dashboard' | 'secrets' | 'settings' | 'scan') => void;
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
    case 'desktop_open_project': {
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
    case 'agent_list_audit':
      return {
        rows: [],
        chain_status: { locked: false, hmac_ok: null, first_break_sequence: null },
      };
    case 'agent_reveal':
      return revealed();
    case 'desktop_scan_project':
      return { launched: true, command: 'locket scan --require-known' };
    case 'agent_scan':
      return { findings: [], locked: true };
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

describe('automatic locking availability', () => {
  it.each([undefined, 'unavailable: native observer unavailable'])(
    'shows manual-lock guidance when monitoring is %s',
    async (monitoring) => {
      sessionMonitoring = monitoring;
      const app = await connectedApp();
      const warning = () =>
        findNode(app.root, (node) => node.props['data-testid'] === 'session-lock-warning');
      expect(warning()?.text).toContain('Lock the vault before leaving this device');
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

describe('reveal request lifetime in the mounted app', () => {
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
});
