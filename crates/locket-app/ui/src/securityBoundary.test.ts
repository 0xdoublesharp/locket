import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import App from './App.vue';
import type { DesktopProjectContext } from './agent/types';
import { createMockRuntime } from './preview/mockRuntime';
import { button, byProp, click, findNode, mountComponent, nodeText, settle } from './test/renderer';
import type { SecretRowMeta } from './types/views';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

interface AppState {
  activeContext: DesktopProjectContext | null;
  knownProjects: DesktopProjectContext[];
  connectProject: (initialize: boolean, path: string) => Promise<void>;
  handleEditorReveal: (row: SecretRowMeta) => Promise<void>;
  handleListCopy: (row: SecretRowMeta) => Promise<void>;
  handleTrayMenuAction: (action: 'lock-vault') => Promise<void>;
}

const plaintext = 'webview-security-test-canary';
const secret: SecretRowMeta = {
  id: 'variable-1',
  name: 'DATABASE_URL',
  source: 'team',
  required: true,
  optional: false,
  createdAt: '2026-01-01T00:00:00Z',
  currentVersion: 1,
  hasDeprecatedGrace: false,
};

const storageAccess = vi.fn();
const clipboardWrite = vi.fn();
let unmount: (() => void) | undefined;

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers({ toFake: ['performance', 'setInterval', 'clearInterval'] });
  const storage = new Proxy(
    {},
    {
      get: storageAccess,
      set: () => {
        storageAccess();
        return true;
      },
      defineProperty: () => {
        storageAccess();
        return true;
      },
    },
  );
  const storageGlobals = { localStorage: storage, sessionStorage: storage, indexedDB: storage };
  const document = Object.defineProperty({}, 'cookie', { get: storageAccess, set: storageAccess });
  for (const [name, value] of Object.entries(storageGlobals)) vi.stubGlobal(name, value);
  vi.stubGlobal('document', document);
  vi.stubGlobal('window', Object.assign(new EventTarget(), storageGlobals, { document }));
  vi.stubGlobal('navigator', { clipboard: { writeText: clipboardWrite } });

  const native = createMockRuntime(new URLSearchParams());
  vi.mocked(invoke).mockImplementation((async (command, args) => {
    if (command === 'agent_reveal') return { value: plaintext, ttl_seconds: 1 };
    if (command === 'agent_copy_secret') return { kind: 'copied', ttl_seconds: 1 };
    if (Array.isArray(args) || args instanceof ArrayBuffer || args instanceof Uint8Array) {
      throw new TypeError('Expected a JSON object for the native fixture');
    }
    return native(command, args ?? {});
  }) as typeof invoke);
  vi.mocked(listen).mockResolvedValue(() => {});
});

afterEach(() => {
  unmount?.();
  unmount = undefined;
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function connectedApp() {
  const app = mountComponent<AppState>(App);
  unmount = app.unmount;
  await settle();
  const project = app.state.knownProjects.find((entry) => !entry.is_shared);
  if (!project) throw new Error('Expected a project fixture');
  await app.state.connectProject(false, project.root);
  await settle();
  expect(app.state.activeContext).toEqual(project);
  return app;
}

it('copies through native IPC without exposing plaintext or accessing WebView storage', async () => {
  const { root, state } = await connectedApp();
  vi.mocked(invoke).mockClear();
  await state.handleListCopy(secret);
  await settle();

  expect(invoke).toHaveBeenCalledWith('agent_copy_secret', {
    request: {
      secret_name: secret.name,
      project_id: state.activeContext?.project_id,
      profile_id: state.activeContext?.profile_id,
    },
  });
  expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).not.toContain('agent_reveal');
  expect(nodeText(root)).toContain('Copied value temporarily.');
  expect(nodeText(root)).not.toContain(plaintext);
  expect(clipboardWrite).not.toHaveBeenCalled();
  expect(storageAccess).not.toHaveBeenCalled();
});

it.each(['dismiss', 'lock', 'timeout'] as const)(
  'clears a revealed value on %s without accessing WebView storage',
  async (action) => {
    const { root, state } = await connectedApp();
    const value = () => findNode(root, (node) => node.props['data-testid'] === 'reveal-value');
    await state.handleEditorReveal(secret);
    await settle();
    expect(value()?.text).toBe(plaintext);
    expect(storageAccess).not.toHaveBeenCalled();

    switch (action) {
      case 'dismiss':
        await click(button(byProp(root, 'aria-labelledby', 'reveal-title'), 'Close'));
        break;
      case 'lock':
        await state.handleTrayMenuAction('lock-vault');
        expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toContain('agent_lock');
        break;
      case 'timeout':
        await vi.advanceTimersByTimeAsync(999);
        expect(value()?.text).toBe(plaintext);
        await vi.advanceTimersByTimeAsync(1);
        break;
    }

    await settle();
    expect(value()).toBeUndefined();
    expect(nodeText(root)).not.toContain(plaintext);
    expect(storageAccess).not.toHaveBeenCalled();
  },
);
