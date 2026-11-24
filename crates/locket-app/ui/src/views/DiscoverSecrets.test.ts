import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { findNode, mountComponent, settle } from '../test/renderer';
import { createMockRuntime } from '../preview/mockRuntime';
import DiscoverSecrets from './DiscoverSecrets.vue';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

beforeEach(() => {
  vi.stubGlobal('Document', class {});
  vi.stubGlobal('ShadowRoot', class {});
});
afterEach(() => vi.unstubAllGlobals());

it('lists shared vault metadata and applies query, tag, and owner to all projects', async () => {
  vi.mocked(invoke).mockImplementation(createMockRuntime(new URLSearchParams()) as typeof invoke);
  const view = mountComponent<{
    query: string;
    tag: string;
    owner: string;
    search: () => Promise<void>;
  }>(DiscoverSecrets, { privacyMode: false, knownProjectIds: ['acme-api'] });
  try {
    await settle();
    expect(findNode(view.root, (node) => node.text.includes('@shared'))).toBeDefined();
    expect(findNode(view.root, (node) => node.text.includes('OPENAI_API_KEY'))).toBeDefined();

    view.state.query = 'postmark';
    view.state.tag = ' email ';
    view.state.owner = 'messag';
    await view.state.search();
    await settle();
    expect(invoke).toHaveBeenLastCalledWith('agent_discover_secrets', {
      request: {
        query: 'postmark',
        tag: 'email',
        owner: 'messag',
        limit: 200,
        redact_names: false,
      },
    });
    expect(findNode(view.root, (node) => node.text.includes('@shared'))).toBeDefined();
    expect(findNode(view.root, (node) => node.text.includes('POSTMARK_TOKEN'))).toBeDefined();
    expect(findNode(view.root, (node) => node.text.includes('OPENAI_API_KEY'))).toBeUndefined();
  } finally {
    view.unmount();
  }
});

it('renders aliases without metadata clipboard or identifying filters in privacy mode', async () => {
  vi.mocked(invoke).mockImplementation(createMockRuntime(new URLSearchParams()) as typeof invoke);
  const view = mountComponent(DiscoverSecrets, { privacyMode: true, knownProjectIds: [] });
  try {
    await settle();
    expect(invoke).toHaveBeenLastCalledWith('agent_discover_secrets', {
      request: { limit: 200, redact_names: true },
    });
    expect(findNode(view.root, (node) => node.text === 'Variable 1')).toBeDefined();
    expect(findNode(view.root, (node) => node.text.includes('DATABASE_URL'))).toBeUndefined();
    expect(findNode(view.root, (node) => node.text.includes('Copy ref'))).toBeUndefined();
    expect(findNode(view.root, (node) => node.tag === 'input')).toBeUndefined();
  } finally {
    view.unmount();
  }
});

it('marks the exact active environment and offers to switch to another in the same project', async () => {
  vi.mocked(invoke).mockImplementation(createMockRuntime(new URLSearchParams()) as typeof invoke);
  const onSwitchEnvironment = vi.fn();
  const view = mountComponent(DiscoverSecrets, {
    privacyMode: false,
    knownProjectIds: ['acme-api'],
    currentProjectId: 'acme-api',
    currentProfileId: 'acme-api-dev',
    onSwitchEnvironment,
  });
  try {
    await settle();
    const staging = findNode(view.root, (node) => node.text === 'Switch to staging');
    expect(staging?.parent?.tag).toBe('button');
    (staging?.parent?.props.onClick as () => void)();
    expect(onSwitchEnvironment).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ project_id: 'acme-api', profile_id: 'acme-api-staging' }),
    );
    const active = findNode(view.root, (node) => node.props.class === 'discovery__current');
    expect(active).toBeDefined();
    expect(
      findNode(
        staging!.parent!.parent!.parent!,
        (node) => node.props.class === 'discovery__current',
      ),
    ).toBeUndefined();
  } finally {
    view.unmount();
  }
});
