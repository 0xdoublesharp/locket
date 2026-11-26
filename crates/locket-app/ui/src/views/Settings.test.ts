import { expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import {
  button,
  byProp,
  check,
  click,
  control,
  deferred,
  findNode,
  input,
  mountComponent,
  nodeText,
  settle,
  submit,
} from '../test/renderer';
import Settings from './Settings.vue';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

it('emits a partial wire patch when a vault duration preset is selected', () => {
  const update = vi.fn();
  const view = mountComponent(Settings, {
    state: { privacyRedactNames: false, unlockTtlSeconds: 900, agentVersion: 'fixture' },
    loading: false,
    canEditVault: true,
    projectConnected: true,
    errorMessage: null,
    onUpdate: update,
  });
  try {
    const preset = findNode(view.root, (node) => node.tag === 'button' && node.text === '4h');
    expect(preset).toBeDefined();
    (preset?.props.onClick as (() => void) | undefined)?.();
    expect(update).toHaveBeenCalledWith({ agent_unlock_ttl: '4h' });
  } finally {
    view.unmount();
  }
});

it('patches verification independently and preserves the other gates', () => {
  const onUpdate = vi.fn();
  const view = mountComponent(Settings, {
    state: {
      privacyRedactNames: false,
      unlockTtl: '1h',
      verification: { reveal: false, unlock: true, copy: true },
      agentVersion: 'fixture',
    },
    loading: false,
    canEditVault: true,
    projectConnected: true,
    errorMessage: null,
    onUpdate,
  });
  try {
    const label = findNode(
      view.root,
      (node) =>
        node.tag === 'label' && node.children.some((child) => child.text === 'Reveal a value'),
    );
    const toggle = label?.children.find((node) => node.tag === 'input');
    expect(toggle).toBeDefined();
    toggle!.checked = true;
    (toggle!.props.onChange as (event: { target: unknown }) => void)({ target: toggle });
    expect(onUpdate).toHaveBeenCalledWith({ user_verification_required_for: { reveal: true } });
  } finally {
    view.unmount();
  }
});

it('copies the native MCP JSON and the command for each selected client', async () => {
  const command = '/Applications/Locket Dev.app/locket';
  const args = ['mcp'];
  const json = JSON.stringify({ mcpServers: { locket: { command, args } } }, null, 2);
  vi.mocked(invoke)
    .mockResolvedValueOnce(false)
    .mockResolvedValueOnce({ command, args, json })
    .mockResolvedValue(undefined);
  const view = mountComponent(Settings, {
    state: { privacyRedactNames: false, agentVersion: 'fixture' },
    loading: false,
    canEditVault: true,
    projectConnected: true,
    errorMessage: null,
  });
  try {
    await settle();
    const click = async (label: string, byAriaLabel = false) => {
      const button = findNode(
        view.root,
        (node) =>
          node.tag === 'button' &&
          (byAriaLabel
            ? node.props['aria-label'] === label
            : node.text === label || node.children.some((child) => child.text.trim() === label)),
      );
      expect(button).toBeDefined();
      await (button!.props.onClick as () => void | Promise<void>)();
      await settle();
    };
    expect(findNode(view.root, (node) => node.tag === 'pre')).toBeDefined();
    await click('Copy MCP JSON', true);
    expect(invoke).toHaveBeenLastCalledWith('desktop_copy_text_plain', { text: json });
    for (const [label, program] of [
      ['Claude Code', 'claude'],
      ['Codex CLI', 'codex'],
    ] as const) {
      await click(label);
      const text = `${program} mcp add locket -- '${command}' mcp`;
      const snippet = findNode(view.root, (node) => node.tag === 'code' && node.text === text);
      expect(snippet).toBeDefined();
      await click(`Copy ${label} command`, true);
      expect(invoke).toHaveBeenLastCalledWith('desktop_copy_text_plain', { text });
    }
    await click('Copy agent prompt');
    expect(invoke).toHaveBeenLastCalledWith('desktop_copy_text_plain', {
      text: expect.stringContaining('locket env scan --remaining --json'),
    });
    expect(
      findNode(
        view.root,
        (node) => node.props.role === 'status' && node.text === 'Copied agent prompt.',
      ),
    ).toBeDefined();
  } finally {
    view.unmount();
    vi.mocked(invoke).mockReset();
  }
});

it('validates custom durations and persists the desktop login toggle with pending and failure feedback', async () => {
  const onUpdate = vi.fn();
  const launchRequest = deferred<boolean>();
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'desktop_get_launch_at_login') return false;
    if (command === 'desktop_set_launch_at_login') return launchRequest.promise;
    return undefined;
  });
  const state = {
    privacyRedactNames: false,
    unlockTtlSeconds: 900,
    unlockTtl: '15m',
    agentVersion: 'fixture',
    verification: null,
    dangerousProfile: { profile_name: 'dev', profile_label: 'dev', dangerous: false },
    dangerousProfileFlag: false,
  };
  const view = mountComponent(Settings, {
    state,
    loading: true,
    canEditVault: true,
    projectConnected: true,
    errorMessage: null,
    onUpdate,
  });
  const { root, setProps } = view;
  try {
    expect(nodeText(root)).toContain('Syncing settings');
    expect(button(root, '15m').props.disabled).toBe(true);
    setProps({ loading: false });
    await settle();
    const duration = control(root, 'Custom duration');
    await input(duration, '9h');
    await submit(root);
    expect(nodeText(root)).toContain('Enter a duration between 1s and 8h');
    expect(duration.props['aria-invalid']).toBe('true');
    expect(onUpdate).not.toHaveBeenCalled();
    await input(duration, ' 45m ');
    await submit(root);
    expect(onUpdate).toHaveBeenLastCalledWith({ agent_unlock_ttl: '45m' });
    setProps({
      state: { ...state, unlockTtl: '1h', dangerousProfileFlag: true },
      saveMessage: 'Saved.',
    });
    await settle();
    expect(duration.value).toBe('1h');
    expect(nodeText(root)).toContain('Saved.');
    await check(control(root, 'Mark dev as dangerous'), false);
    expect(onUpdate).toHaveBeenLastCalledWith({ dangerous_profile: false });

    const launch = control(root, 'Launch at login');
    await check(launch);
    expect(launch.checked).toBe(false);
    expect(launch.props.disabled).toBe(true);
    expect(invoke).toHaveBeenCalledWith('desktop_set_launch_at_login', { enabled: true });
    launchRequest.resolve(true);
    await settle();
    expect(nodeText(root)).toContain('Launch at login enabled.');
    vi.mocked(invoke).mockRejectedValueOnce('Permission rejected');
    await check(launch, false);
    expect(nodeText(root)).toContain('Could not update launch at login.');
    expect(launch.checked).toBe(true);
    vi.mocked(invoke).mockResolvedValueOnce(false);
    await check(launch, false);
    expect(nodeText(root)).toContain('Launch at login disabled.');
    setProps({ canEditVault: false, saveMessage: null });
    await settle();
    expect(nodeText(root)).toContain('Unlock this project to edit vault settings.');
    setProps({ projectConnected: false });
    await settle();
    expect(nodeText(root)).toContain('Connect a project to edit vault settings.');
  } finally {
    view.unmount();
    vi.mocked(invoke).mockReset();
  }
});

it('moves between MCP tabs with the keyboard and drops stale copy feedback', async () => {
  const staleCopy = deferred<void>();
  vi.mocked(invoke)
    .mockResolvedValueOnce(false)
    .mockResolvedValueOnce(undefined)
    .mockReturnValueOnce(staleCopy.promise);
  const view = mountComponent(Settings, {
    state: { privacyRedactNames: false, agentVersion: 'fixture' },
    loading: false,
    canEditVault: false,
    projectConnected: false,
    errorMessage: 'Read failed.',
  });
  const { root } = view;
  try {
    await settle();
    expect(nodeText(root)).toContain('Read failed.');
    const tablist = byProp(root, 'role', 'tablist');
    const focus = vi.fn();
    Object.assign(tablist, {
      querySelector: (selector: string) => {
        const tab = byProp(tablist, 'id', selector.slice(1));
        return { focus: () => focus(tab.props.id) };
      },
    });
    await click(button(root, 'Copy MCP JSON'));
    const key = async (value: string) => {
      const event = Object.assign(new Event('keydown', { cancelable: true }), { key: value });
      tablist.dispatchEvent(event);
      await settle();
      return event;
    };
    await key('ArrowLeft');
    expect(focus).toHaveBeenLastCalledWith('settings-mcp-tab-codex');
    expect(byProp(root, 'id', 'settings-mcp-tab-codex').props['aria-selected']).toBe(true);
    staleCopy.resolve();
    await settle();
    expect(nodeText(root)).not.toContain('Copied MCP JSON.');
    await key('ArrowRight');
    expect(focus).toHaveBeenLastCalledWith('settings-mcp-tab-json');
    await key('End');
    expect(focus).toHaveBeenLastCalledWith('settings-mcp-tab-codex');
    await key('Home');
    expect(focus).toHaveBeenLastCalledWith('settings-mcp-tab-json');
    expect((await key('Tab')).defaultPrevented).toBe(false);
    vi.mocked(invoke).mockRejectedValueOnce('fixture-diagnostic');
    await click(button(root, 'Copy MCP JSON'));
    expect(nodeText(root)).toContain('Could not copy MCP JSON.');
    expect(nodeText(root)).not.toContain('fixture-diagnostic');
  } finally {
    view.unmount();
    vi.mocked(invoke).mockReset();
  }
});
