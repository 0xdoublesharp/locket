import { expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { findNode, mountComponent, settle } from '../test/renderer';
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
      text: expect.stringContaining('locket env scan --json'),
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
