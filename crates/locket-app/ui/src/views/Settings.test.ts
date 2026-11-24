import { expect, it, vi } from 'vitest';
import { findNode, mountComponent } from '../test/renderer';
import Settings from './Settings.vue';

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
