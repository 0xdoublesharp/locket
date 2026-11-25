import { afterEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import AgentUnavailableBanner from './AgentUnavailableBanner.vue';
import AppIcon from './AppIcon.vue';
import CopyReference from './CopyReference.vue';
import ProfileSwitcherModal from './ProfileSwitcherModal.vue';
import UnlockModal from './UnlockModal.vue';
import type { AppIconName } from '../types/views';
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

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

const mounts: ReturnType<typeof mountComponent>[] = [];
function mount(...args: Parameters<typeof mountComponent>) {
  const mounted = mountComponent(...args);
  mounts.push(mounted);
  return mounted;
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
  vi.resetAllMocks();
});

it('submits only the selected unlock method and clears the passphrase on error or cancellation', async () => {
  const onSubmit = vi.fn();
  const onDismiss = vi.fn();
  const { root, setProps } = mount(UnlockModal, {
    projectLabel: 'Fixture',
    busy: false,
    onSubmit,
    onDismiss,
  });
  await submit(root);
  expect(onSubmit).toHaveBeenCalledWith({ kind: 'os-keychain' });
  await check(control(root, 'Use a passphrase'));
  const passphrase = control(root, 'Passphrase');
  expect(passphrase.props.type).toBe('password');
  expect(button(root, 'Unlock with passphrase').props.disabled).toBe(true);
  await submit(root);
  expect(onSubmit).toHaveBeenCalledOnce();
  await input(passphrase, 'fixture-only-passphrase');
  await submit(root);
  expect(onSubmit).toHaveBeenLastCalledWith({
    kind: 'passphrase',
    passphrase: 'fixture-only-passphrase',
  });
  expect(passphrase.value).toBe('');
  await input(passphrase, 'fixture-retry');
  setProps({ errorMessage: 'Unlock rejected.' });
  await settle();
  expect(passphrase.value).toBe('');
  expect(nodeText(byProp(root, 'role', 'alert'))).toBe('Unlock rejected.');
  expect(nodeText(root)).not.toMatch(/fixture-only-passphrase|fixture-retry/);
  setProps({ busy: true });
  await settle();
  expect(button(root, 'Cancel').props.disabled).toBe(true);
  expect(button(root, 'Unlocking…').props.disabled).toBe(true);
  await submit(root);
  expect(onSubmit).toHaveBeenCalledTimes(2);
  setProps({ busy: false });
  await settle();
  await input(passphrase, 'fixture-cancel');
  await click(button(root, 'Cancel'));
  expect(onDismiss).toHaveBeenCalledOnce();
  expect(passphrase.value).toBe('');
});

it('requires an exact typed name for dangerous environment switching and resets on dismissal', async () => {
  const onSubmit = vi.fn();
  const onDismiss = vi.fn();
  const { root, setProps } = mount(ProfileSwitcherModal, {
    dangerous: true,
    currentProfile: 'dev',
    onSubmit,
    onDismiss,
  });
  const target = control(root, 'Target environment');
  const confirmation = control(root, 'Type the profile name');
  expect(nodeText(root)).toContain('Active: dev');
  expect(button(root, 'Switch').props.disabled).toBe(true);
  await input(target, 'prod');
  await input(confirmation, 'Prod');
  await submit(root);
  expect(onSubmit).not.toHaveBeenCalled();
  await input(confirmation, 'prod');
  await submit(root);
  expect(onSubmit).toHaveBeenLastCalledWith('prod', 'prod');
  await click(button(root, 'Cancel'));
  expect(target.value).toBe('');
  expect(confirmation.value).toBe('');
  expect(onDismiss).toHaveBeenCalledOnce();
  setProps({ dangerous: false, currentProfile: null });
  await settle();
  await input(target, 'dev');
  await submit(root);
  expect(onSubmit).toHaveBeenLastCalledWith('dev', undefined);
});

it('invalidates an in-flight clipboard result on reference change and reports only the current result', async () => {
  const oldCopy = deferred<void>();
  vi.mocked(invoke).mockReturnValueOnce(oldCopy.promise);
  const { root, setProps } = mount(CopyReference, { reference: 'lk://dev/FIRST' });
  await click(button(root, 'Copy ref'));
  expect(invoke).toHaveBeenLastCalledWith('desktop_copy_text_plain', { text: 'lk://dev/FIRST' });
  setProps({ reference: 'lk://dev/SECOND' });
  await settle();
  oldCopy.resolve();
  await settle();
  expect(nodeText(root)).not.toContain('Copied');
  vi.mocked(invoke).mockRejectedValueOnce({
    kind: 'protocol',
    reason: 'fixture-private-diagnostic',
  });
  await click(button(root, 'Copy ref'));
  expect(nodeText(root)).toContain('Could not copy reference.');
  expect(nodeText(root)).not.toContain('fixture-private-diagnostic');
  vi.mocked(invoke).mockResolvedValueOnce(undefined);
  await click(button(root, 'Copy ref'));
  expect(nodeText(root)).toContain('Copied lk://dev/SECOND');
  setProps({ reference: null });
  await settle();
  expect(findNode(root, (node) => node.tag === 'button')).toBeUndefined();
});

it('offers actionable agent recovery and suppresses duplicate actions while pending', async () => {
  const onStart = vi.fn();
  const onRetry = vi.fn();
  const { root, setProps } = mount(AgentUnavailableBanner, {
    error: {
      kind: 'unavailable',
      reason: 'fixture-socket-path',
      socket_path: '/fixture/sensitive',
      next_action: 'Retry',
      display_reason: 'Connection closed.',
    },
    canStart: true,
    onStart,
    onRetry,
  });
  expect(nodeText(root)).toContain('Locket agent unavailable');
  expect(nodeText(root)).not.toMatch(/sensitive|fixture-socket-path/);
  await click(button(root, 'Start agent'));
  expect(onStart).toHaveBeenCalledOnce();
  setProps({ starting: true });
  await settle();
  expect(button(root, 'Starting…').props.disabled).toBe(true);
  expect(button(root, 'Retry').props.disabled).toBe(true);
  setProps({ starting: false, retrying: true });
  await settle();
  expect(button(root, 'Retrying…').props.disabled).toBe(true);
  setProps({ retrying: false, canStart: false });
  await settle();
  expect(nodeText(root)).toContain('Check that the Locket agent is running');
  await click(button(root, 'Retry'));
  expect(onRetry).toHaveBeenCalledOnce();
  setProps({ error: { kind: 'rejected', code: 'PolicyDenied', next_action: 'Check access.' } });
  await settle();
  expect(nodeText(root)).toContain('Check access. PolicyDenied');
  setProps({
    error: { kind: 'protocol', reason: 'Invalid response.' },
    heading: 'Connection failed',
  });
  await settle();
  expect(nodeText(byProp(root, 'role', 'alert'))).toContain('Connection failed Invalid response.');
});

it('renders distinct, decorative artwork at default and requested sizes for the icon set', async () => {
  const icons: AppIconName[] = [
    'brand-lock',
    'lock',
    'unlock',
    'folder',
    'key',
    'terminal',
    'activity',
    'users',
    'settings',
    'search',
    'copy',
    'link',
    'eye',
    'clock',
    'fingerprint',
    'refresh',
    'info',
    'alert',
    'check',
    'plus',
    'cloud',
    'user',
    'laptop',
    'compass',
    'chevron-down',
    'x',
    'more',
  ];
  const { root, setProps } = mount(AppIcon, { name: icons[0] });
  const svg = byProp(root, 'viewBox', '0 0 24 24');
  expect(svg.props).toMatchObject({
    width: 16,
    height: 16,
    'aria-hidden': 'true',
    focusable: 'false',
  });
  const artwork = new Set<string>();
  for (const name of icons) {
    setProps({ name, size: 24 });
    await settle();
    expect(svg.props).toMatchObject({ width: 24, height: 24 });
    const shapes = svg.children.filter((node) => !node.tag.startsWith('#'));
    expect(shapes.length).toBeGreaterThan(0);
    artwork.add(JSON.stringify(shapes.map((node) => [node.tag, node.props])));
  }
  expect(artwork.size).toBe(icons.length);
});
