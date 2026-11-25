import { expect, it, vi } from 'vitest';
import ProfileSwitcherView from './ProfileSwitcherView.vue';
import {
  button,
  byProp,
  check,
  click,
  control,
  input,
  mountComponent,
  nodeText,
  settle,
  submit,
} from '../test/renderer';

it('applies selected dangerous flags, requires the typed target, and hides tracked names in privacy mode', async () => {
  const onSwitch = vi.fn();
  const onSelect = vi.fn();
  const view = mountComponent(ProfileSwitcherView, {
    state: {
      activeProfile: 'dev',
      activeDangerous: false,
      recentTargets: [],
      knownProfiles: [{ name: 'prod', dangerous: true }],
    },
    privacyMode: false,
    switching: false,
    onSwitch,
    onSelect,
    lastSwitchedAt: '2026-06-26T12:00:00Z',
  });
  const { root, setProps } = view;
  try {
    expect(nodeText(root)).toContain('Last switch:');
    expect(byProp(root, 'data-testid', 'profile-entry-dev').props['aria-current']).toBe('true');
    await click(byProp(root, 'data-testid', 'profile-entry-prod'));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith({ name: 'prod', dangerous: true });
    const switchForm = byProp(root, 'data-testid', 'profile-switcher-form');
    const target = control(switchForm, 'Target environment name');
    const dangerous = control(switchForm, 'Target environment is flagged dangerous');
    expect(target.value).toBe('prod');
    expect(dangerous.props.disabled).toBe(true);
    const confirmation = control(switchForm, 'Type the target environment name');
    await input(confirmation, 'Prod');
    await submit(switchForm);
    expect(onSwitch).not.toHaveBeenCalled();
    await input(confirmation, ' prod ');
    await submit(switchForm);
    expect(onSwitch).toHaveBeenLastCalledWith({
      profileName: 'prod',
      confirmation: 'prod',
      dangerous: true,
    });
    setProps({ switching: true, errorMessage: 'Switch failed.' });
    await settle();
    expect(button(switchForm, 'Switching...').props.disabled).toBe(true);
    expect(nodeText(switchForm)).toContain('Switch failed.');
    setProps({ switching: false, privacyMode: true });
    await settle();
    expect(nodeText(byProp(root, 'data-testid', 'profile-list'))).toBe(
      'active environment active environment dangerous',
    );

    await input(target, 'Invalid name');
    expect(nodeText(switchForm)).toContain('Name may contain letters');
    await input(target, 'qa');
    await check(dangerous, false);
    await submit(switchForm);
    expect(onSwitch).toHaveBeenLastCalledWith({
      profileName: 'qa',
      confirmation: undefined,
      dangerous: false,
    });
  } finally {
    view.unmount();
  }
});

it('validates creation, keeps input during failure, and clears it only after a save notice', async () => {
  const onCreate = vi.fn();
  const view = mountComponent(ProfileSwitcherView, {
    state: { activeProfile: null, activeDangerous: false, recentTargets: [] },
    privacyMode: false,
    switching: false,
    canCreate: true,
    creating: false,
    onCreate,
  });
  const { root, setProps } = view;
  try {
    expect(nodeText(root)).toContain('No environments tracked yet.');
    const form = byProp(root, 'data-testid', 'profile-create-form');
    const name = control(form, 'Environment name');
    await input(name, 'bad/name');
    await submit(form);
    expect(nodeText(form)).toContain('Use 1–128 letters');
    expect(onCreate).not.toHaveBeenCalled();
    await input(name, ' qa ');
    await submit(form);
    expect(onCreate).toHaveBeenCalledExactlyOnceWith('qa');
    setProps({ creating: true });
    await settle();
    expect(button(form, 'Creating…').props.disabled).toBe(true);
    expect(name.props.disabled).toBe(true);
    setProps({ creating: false, createError: 'Already exists.' });
    await settle();
    expect(nodeText(form)).toContain('Already exists.');
    expect(name.value).toBe(' qa ');
    setProps({ createError: null, createNotice: 'Created environment qa.' });
    await settle();
    expect(name.value).toBe('');
    expect(nodeText(form)).toContain('Created environment qa.');
  } finally {
    view.unmount();
  }
});
