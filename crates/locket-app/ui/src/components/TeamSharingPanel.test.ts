import { afterEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import TeamSharingPanel from './TeamSharingPanel.vue';
import type { TeamSyncStatus } from '../team/sync';
import {
  button,
  byProp,
  check,
  click,
  control,
  deferred,
  input,
  mountComponent,
  nodeText,
  settle,
} from '../test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

const mounts: ReturnType<typeof mountComponent>[] = [];
function sharing(props: Record<string, unknown> = {}) {
  const view = mountComponent(TeamSharingPanel, { projectId: 'project-a', ...props });
  mounts.push(view);
  return view;
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
  vi.resetAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const checked: TeamSyncStatus = {
  state: 'ready',
  epoch: 3,
  waiting: 0,
  conflicts: 0,
  published: 0,
  applied: 1,
};
const blocked: TeamSyncStatus = {
  ...checked,
  conflicts: 1,
  waiting: 1,
  folder: '/fixture/shared-area',
  owner_fingerprint: 'fixture-owner',
  last_verified_at: 1_750_000_000_000_000_000,
  last_error: 'fixture-delivery-detail',
  pending_profiles: { consent: 'consent-required', rename: 'profile-conflict' },
  pending_details: [
    {
      profile_id: 'consent',
      profile_name: 'Production',
      reason: 'consent-required',
      colliding_profile: null,
      colliding_secrets: [],
    },
    {
      profile_id: 'rename',
      profile_name: 'Development',
      reason: 'profile-conflict',
      colliding_profile: { id: 'local-profile', name: 'Development' },
      colliding_secrets: [],
    },
    {
      profile_id: 'override',
      profile_name: 'Testing',
      reason: 'value-conflict',
      colliding_profile: null,
      colliding_secrets: [{ id: 'local-variable', name: 'FIXTURE_VARIABLE' }],
    },
    {
      profile_id: 'ready',
      profile_name: 'Staging',
      reason: 'retry',
      colliding_profile: null,
      colliding_secrets: [],
    },
  ],
};

it('keeps delivery identifiers and diagnostics out of privacy mode', async () => {
  vi.mocked(invoke).mockResolvedValue(blocked);
  const { root, setProps } = sharing();
  await settle();
  expect(invoke).toHaveBeenCalledWith('desktop_team_sync_status', {
    request: { project_id: 'project-a' },
  });
  expect(nodeText(root)).toContain('1 file');
  expect(nodeText(root)).toContain('/ fixture / shared-area');
  expect(nodeText(root)).toContain('fixture-owner');
  expect(nodeText(root)).toContain('fixture-delivery-detail');
  expect(nodeText(root)).toContain('The local collision has been resolved.');
  setProps({ privacyMode: true });
  await settle();
  expect(nodeText(root)).toContain('Delivery needs attention.');
  expect(nodeText(root)).not.toMatch(
    /shared-area|fixture-owner|fixture-delivery-detail|FIXTURE_VARIABLE|Set up this device/,
  );
  vi.mocked(invoke).mockRejectedValueOnce({
    kind: 'protocol',
    reason: 'fixture-sensitive-diagnostic',
  });
  await click(button(root, 'Check status'));
  expect(nodeText(root)).toContain('Team update check failed.');
  expect(nodeText(root)).not.toContain('fixture-sensitive-diagnostic');
});

it('configures delivery after confirmation and copies the verified owner join command', async () => {
  vi.mocked(invoke).mockResolvedValue(checked);
  const confirmDangerous = vi
    .fn()
    .mockResolvedValueOnce(undefined)
    .mockResolvedValueOnce(true)
    .mockResolvedValueOnce(false);
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  const { root } = sharing({ confirmDangerous });
  await settle();
  expect(button(root, 'Save folder and consent').props.disabled).toBe(true);
  await input(control(root, 'Shared folder'), '/fixture/team');
  await input(control(root, 'Independently verified owner fingerprint'), 'A'.repeat(64));
  const join = byProp(root, 'aria-label', 'Join verified team').value;
  expect(join).toBe(`locket team join --folder '/fixture/team' --owner '${'a'.repeat(64)}'`);
  await click(button(root, 'Copy Join verified team'));
  expect(writeText).toHaveBeenCalledWith(join);
  await check(control(root, 'Allow automatic delivery'));
  await click(button(root, 'Save folder and consent'));
  expect(invoke).toHaveBeenCalledTimes(1);
  await click(button(root, 'Save folder and consent'));
  expect(confirmDangerous).toHaveBeenCalledWith('Configure team sync');
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_configure', {
    request: {
      project_id: 'project-a',
      folder: '/fixture/team',
      allow_dangerous: true,
      confirm_dangerous: true,
    },
  });
  await click(button(root, 'Apply verified updates'));
  expect(confirmDangerous).toHaveBeenLastCalledWith('Sync team updates');
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_now', {
    request: { project_id: 'project-a' },
  });
});

it('reconciles profile and variable collisions with the authenticated IDs', async () => {
  vi.mocked(invoke).mockResolvedValue(blocked);
  const confirmDangerous = vi.fn().mockResolvedValue(true);
  const { root } = sharing({ confirmDangerous });
  await settle();
  expect(nodeText(root)).toContain('Values are held because this profile is dangerous');
  const rename = button(root, 'Rename local profile and retry');
  expect(rename.props.disabled).toBe(true);
  await input(control(root, 'New name for your local profile'), '  personal-dev  ');
  await click(rename);
  expect(confirmDangerous).toHaveBeenCalledWith('Reconcile team changes');
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_rename_profile', {
    request: {
      project_id: 'project-a',
      confirm_dangerous: true,
      incoming_profile_id: 'rename',
      local_profile_id: 'local-profile',
      new_name: 'personal-dev',
    },
  });
  vi.mocked(invoke).mockRejectedValueOnce({
    kind: 'protocol',
    reason: 'reconciliation unavailable',
  });
  await click(button(root, 'Keep as personal override and retry'));
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_preserve_override', {
    request: {
      project_id: 'project-a',
      confirm_dangerous: true,
      incoming_profile_id: 'override',
      local_secret_id: 'local-variable',
    },
  });
  expect(nodeText(root)).toContain('reconciliation unavailable');
});

it('refreshes on the timer and rejects responses from the previously selected project', async () => {
  vi.useFakeTimers();
  const staleStatus = deferred<TeamSyncStatus>();
  vi.mocked(invoke)
    .mockReturnValueOnce(staleStatus.promise)
    .mockResolvedValue({
      ...checked,
      epoch: 9,
      state: 'fork',
      waiting_known: true,
      pending_profiles: { incoming: 'collision' },
    });
  const { root, setProps, unmount } = sharing();
  expect(button(root, 'Check status').props.disabled).toBe(true);
  setProps({ projectId: 'project-b' });
  await settle();
  expect(nodeText(root)).toContain('Stopped: conflicting update history');
  expect(nodeText(root)).toContain('0 files');
  expect(nodeText(root)).toContain('locket team sync pending');
  staleStatus.resolve(blocked);
  await settle();
  expect(nodeText(root)).toContain('#9');
  expect(nodeText(root)).not.toContain('fixture-owner');
  await vi.advanceTimersByTimeAsync(30_000);
  expect(invoke).toHaveBeenCalledTimes(3);
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_status', {
    request: { project_id: 'project-b' },
  });
  unmount();
  await vi.advanceTimersByTimeAsync(30_000);
  expect(invoke).toHaveBeenCalledTimes(3);
});
