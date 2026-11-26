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
  select,
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

it('tests and saves S3 settings, then retests the saved backend without resending credentials', async () => {
  const saved = {
    ...checked,
    transport_kind: 's3',
    remote_target: 's3://fixture-bucket/team',
    remote_endpoint: 'https://r2.fixture.test',
    remote_region: 'auto',
    credential_mode: 'vault',
  };
  const test = {
    ok: true,
    transport_kind: 's3',
    target: saved.remote_target,
    package_count: 3,
    writable_checked: false,
    message: 'Connection succeeded.',
  };
  vi.mocked(invoke)
    .mockResolvedValueOnce(checked)
    .mockResolvedValueOnce(test)
    .mockResolvedValueOnce(saved)
    .mockResolvedValueOnce(test);
  const confirmDangerous = vi.fn().mockResolvedValue('dev');
  const { root, setProps } = sharing({ confirmDangerous });
  await settle();
  await click(button(root, 'S3 / R2 / MinIO'));
  await input(control(root, 'Bucket'), 'fixture-bucket');
  const region = control(root, 'Region');
  expect(region.value).toBe('us-east-1');
  await input(region, 'auto');
  await input(control(root, 'Key prefix'), 'team');
  await input(control(root, 'Custom endpoint URL'), saved.remote_endpoint);
  await check(control(root, 'Path-style URLs'));
  await input(control(root, 'Access Key ID'), 'fixture-key-id');
  const secret = control(root, 'Secret Access Key');
  const token = control(root, 'Session Token');
  await input(secret, 'fixture-secret-key');
  await input(token, 'fixture-session-token');
  expect(secret.props.type).toBe('password');
  expect(token.props.type).toBe('password');
  await click(button(root, 'Show secret access key'));
  expect(secret.props.type).toBe('text');
  await click(button(root, 'Hide secret access key'));
  expect(secret.props.type).toBe('password');
  await input(control(root, 'Independently verified owner fingerprint'), 'A'.repeat(64));
  expect(nodeText(root)).not.toContain('Join verified team');
  const request = {
    project_id: 'project-a',
    confirm_dangerous_profile: 'dev',
    transport: {
      kind: 's3',
      bucket: 'fixture-bucket',
      region: 'auto',
      prefix: 'team',
      endpoint: saved.remote_endpoint,
      path_style: true,
      credential_mode: 'vault',
      access_key_id: 'fixture-key-id',
      secret_access_key: 'fixture-secret-key',
      session_token: 'fixture-session-token',
    },
  };
  await click(button(root, 'Test connection'));
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_test_remote', { request });
  expect(nodeText(root)).toContain('Connected · 3 encrypted packages found');
  await check(control(root, 'Allow automatic delivery'));
  await click(button(root, 'Save delivery backend & consent'));
  expect(confirmDangerous).toHaveBeenLastCalledWith('Configure team sync', true);
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_configure', {
    request: { ...request, allow_dangerous: true },
  });
  expect(secret.value).toBe('');
  expect(token.value).toBe('');
  expect(nodeText(root)).toContain('Remote storage cannot prove');
  expect(nodeText(root)).toContain('Delivery backend S3 s3://fixture-bucket/team');
  expect(nodeText(root)).toContain('Vault encrypted');
  expect(nodeText(root)).toContain(saved.remote_endpoint);
  expect(byProp(root, 'aria-label', 'Join verified team').value).toBe(
    `locket team join --remote --owner '${'a'.repeat(64)}'`,
  );
  await click(button(root, 'Test connection'));
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_test_remote', {
    request: { project_id: 'project-a', confirm_dangerous_profile: 'dev' },
  });
  setProps({ privacyMode: true });
  await settle();
  expect(nodeText(root)).toContain('Connection test passed.');
  expect(nodeText(root)).not.toMatch(
    /fixture-bucket|r2\.fixture\.test|3 encrypted packages|Vault encrypted/,
  );
});

it('redacts WebDAV diagnostics in privacy mode and clears credentials when switching backends or projects', async () => {
  const test = deferred<unknown>();
  vi.mocked(invoke).mockResolvedValueOnce(checked).mockReturnValueOnce(test.promise);
  const { root, setProps } = sharing();
  await settle();
  await click(button(root, 'WebDAV'));
  await input(control(root, 'HTTPS URL'), 'https://dav.fixture.test/team');
  await select(control(root, 'Auth type', 'select'), 'basic');
  await input(control(root, 'Username'), 'fixture-user');
  await input(control(root, 'Password'), 'fixture-password');
  await click(button(root, 'Shared folder'));
  await click(button(root, 'WebDAV'));
  expect(control(root, 'Password').value).toBe('');
  await select(control(root, 'Auth type', 'select'), 'bearer');
  await input(control(root, 'Bearer token'), 'fixture-bearer');
  await click(button(root, 'Test connection'));
  setProps({ privacyMode: true });
  await settle();
  test.resolve({
    ok: false,
    transport_kind: 'webdav',
    target: 'https://dav.fixture.test/team',
    package_count: 0,
    writable_checked: false,
    message: 'Access denied at dav.fixture.test for fixture-bearer',
  });
  await settle();
  expect(nodeText(root)).toContain('Connection test failed.');
  expect(nodeText(root)).not.toMatch(/dav\.fixture\.test|fixture-bearer|Access denied/);
  setProps({ privacyMode: false });
  await settle();
  expect(nodeText(root)).toContain('Access denied at dav.fixture.test');
  expect(nodeText(root)).not.toContain('fixture-bearer');
  expect(control(root, 'Bearer token').value).toBe('');
  await input(control(root, 'Bearer token'), 'fixture-unsaved');
  vi.mocked(invoke).mockResolvedValueOnce(checked);
  setProps({ projectId: 'project-b' });
  await settle();
  await click(button(root, 'WebDAV'));
  await select(control(root, 'Auth type', 'select'), 'bearer');
  expect(control(root, 'Bearer token').value).toBe('');
  expect(control(root, 'HTTPS URL').value).toBe('');
  expect(nodeText(root)).not.toContain('Access denied');
});

it('configures delivery after confirmation and copies the verified owner join command', async () => {
  vi.mocked(invoke).mockResolvedValue(checked);
  const confirmDangerous = vi
    .fn()
    .mockResolvedValueOnce(undefined)
    .mockResolvedValueOnce('dev')
    .mockResolvedValueOnce(false);
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  const { root } = sharing({ confirmDangerous });
  await settle();
  expect(button(root, 'Save delivery backend & consent').props.disabled).toBe(true);
  await input(control(root, 'Shared folder'), '/fixture/team');
  await input(control(root, 'Independently verified owner fingerprint'), 'A'.repeat(64));
  const join = byProp(root, 'aria-label', 'Join verified team').value;
  expect(join).toBe(`locket team join --folder '/fixture/team' --owner '${'a'.repeat(64)}'`);
  await click(button(root, 'Copy Join verified team'));
  expect(writeText).toHaveBeenCalledWith(join);
  await check(control(root, 'Allow automatic delivery'));
  await click(button(root, 'Save delivery backend & consent'));
  expect(invoke).toHaveBeenCalledTimes(1);
  await click(button(root, 'Save delivery backend & consent'));
  expect(confirmDangerous).toHaveBeenCalledWith('Configure team sync', true);
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_configure', {
    request: {
      project_id: 'project-a',
      folder: '/fixture/team',
      allow_dangerous: true,
      confirm_dangerous_profile: 'dev',
    },
  });
  await click(button(root, 'Apply verified updates'));
  expect(confirmDangerous).toHaveBeenLastCalledWith('Sync team updates');
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_now', {
    request: { project_id: 'project-a' },
  });
});

it.each([1, 3])(
  'publishes as the owner and redacts the package count in privacy mode (%i)',
  async (published) => {
    const owner = { ...checked, state: 'owner', folder: '/fixture/team' };
    vi.mocked(invoke)
      .mockResolvedValueOnce(owner)
      .mockResolvedValueOnce({ ...owner, published });
    const { root, setProps } = sharing();
    await settle();
    const publish = button(root, 'Publish updates now');
    expect(publish.props.class).toContain('companion-button--primary');
    expect(nodeText(root)).not.toContain('Apply verified updates');
    await click(publish);
    expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_now', {
      request: { project_id: 'project-a' },
    });
    const notice = `Published ${published} encrypted ${published === 1 ? 'package' : 'packages'}.`;
    expect(nodeText(root)).toContain(notice);
    setProps({ privacyMode: true });
    await settle();
    expect(nodeText(root)).toContain('Published team updates.');
    expect(nodeText(root)).not.toContain(notice);
    expect(nodeText(root)).not.toContain('Disconnect backend');
  },
);

it('disconnects a remote backend after confirmation and clears draft credentials and connection feedback', async () => {
  const trust = { ...checked, owner_fingerprint: 'fixture-owner' };
  const saved = { ...trust, transport_kind: 's3', remote_target: 's3://fixture-bucket/team' };
  vi.mocked(invoke)
    .mockResolvedValueOnce(saved)
    .mockResolvedValueOnce({ ok: true, package_count: 2 })
    .mockResolvedValueOnce(trust);
  const confirmDangerous = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce('dev');
  const { root } = sharing({ confirmDangerous });
  await settle();
  await input(control(root, 'Bucket'), 'fixture-bucket');
  const accessKey = control(root, 'Access Key ID');
  const secret = control(root, 'Secret Access Key');
  const token = control(root, 'Session Token');
  await input(accessKey, 'fixture-key');
  await input(secret, 'fixture-secret');
  await input(token, 'fixture-token');
  await click(button(root, 'Show secret access key'));
  await click(button(root, 'Test connection'));
  expect(nodeText(root)).toContain('Connected · 2 encrypted packages found');
  await click(button(root, 'Disconnect backend'));
  expect(confirmDangerous).toHaveBeenLastCalledWith('Disconnect team sync backend');
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_clear', {
    request: { project_id: 'project-a', confirm_dangerous_profile: 'dev' },
  });
  for (const credential of [accessKey, secret, token]) expect(credential.value).toBe('');
  expect(secret.props.type).toBe('password');
  expect(nodeText(root)).toContain(
    'Delivery disconnected. Authenticated trust history was preserved.',
  );
  expect(nodeText(root)).toContain('fixture-owner');
  expect(nodeText(root)).not.toMatch(/Disconnect backend|Connected ·|s3:\/\/fixture-bucket/);
});

it('keeps a shared folder connected if confirmation is canceled or privacy mode turns on', async () => {
  vi.mocked(invoke).mockResolvedValue({ ...checked, folder: '/fixture/team' });
  const confirmation = deferred<string>();
  const confirmDangerous = vi
    .fn()
    .mockResolvedValueOnce(undefined)
    .mockReturnValueOnce(confirmation.promise);
  const { root, setProps } = sharing({ confirmDangerous });
  await settle();
  await click(button(root, 'Disconnect backend'));
  expect(invoke).toHaveBeenCalledTimes(1);
  expect(nodeText(root)).toContain('Delivery folder');
  await click(button(root, 'Disconnect backend'));
  setProps({ privacyMode: true });
  await settle();
  confirmation.resolve('dev');
  await settle();
  expect(invoke).toHaveBeenCalledTimes(1);
  expect(nodeText(root)).not.toMatch(/Disconnect backend|Delivery folder/);
  setProps({ privacyMode: false });
  await settle();
  expect(nodeText(root)).toContain('Disconnect backend');
});

it('reconciles profile and variable collisions with the authenticated IDs', async () => {
  vi.mocked(invoke).mockResolvedValue(blocked);
  const confirmDangerous = vi.fn().mockResolvedValue('dev');
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
      confirm_dangerous_profile: 'dev',
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
      confirm_dangerous_profile: 'dev',
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
