import { describe, expect, it } from 'vitest';
import type { DesktopProjectContext, DetectedCommandRow } from '../agent/types';
import { createMockRuntime } from './mockRuntime';

describe('desktop preview actions', () => {
  it('creates an environment, copies the selected source, and deletes the original', async () => {
    const invoke = createMockRuntime(new URLSearchParams({ state: 'locked' }));
    const request = (command: string, payload: Record<string, unknown>) =>
      invoke(command, { request: payload });
    const [shared, project] = (await invoke(
      'desktop_list_projects',
      {},
    )) as DesktopProjectContext[];
    const projectId = project!.project_id;
    await request('agent_unlock', { project_id: projectId, ttl_seconds: 900 });
    const created = (await request('desktop_create_profile', {
      project_id: projectId,
      profile_name: 'qa',
    })) as { profile_id: string };
    await expect(request('agent_list_projects', {})).resolves.toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          project_id: projectId,
          profiles: expect.arrayContaining([
            { id: created.profile_id, name: 'qa', dangerous: false },
          ]),
        }),
      ]),
    );
    await request('agent_set_active_profile', { project_id: projectId, profile_name: 'qa' });
    const source = {
      project_id: projectId,
      profile_id: created.profile_id,
      secret_name: 'TOKEN',
      source: 'machine-local',
    };
    await request('agent_set_secret', { ...source, value: 'preview fixture' });
    const copy = {
      from_project_id: projectId,
      from_profile_id: created.profile_id,
      secret_name: source.secret_name,
      source: source.source,
    };
    await expect(request('desktop_copy_secret_to_shared', copy)).rejects.toMatchObject({
      code: 'UnlockRequired',
      message: expect.stringContaining('Global Vault'),
    });
    await invoke('desktop_open_shared_vault', {});
    await request('agent_unlock', { project_id: shared!.project_id, ttl_seconds: 900 });
    await request('desktop_open_project', { path: project!.root });
    await expect(request('desktop_copy_secret_to_shared', copy)).resolves.toEqual({
      target_project_id: shared!.project_id,
      target_profile_id: shared!.profile_id,
      secret_name: source.secret_name,
      version: 1,
      action: 'create',
    });
    await expect(request('desktop_copy_secret_to_shared', copy)).rejects.toMatchObject({
      code: 'SecretAlreadyExists',
    });
    await expect(request('desktop_delete_secret', source)).resolves.toMatchObject({
      deleted: true,
    });
    await expect(
      request('agent_list_secrets', { project_id: projectId, profile_id: created.profile_id }),
    ).resolves.toEqual({ rows: [] });
    await invoke('desktop_open_shared_vault', {});
    await expect(
      request('agent_reveal', { profile_id: shared!.profile_id, secret_name: source.secret_name }),
    ).resolves.toMatchObject({ value: 'preview fixture' });
  });

  it('updates detection when a suggestion is saved as a policy', async () => {
    const invoke = createMockRuntime(new URLSearchParams());
    const detect = () => invoke('desktop_detect_commands', { request: { project_id: 'acme-api' } });
    expect(
      ((await detect()) as DetectedCommandRow[]).map(({ name, already_configured }) => [
        name,
        already_configured,
      ]),
    ).toEqual([
      ['dev', true],
      ['test', false],
      ['lint', false],
      ['build', false],
    ]);
    await invoke('desktop_save_policy', {
      request: {
        project_id: 'acme-api',
        mode: 'create',
        original_name: 'lint',
        policy: { name: 'lint', command_kind: 'argv', command_preview: 'pnpm run lint' },
      },
    });
    expect(
      ((await detect()) as DetectedCommandRow[]).find(({ name }) => name === 'lint'),
    ).toMatchObject({ already_configured: true });
  });
});

it('recovers a disconnected preview agent and supports a fresh project and Global Vault', async () => {
  const disconnected = createMockRuntime(new URLSearchParams({ state: 'error' }));
  await expect(disconnected('agent_status', {})).rejects.toMatchObject({
    code: 'AgentUnavailable',
  });
  await disconnected('desktop_start_agent', {});
  await expect(disconnected('agent_status', {})).resolves.toMatchObject({ lock_state: 'unlocked' });

  const invoke = createMockRuntime(new URLSearchParams({ state: 'welcome' }));
  const request = (command: string, payload: Record<string, unknown>) =>
    invoke(command, { request: payload });
  await expect(invoke('desktop_list_projects', {})).resolves.toEqual([]);
  await expect(invoke('agent_verify_bundle', {})).rejects.toMatchObject({
    code: 'ProjectNotFound',
  });
  await expect(request('desktop_open_project', { path: '/fixture/new' })).rejects.toMatchObject({
    code: 'ProjectNotFound',
  });
  const project = (await request('desktop_initialize_project', {
    path: '/fixture/new',
  })) as DesktopProjectContext;
  expect(project).toMatchObject({ root: '/fixture/new', project_name: 'new', profile_name: 'dev' });
  const copy = {
    from_project_id: project.project_id,
    from_profile_id: project.profile_id,
    secret_name: 'ABSENT',
  };
  await expect(request('desktop_copy_secret_to_shared', copy)).rejects.toMatchObject({
    code: 'UnlockRequired',
  });
  await request('agent_unlock', { project_id: project.project_id, ttl_seconds: 900 });
  await expect(request('desktop_copy_secret_to_shared', copy)).rejects.toMatchObject({
    code: 'ProjectNotFound',
  });
  const shared = (await invoke('desktop_open_shared_vault', {})) as DesktopProjectContext;
  expect(shared).toMatchObject({ is_shared: true, project_name: '@shared' });
  expect(await invoke('desktop_open_shared_vault', {})).toEqual(shared);
  await request('agent_unlock', { project_id: shared.project_id, ttl_seconds: 900 });
  await request('desktop_open_project', { path: project.root });
  await expect(request('desktop_copy_secret_to_shared', copy)).rejects.toMatchObject({
    code: 'SecretNotFound',
  });
  await expect(
    request('desktop_delete_secret', {
      project_id: project.project_id,
      profile_id: project.profile_id,
      secret_name: 'ABSENT',
      source: 'user-local',
    }),
  ).rejects.toMatchObject({ code: 'SecretNotFound' });
  await expect(
    request('desktop_create_profile', { project_id: project.project_id, profile_name: 'dev' }),
  ).rejects.toMatchObject({ code: 'SecretAlreadyExists' });
  await expect(
    request('agent_set_active_profile', {
      project_id: project.project_id,
      profile_name: 'missing',
    }),
  ).rejects.toMatchObject({ code: 'ProfileNotFound' });
});

it('checks dangerous confirmation in preview and filters discovery by glob and source without disclosing metadata', async () => {
  const invoke = createMockRuntime(new URLSearchParams());
  const request = (command: string, payload: Record<string, unknown>) =>
    invoke(command, { request: payload });
  const prod = { project_id: 'acme-api', profile_name: 'prod' };
  await expect(request('agent_set_active_profile', prod)).rejects.toMatchObject({
    code: 'DangerousProfileConfirmationRequired',
  });
  await expect(
    request('agent_set_active_profile', { ...prod, confirmation: 'prod' }),
  ).resolves.toMatchObject({ profile_name: 'prod', dangerous: true });
  await request('agent_unlock', { project_id: 'acme-api', ttl_seconds: 900 });
  const access = { project_id: 'acme-api', profile_id: 'acme-api-prod', secret_name: 'TOKEN' };
  for (const confirm_dangerous_profile of [undefined, '', 'PROD', 'prod ']) {
    await expect(
      request('agent_copy_secret', { ...access, confirm_dangerous_profile }),
    ).rejects.toMatchObject({ code: 'ConfirmationFailed' });
  }
  await expect(
    request('agent_copy_secret', { ...access, confirm_dangerous_profile: 'prod' }),
  ).resolves.toMatchObject({ kind: 'unsupported' });
  const remove = {
    project_id: 'acme-api',
    profile_id: 'acme-api-prod',
    secret_name: 'STRIPE_SECRET_KEY',
    source: 'team-managed',
  };
  await expect(request('desktop_delete_secret', remove)).rejects.toMatchObject({
    code: 'DangerousProfileConfirmationRequired',
  });
  await expect(
    request('agent_discover_secrets', {
      name_glob: 'stripe*key',
      project: 'acme-api',
      profile: 'prod',
      source: 'team-managed',
      redact_names: false,
    }),
  ).resolves.toEqual([expect.objectContaining({ name: 'STRIPE_SECRET_KEY', owner: 'Payments' })]);
  const redacted = await request('agent_discover_secrets', {
    name_glob: 'stripe?secret*',
    limit: 1,
    redact_names: true,
  });
  expect(redacted).toEqual([
    expect.objectContaining({
      name: expect.stringMatching(/^Variable \d+$/),
      owner: null,
      tags: [],
      trusted_roots: ['Project folder'],
    }),
  ]);
  expect(JSON.stringify(redacted)).not.toMatch(/STRIPE_SECRET_KEY|Payments|billing/);
  await expect(
    request('agent_discover_secrets', { name_glob: 'stripe[secret]*', redact_names: false }),
  ).resolves.toEqual([]);
  await expect(
    request('desktop_delete_secret', { ...remove, confirmation: 'prod' }),
  ).resolves.toMatchObject({ deleted: true });
  await expect(
    request('agent_discover_secrets', {
      name_glob: 'stripe*',
      profile: 'prod',
      redact_names: false,
    }),
  ).resolves.toEqual([]);
});

it('tracks preview session, config and desktop preference changes independently of secret metadata', async () => {
  const invoke = createMockRuntime(new URLSearchParams());
  const request = (command: string, payload: Record<string, unknown>) =>
    invoke(command, { request: payload });
  await expect(invoke('desktop_get_launch_at_login', {})).resolves.toBe(false);
  await expect(invoke('desktop_set_launch_at_login', { enabled: true })).resolves.toBe(true);
  await expect(invoke('desktop_get_launch_at_login', {})).resolves.toBe(true);
  await expect(
    invoke('desktop_pick_file', { save: true, defaultName: 'fixture.lkb' }),
  ).resolves.toMatch(/\/fixture\.lkb$/);
  await expect(invoke('desktop_pick_file', { title: 'Browse for an env file' })).resolves.toMatch(
    /\/acme-api\/\.env$/,
  );
  await expect(
    request('desktop_import_env', { project_id: 'acme-api', path: '.env' }),
  ).resolves.toEqual({ summary: 'Imported 1 variable.' });
  const metadata = await request('agent_list_secrets', {
    project_id: 'acme-api',
    profile_id: 'acme-api-dev',
  });
  expect(metadata).toMatchObject({
    rows: expect.arrayContaining([expect.objectContaining({ name: 'REDIS_URL' })]),
  });
  expect(JSON.stringify(metadata)).not.toContain('preview-imported-value');
  await expect(
    request('agent_write_config', {
      project_id: 'acme-api',
      profile_name: 'dev',
      changes: { dangerous_profile: true, user_verification_required_for: { copy: true } },
    }),
  ).resolves.toMatchObject({
    settings: {
      dangerous_profile: { dangerous: true },
      user_verification_required_for: { copy: true },
    },
  });
  await expect(invoke('desktop_scan_project', {})).resolves.toEqual({
    launched: true,
    command: 'locket scan --require-known',
  });
  await invoke('agent_lock', {});
  await expect(invoke('agent_status', {})).resolves.toMatchObject({
    lock_state: 'locked',
    unlock_ttl_seconds: null,
  });
  await expect(
    request('agent_reveal', { profile_id: 'acme-api-dev', secret_name: 'REDIS_URL' }),
  ).rejects.toMatchObject({ code: 'UnlockRequired' });
  await expect(invoke('fixture-unknown-command', {})).rejects.toThrow(
    'Unsupported preview command',
  );
});
