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
