import { beforeEach, describe, expect, it, vi } from 'vitest';
import { invoke, isTauri } from '@tauri-apps/api/core';
import {
  desktopListProjects,
  desktopGetLaunchAtLogin,
  desktopSetLaunchAtLogin,
  desktopPickDirectory,
  desktopPickFile,
  desktopCopyTextPlain,
  desktopMcpConfigSnippet,
  discoverSecrets,
  listProjects,
  desktopOpenProject,
  desktopOpenSharedVault,
  desktopInspectProjectFolder,
  desktopInitializeProject,
  desktopImportEnv,
  desktopStartAgent,
  desktopRunPolicy,
  desktopCreateProfile,
  desktopDeleteSecret,
  desktopCopySecretToShared,
  desktopDetectCommands,
  desktopSavePolicy,
  desktopTeamSyncConfigure,
  desktopTeamSyncTestRemote,
  desktopTeamSyncRenameProfile,
  desktopTeamSyncPreserveOverride,
  unlockVault,
  actionError,
} from './client';
import type { TeamSyncTransportInput } from './types';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn() }));
describe('typed desktop operations', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(isTauri).mockReturnValue(true);
    vi.mocked(invoke).mockResolvedValue(undefined);
  });
  it('forwards legacy folder settings and every configured or draft delivery test shape', async () => {
    const project_id = 'fixture';
    const allow_dangerous = false;
    const legacy = { project_id, folder: '/fixture/team', allow_dangerous };
    vi.mocked(invoke).mockResolvedValue({ transport_kind: 'folder', folder: legacy.folder });
    await expect(desktopTeamSyncConfigure(legacy)).resolves.toMatchObject({
      ok: true,
      value: { folder: legacy.folder },
    });
    expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_configure', { request: legacy });

    const transports: TeamSyncTransportInput[] = [
      { kind: 'folder', path: legacy.folder },
      { kind: 's3', bucket: 'fixture', region: 'auto', credential_mode: 'env' },
      {
        kind: 'webdav',
        url: 'https://fixture.test/team',
        credential_mode: 'none',
        auth_kind: 'none',
      },
    ];
    for (const transport of transports) {
      const request = { project_id, transport, allow_dangerous };
      await desktopTeamSyncConfigure(request);
      expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_configure', { request });

      const result = {
        ok: true,
        transport_kind: transport.kind,
        target: 'fixture-target',
        package_count: 3,
        writable_checked: false,
        message: 'Package listing succeeded',
      };
      vi.mocked(invoke).mockResolvedValueOnce(result);
      const test = { project_id, transport, confirm_dangerous_profile: 'dev' };
      await expect(desktopTeamSyncTestRemote(test)).resolves.toEqual({ ok: true, value: result });
      expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_test_remote', { request: test });
    }
    vi.mocked(invoke).mockRejectedValueOnce({ kind: 'protocol', reason: 'Connection lost' });
    await expect(desktopTeamSyncTestRemote({ project_id })).resolves.toEqual({
      ok: false,
      error: { kind: 'protocol', reason: 'Connection lost' },
    });
    expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_test_remote', {
      request: { project_id },
    });
  });
  it('forwards exact native argument shapes', async () => {
    await desktopListProjects();
    expect(invoke).toHaveBeenLastCalledWith('desktop_list_projects', {});
    await desktopOpenProject({ path: '/fixture' });
    expect(invoke).toHaveBeenLastCalledWith('desktop_open_project', {
      request: { path: '/fixture' },
    });
    await desktopOpenSharedVault();
    expect(invoke).toHaveBeenLastCalledWith('desktop_open_shared_vault', {});
    await desktopInspectProjectFolder({ path: '/fixture' });
    expect(invoke).toHaveBeenLastCalledWith('desktop_inspect_project_folder', {
      request: { path: '/fixture' },
    });
    await desktopInitializeProject({ path: '/fixture' });
    expect(invoke).toHaveBeenLastCalledWith('desktop_initialize_project', {
      request: { path: '/fixture' },
    });
    await desktopStartAgent({ project_id: 'fixture' });
    expect(invoke).toHaveBeenLastCalledWith('desktop_start_agent', {
      request: { project_id: 'fixture' },
    });
    const request = { project_id: 'fixture', path: '.env', overwrite: false, literal: false };
    await desktopImportEnv(request);
    expect(invoke).toHaveBeenLastCalledWith('desktop_import_env', { request });
    await desktopRunPolicy({ project_id: 'fixture', policy_name: 'dev' });
    expect(invoke).toHaveBeenLastCalledWith('desktop_run_policy', {
      request: { project_id: 'fixture', policy_name: 'dev' },
    });
  });
  it('keeps companion and discovery IPC payloads exact', async () => {
    const discover = { query: 'postmark', tag: 'email', owner: 'messaging', redact_names: false };
    const list = { redact_names: true };
    await desktopGetLaunchAtLogin();
    await desktopSetLaunchAtLogin(true);
    await desktopPickDirectory('Project folder');
    await desktopPickFile({ title: 'Export backup', save: true, defaultName: 'locket-backup.lkb' });
    await desktopCopyTextPlain('lk://dev/POSTMARK_TOKEN');
    await desktopMcpConfigSnippet();
    await discoverSecrets(discover);
    await listProjects(list);
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['desktop_get_launch_at_login', {}],
      ['desktop_set_launch_at_login', { enabled: true }],
      ['desktop_pick_directory', { title: 'Project folder' }],
      [
        'desktop_pick_file',
        { title: 'Export backup', save: true, defaultName: 'locket-backup.lkb' },
      ],
      ['desktop_copy_text_plain', { text: 'lk://dev/POSTMARK_TOKEN' }],
      ['desktop_mcp_config_snippet', {}],
      ['agent_discover_secrets', { request: discover }],
      ['agent_list_projects', { request: list }],
    ]);
  });
  it('saves a single durable policy and confirmation', async () => {
    const request = {
      project_id: 'fixture',
      mode: 'delete' as const,
      original_name: 'dev',
      policy: {} as never,
      confirmation: 'production',
    };
    await desktopSavePolicy(request);
    expect(invoke).toHaveBeenLastCalledWith('desktop_save_policy', { request });
  });
  it('sends typed requests and returns the responses for desktop CRUD and detection', async () => {
    const create = { project_id: 'fixture', profile_name: 'qa' };
    const created = { profile_id: 'qa-id', profile_name: 'qa', dangerous: false, created: true };
    vi.mocked(invoke).mockResolvedValueOnce(created);
    expect(await desktopCreateProfile(create)).toEqual({ ok: true, value: created });

    const remove = {
      project_id: 'fixture',
      profile_id: 'prod-id',
      secret_name: 'TOKEN',
      source: 'team-managed' as const,
      confirmation: 'prod',
    };
    const deleted = { secret_name: 'TOKEN', source: 'team-managed', version: 2, deleted: true };
    vi.mocked(invoke).mockResolvedValueOnce(deleted);
    expect(await desktopDeleteSecret(remove)).toEqual({ ok: true, value: deleted });

    const copy = {
      from_project_id: 'fixture',
      from_profile_id: 'prod-id',
      secret_name: 'TOKEN',
      source: 'machine-local' as const,
      overwrite: true,
      confirmation: 'prod',
    };
    const copied = {
      target_project_id: 'shared-id',
      target_profile_id: 'shared-default-id',
      secret_name: 'TOKEN',
      version: 3,
      action: 'rotate',
    };
    vi.mocked(invoke).mockResolvedValueOnce(copied);
    expect(await desktopCopySecretToShared(copy)).toEqual({ ok: true, value: copied });

    const detect = { project_id: 'fixture' };
    const detected = [
      {
        name: 'test',
        argv: ['pnpm', 'run', 'test'],
        command_preview: 'pnpm run test',
        source_file: 'package.json',
        already_configured: false,
      },
    ];
    vi.mocked(invoke).mockResolvedValueOnce(detected);
    expect(await desktopDetectCommands(detect)).toEqual({ ok: true, value: detected });
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['desktop_create_profile', { request: create }],
      ['desktop_delete_secret', { request: remove }],
      ['desktop_copy_secret_to_shared', { request: copy }],
      ['desktop_detect_commands', { request: detect }],
    ]);
  });
  it('uses typed keychain unlock or explicit passphrase', async () => {
    const request = {
      project_id: 'fixture',
      ttl_seconds: 900,
      source: { kind: 'os-keychain' as const },
      audit: { profile_id: 'dev' },
    };
    await unlockVault(request);
    expect(invoke).toHaveBeenLastCalledWith('agent_unlock', { request });
    await unlockVault({ ...request, source: { kind: 'passphrase', passphrase: 'fixture-only' } });
    expect(invoke).toHaveBeenLastCalledWith('agent_unlock', {
      request: { ...request, source: { kind: 'passphrase', passphrase: 'fixture-only' } },
    });
  });
  it('keeps browser previews disconnected and returns useful errors', async () => {
    vi.mocked(isTauri).mockReturnValue(false);
    const result = await desktopStartAgent({});
    expect(result.ok).toBe(false);
    expect(invoke).not.toHaveBeenCalled();
    if (!result.ok) expect(actionError(result.error)).toContain('desktop');
    expect(actionError({ kind: 'rejected', code: 'Locked' } as never)).toContain('Locked');
    vi.mocked(isTauri).mockReturnValue(true);
    vi.mocked(invoke).mockRejectedValueOnce('Invalid path');
    const failure = await desktopOpenProject({ path: '/invalid' });
    if (!failure.ok) expect(actionError(failure.error)).toContain('Invalid path');
  });
});

it('sends only typed local collision identifiers for approved pending resolution', async () => {
  vi.mocked(isTauri).mockReturnValue(true);
  const status = {
    epoch: 3,
    state: 'verified',
    conflicts: 0,
    waiting: 0,
    published: 0,
    applied: 0,
    pending_profiles: {},
  };
  vi.mocked(invoke).mockResolvedValue(status);
  const rename = {
    project_id: 'project',
    incoming_profile_id: 'incoming-profile',
    local_profile_id: 'local-profile',
    new_name: 'preserved-local',
    confirm_dangerous_profile: 'production',
  };
  expect(await desktopTeamSyncRenameProfile(rename)).toEqual({ ok: true, value: status });
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_rename_profile', { request: rename });
  const preserve = {
    project_id: 'project',
    incoming_profile_id: 'incoming-profile',
    local_secret_id: 'local-secret',
    confirm_dangerous_profile: 'production',
  };
  expect(await desktopTeamSyncPreserveOverride(preserve)).toEqual({ ok: true, value: status });
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_preserve_override', {
    request: preserve,
  });
});
