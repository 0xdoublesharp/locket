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
  desktopSavePolicy,
  desktopTeamSyncRenameProfile,
  desktopTeamSyncPreserveOverride,
  unlockVault,
  actionError,
} from './client';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn() }));
describe('typed desktop operations', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(isTauri).mockReturnValue(true);
    vi.mocked(invoke).mockResolvedValue(undefined);
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
  };
  expect(await desktopTeamSyncRenameProfile(rename)).toEqual({ ok: true, value: status });
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_rename_profile', { request: rename });
  const preserve = {
    project_id: 'project',
    incoming_profile_id: 'incoming-profile',
    local_secret_id: 'local-secret',
  };
  expect(await desktopTeamSyncPreserveOverride(preserve)).toEqual({ ok: true, value: status });
  expect(invoke).toHaveBeenLastCalledWith('desktop_team_sync_preserve_override', {
    request: preserve,
  });
});
