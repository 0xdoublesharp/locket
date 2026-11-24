import type {
  AgentClientError,
  AgentConfigSettings,
  AgentStatus,
  AuditWireRow,
  CommandPolicyWireRow,
  DesktopProjectContext,
  DesktopSavePolicyRequest,
  DeviceMemberWireRow,
  DiscoverSecretsRequest,
  DiscoveredSecretWire,
  EffectiveUserVerificationSettings,
  ProjectSummaryWire,
  RuntimeSessionWireRow,
  SecretWireRow,
  SetActiveProfileResponse,
  UnlockRequest,
  VersionWireRow,
  WriteConfigRequest,
} from '../agent/types';
import type { SetSecretRequest, SetSecretResponse } from '../agent/client';

const workspace = '/Users/justin/Workspaces';
const mcp = { command: 'locket', args: ['mcp'] };
const noResponse = new Promise<never>(() => {});

export function createMockRuntime(params: URLSearchParams) {
  const scenario = params.get('state');
  const startView = params.get('view') ?? 'dashboard';
  const now = Date.now() * 1_000_000;
  const minute = 60_000_000_000;
  const day = 1440 * minute;
  let unlocked = scenario !== 'locked';
  let launchAtLogin = false;
  let sequence = 0;
  const verification: EffectiveUserVerificationSettings = {
    unlock: true,
    reveal: true,
    copy: false,
    dangerous_profile_switch: true,
    recovery: true,
    team_accept: false,
    device_register: true,
  };
  const config = { privacy_redact_names: false, agent_unlock_ttl: '1h' };
  let unlockedFor = 3600;

  const projects: DesktopProjectContext[] = [
    {
      root: `${workspace}/acme-api`,
      project_id: 'acme-api',
      project_name: 'acme-api',
      profile_id: 'acme-api-dev',
      profile_name: 'dev',
    },
    {
      root: 'Shared vault',
      project_id: 'shared',
      project_name: '@shared',
      profile_id: 'shared-default',
      profile_name: 'default',
    },
    {
      root: `${workspace}/web-app`,
      project_id: 'web-app',
      project_name: 'web-app',
      profile_id: 'web-app-dev',
      profile_name: 'dev',
    },
  ];
  let selected = projects[0]!;
  const profiles = new Map([
    ['acme-api-dev', { project: 'acme-api', name: 'dev', dangerous: false }],
    ['acme-api-staging', { project: 'acme-api', name: 'staging', dangerous: false }],
    ['acme-api-prod', { project: 'acme-api', name: 'prod', dangerous: true }],
    ['shared-default', { project: 'shared', name: 'default', dangerous: false }],
    ['web-app-dev', { project: 'web-app', name: 'dev', dangerous: false }],
  ]);
  const names = [
    ['DATABASE_URL', 'team-managed', 'Platform', 'database'],
    ['OPENAI_API_KEY', 'user-local', 'Developer Experience', 'ai'],
    ['STRIPE_SECRET_KEY', 'team-managed', 'Payments', 'billing'],
    ['JWT_SIGNING_KEY', 'machine-local', 'Platform', 'auth'],
    ['POSTMARK_TOKEN', 'team-managed', 'Messaging', 'email'],
    ['SENTRY_DSN', 'user-local', 'Observability', 'monitoring'],
  ] as const;
  const secrets: SecretWireRow[] =
    scenario === 'empty'
      ? []
      : names.map(([name, source, owner, tag], index) => ({
          id: `variable-${index + 1}`,
          profile_id: 'acme-api-dev',
          name,
          source,
          source_precedence: source === 'team-managed' ? 1 : source === 'user-local' ? 2 : 3,
          origin: 'local',
          current_version: index === 2 ? 3 : 1,
          state: 'active',
          required: index < 4,
          optional: index >= 4,
          owner,
          tags: [tag],
          created_at: now - (25 - index * 3) * day,
          updated_at: now - 2 * day,
          last_rotated_at: index === 2 ? now - 2 * day : null,
        }));
  if (secrets.length) {
    secrets.push(
      { ...secrets[4]!, id: 'variable-shared-email', profile_id: 'shared-default' },
      { ...secrets[5]!, id: 'variable-web-monitoring', profile_id: 'web-app-dev' },
      { ...secrets[0]!, id: 'variable-staging-database', profile_id: 'acme-api-staging' },
      { ...secrets[2]!, id: 'variable-prod-billing', profile_id: 'acme-api-prod' },
    );
  }

  const definitions = [
    ['dev-server', 'pnpm dev', ['DATABASE_URL', 'OPENAI_API_KEY'], ['SENTRY_DSN']],
    ['db-migrate', 'pnpm db:migrate', ['DATABASE_URL'], []],
    ['deploy-prod', 'pnpm deploy', ['STRIPE_SECRET_KEY@v2'], ['POSTMARK_TOKEN']],
  ] as const;
  const policies: CommandPolicyWireRow[] =
    scenario === 'empty'
      ? []
      : definitions.map(([name, command, required, optional], index) => ({
          id: `policy-${index + 1}`,
          name,
          command_kind: 'argv',
          command_preview: command,
          required_secrets: [...required],
          optional_secrets: [...optional],
          allowed_secrets: [...required, ...optional],
          confirm: index > 0,
          require_user_verification: index === 2,
          require_agent: true,
          allow_remote_docker: false,
          ttl_seconds: 900,
          env_mode: index === 2 ? 'strict' : 'minimal',
          override_mode: 'locket',
          updated_at_unix_nanos: now - 4 * day,
        }));
  const sessions: RuntimeSessionWireRow[] = policies.map((policy, index) => ({
    session_id: `run-${index + 1}`,
    profile: index === 2 ? 'prod' : 'dev',
    policy: policy.name,
    pid: 8431 - index * 23,
    started_at: now - (4 + index * 25) * minute,
    process_start_time: now - (4 + index * 25) * minute,
    ended_at: index ? now - (3 + index * 24) * minute : undefined,
    exit_status: index ? (index === 2 ? 1 : 0) : undefined,
    state: index === 0 ? 'running' : index === 1 ? 'completed' : 'failed',
    secret_name_count: policy.allowed_secrets.length,
    spawn_audit_sequence: 5 - index,
    completion_audit_sequence: index ? 6 - index : undefined,
  }));
  const audit: AuditWireRow[] =
    scenario === 'empty'
      ? []
      : ['UNLOCK', 'COPY', 'RUN_POLICY', 'ROTATE_SECRET', 'RUN_POLICY'].map((action, index) => ({
          sequence: index + 1,
          timestamp: now - (25 - index * 5) * minute,
          profile_id: 'acme-api-dev',
          action,
          status: 'OK',
          secret_name: index === 1 ? 'DATABASE_URL' : index === 3 ? 'STRIPE_SECRET_KEY' : null,
          command: index === 2 ? 'db-migrate' : index === 4 ? 'dev-server' : null,
        }));
  const members: DeviceMemberWireRow[] =
    scenario === 'empty'
      ? []
      : [
          {
            id: 'device-1',
            kind: 'device',
            name: 'Work MacBook',
            status: 'active',
            local_device: true,
            fingerprint: '62a8b220c5f4',
            created_at: now - 25 * day,
            last_seen_at: now - minute,
          },
          {
            id: 'member-2',
            kind: 'member',
            name: 'Jordan Lee',
            status: 'active',
            role: 'developer',
            trusted_device_count: 1,
            created_at: now - 21 * day,
          },
        ];
  const values = new Map<string, string>();
  let teamFolder = `${workspace}/acme-api/.locket/team`;

  function status(): AgentStatus {
    return {
      lock_state: unlocked ? 'unlocked' : 'locked',
      project_id: selected.project_id,
      profile_name: selected.profile_name,
      live_grant_count: unlocked ? 1 : 0,
      agent_version: '0.1.1',
      unlock_ttl_seconds: unlocked ? unlockedFor : null,
      running_session_count: sessions.filter((session) => session.state === 'running').length,
      scan_warning_count: 0,
      recent_audit_status: unlocked ? 'ok' : 'unknown',
      pinned_reference_warning_count: policies.length ? 1 : 0,
      session_monitoring: 'active: macOS native notifications',
    };
  }

  function readSettings(projectId?: unknown, profileName?: unknown): AgentConfigSettings {
    const entry = [...profiles].find(
      ([, profile]) => profile.project === projectId && profile.name === profileName,
    );
    return {
      ...config,
      user_verification_required_for: { ...verification },
      dangerous_profile: entry
        ? {
            profile_id: entry[0],
            profile_name: entry[1].name,
            profile_label: config.privacy_redact_names ? 'Active environment' : entry[1].name,
            dangerous: entry[1].dangerous,
          }
        : null,
    };
  }

  function discover(request: DiscoverSecretsRequest): DiscoveredSecretWire[] {
    return secrets
      .flatMap((row): DiscoveredSecretWire[] => {
        const profile = profiles.get(row.profile_id);
        const project = projects.find((entry) => entry.project_id === profile?.project);
        if (!profile || !project) return [];
        const searchable = [row.name, row.owner, row.tags?.join(' '), project.project_name]
          .join(' ')
          .toLowerCase();
        if (
          (request.query && !searchable.includes(request.query.toLowerCase())) ||
          (request.owner && !row.owner?.toLowerCase().includes(request.owner.toLowerCase())) ||
          (request.tag && !row.tags?.includes(request.tag)) ||
          (request.project &&
            ![project.project_id, project.project_name].includes(request.project)) ||
          (request.profile && ![row.profile_id, profile.name].includes(request.profile)) ||
          (request.source && request.source !== row.source) ||
          (request.name_glob && !matchesGlob(row.name, request.name_glob)) ||
          (!request.include_deleted && row.state === 'deleted')
        )
          return [];
        const redact = request.redact_names;
        const name = redact ? `Variable ${secrets.indexOf(row) + 1}` : row.name;
        const profileName = redact
          ? `Environment ${[...profiles.keys()].indexOf(row.profile_id) + 1}`
          : profile.name;
        return [
          {
            project_id: project.project_id,
            project_name: redact
              ? `Project ${projects.indexOf(project) + 1}`
              : project.project_name,
            trusted_roots: [redact ? 'Project folder' : project.root],
            profile_id: row.profile_id,
            profile: profileName,
            dangerous: profile.dangerous,
            secret_id: row.id,
            name,
            source: row.source,
            source_precedence: row.source_precedence,
            origin: row.origin,
            version: row.current_version,
            state: row.state,
            description: null,
            owner: redact ? null : (row.owner ?? null),
            tags: redact ? [] : (row.tags ?? []),
            required: row.required,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_rotated_at: row.last_rotated_at,
            reference: `lk://${profileName}/${name}`,
          },
        ];
      })
      .slice(0, request.limit ?? 200);
  }

  function projectSummaries(redact: boolean): ProjectSummaryWire[] {
    return projects.map((project, index) => ({
      project_id: project.project_id,
      name: redact ? `Project ${index + 1}` : project.project_name,
      profiles: [...profiles].flatMap(([id, profile], i) =>
        profile.project === project.project_id
          ? [
              {
                id,
                name: redact ? `Environment ${i + 1}` : profile.name,
                dangerous: profile.dangerous,
              },
            ]
          : [],
      ),
      trusted_roots: [redact ? 'Project folder' : project.root],
      active_secret_count: secrets.filter(
        (row) => profiles.get(row.profile_id)?.project === project.project_id,
      ).length,
    }));
  }

  function saveSecret(request: SetSecretRequest, rotate: boolean): SetSecretResponse {
    requireUnlocked();
    const existing = secrets.find(
      (row) => row.name === request.secret_name && row.profile_id === request.profile_id,
    );
    const source: SecretWireRow['source'] =
      request.source === 'team-managed' || request.source === 'machine-local'
        ? request.source
        : 'user-local';
    const row: SecretWireRow = existing ?? {
      id: `variable-new-${++sequence}`,
      profile_id: request.profile_id,
      name: request.secret_name,
      source,
      source_precedence: 2,
      origin: 'local',
      current_version: 0,
      state: 'active',
      required: false,
      created_at: now,
      updated_at: now,
      last_rotated_at: null,
    };
    if (!existing) secrets.push(row);
    row.current_version++;
    if (rotate) row.last_rotated_at = now;
    values.set(`${row.profile_id}:${row.name}`, request.value);
    return {
      action: rotate ? 'rotated' : 'set',
      secret_id: row.id,
      version: row.current_version,
      source: row.source,
    };
  }

  const routeCommands: Record<string, string> = {
    dashboard: 'agent_status',
    secrets: 'agent_list_secrets',
    discover: 'agent_discover_secrets',
    'secret-editor': 'agent_list_secrets',
    policies: 'agent_list_policies',
    execution: 'agent_list_runtime_sessions',
    audit: 'agent_list_audit',
    team: 'desktop_team_sync_status',
    recovery: 'agent_status',
    settings: 'agent_read_config',
  };
  let showFailure = scenario === 'error';
  function fail(code: string, display_reason: string, next_action: string): never {
    throw {
      kind: 'rejected',
      code,
      message: display_reason,
      display_reason,
      next_action,
      retryable: true,
    } satisfies AgentClientError;
  }
  function requireUnlocked(): void {
    if (!unlocked) fail('UnlockRequired', 'The vault is locked.', 'Unlock the vault and retry.');
  }

  return async (command: string, args: Record<string, unknown>): Promise<unknown> => {
    if (command === routeCommands[startView]) {
      if (scenario === 'loading') return noResponse;
      if (showFailure) {
        // Keep the selected error state stable across metadata refreshes.
        fail('AgentUnavailable', 'Could not load this view.', 'Retry the request.');
      }
    }
    const request = (args.request ?? {}) as Record<string, unknown>;
    const redact = request.redact_names === true || request.privacy_redact_names === true;
    const projectSecrets = secrets.filter((row) => row.profile_id === request.profile_id);
    const auditRows = request.project_id === 'acme-api' ? audit : [];
    const chain = {
      hmac_ok: unlocked ? true : null,
      first_break_sequence: null,
      rows_verified: unlocked ? auditRows.length : 0,
      locked: !unlocked,
    };
    switch (command) {
      case 'agent_status':
        return status();
      case 'desktop_list_projects':
        return projects.map((project) => ({ ...project }));
      case 'desktop_open_project':
      case 'desktop_initialize_project': {
        let project = projects.find((entry) => entry.root === request.path);
        if (
          !project &&
          command === 'desktop_initialize_project' &&
          typeof request.path === 'string'
        ) {
          const id = `project-new-${++sequence}`;
          project = {
            root: request.path,
            project_id: id,
            project_name: request.path.split('/').pop() || 'new-project',
            profile_id: `${id}-dev`,
            profile_name: 'dev',
          };
          projects.push(project);
          profiles.set(project.profile_id, { project: id, name: 'dev', dangerous: false });
        }
        if (!project)
          fail(
            'ProjectNotFound',
            'This folder has no Locket project.',
            'Choose a known project or initialize it.',
          );
        selected = project;
        return { ...selected };
      }
      case 'desktop_start_agent':
        showFailure = false;
        return;
      case 'agent_list_projects':
        return projectSummaries(redact);
      case 'agent_discover_secrets':
        return discover(request);
      case 'agent_read_config':
        return readSettings(request.project_id, request.profile_name);
      case 'agent_write_config': {
        requireUnlocked();
        const { changes } = request as unknown as WriteConfigRequest;
        if (typeof changes.privacy_redact_names === 'boolean')
          config.privacy_redact_names = changes.privacy_redact_names;
        if (changes.agent_unlock_ttl) config.agent_unlock_ttl = changes.agent_unlock_ttl;
        if (changes.user_verification_required_for)
          Object.assign(verification, changes.user_verification_required_for);
        const profile = profiles.get(selected.profile_id);
        if (profile && typeof changes.dangerous_profile === 'boolean')
          profile.dangerous = changes.dangerous_profile;
        return {
          settings: readSettings(request.project_id, request.profile_name),
          changed_keys: Object.keys(changes),
        };
      }
      case 'agent_lock':
        unlocked = false;
        return;
      case 'agent_unlock':
        unlocked = true;
        unlockedFor = (request as unknown as UnlockRequest).ttl_seconds;
        return;
      case 'agent_set_active_profile': {
        requireUnlocked();
        const entry = [...profiles].find(
          ([, profile]) =>
            profile.project === selected.project_id && profile.name === request.profile_name,
        );
        if (!entry)
          fail(
            'ProfileNotFound',
            'The environment was not found.',
            'Choose an existing environment.',
          );
        const [id, profile] = entry;
        if (profile.dangerous && request.confirmation !== profile.name) {
          fail(
            'DangerousProfileConfirmationRequired',
            'Confirm the dangerous environment.',
            'Choose the environment and type its name.',
          );
        }
        const previous = { ...selected };
        selected.profile_id = id;
        selected.profile_name = profile.name;
        return {
          changed: previous.profile_id !== id,
          profile_id: id,
          profile_name: profile.name,
          profile_label: redact ? 'Environment' : profile.name,
          dangerous: profile.dangerous,
          prior_profile_id: previous.profile_id,
          prior_profile_name: previous.profile_name,
          prior_profile_label: redact ? 'Environment' : previous.profile_name,
          live_grants_revoked: 0,
        } satisfies SetActiveProfileResponse;
      }
      case 'agent_list_secrets':
        return {
          rows: projectSecrets.map((row, index) =>
            redact ? { ...row, name: `Variable ${index + 1}`, owner: undefined, tags: [] } : row,
          ),
        };
      case 'agent_list_versions': {
        const rows: VersionWireRow[] = projectSecrets.flatMap((row, index) => {
          const current: VersionWireRow = {
            secret_id: row.id,
            profile_id: row.profile_id,
            name: redact ? `Variable ${index + 1}` : row.name,
            source: row.source,
            source_precedence: row.source_precedence,
            origin: row.origin,
            secret_state: row.state,
            current_version: row.current_version,
            last_rotated_at: row.last_rotated_at,
            version: row.current_version,
            version_state: 'current',
            created_at: row.created_at,
            deprecated_at: null,
            grace_until: null,
            purged_at: null,
            pinned_reference_eligible: true,
            scan_included: true,
          };
          return row.current_version === 3
            ? [
                current,
                {
                  ...current,
                  version: 2,
                  version_state: 'deprecated',
                  deprecated_at: now - 2 * day,
                  grace_until: now + 5 * day,
                },
              ]
            : [current];
        });
        return { rows };
      }
      case 'agent_list_policies':
        return {
          rows:
            request.project_id !== 'acme-api'
              ? []
              : policies.map((row, index) =>
                  redact
                    ? {
                        ...row,
                        name: `Command ${index + 1}`,
                        command_preview: 'Command hidden',
                        required_secrets: [],
                        optional_secrets: [],
                        allowed_secrets: [],
                      }
                    : row,
                ),
        };
      case 'agent_list_runtime_sessions':
        return {
          rows:
            request.project_id !== 'acme-api'
              ? []
              : sessions.map((row, index) =>
                  redact ? { ...row, profile: 'Environment', policy: `Command ${index + 1}` } : row,
                ),
        };
      case 'agent_list_device_members':
        return {
          rows: members.map((row, index) =>
            redact ? { ...row, name: `Member ${index + 1}`, fingerprint: undefined } : row,
          ),
        };
      case 'agent_list_audit':
        return {
          rows: auditRows
            .map((row) =>
              redact ? { ...row, profile_id: null, secret_name: null, command: null } : row,
            )
            .reverse(),
          chain_status: chain,
        };
      case 'agent_verify_audit':
        return { ...chain, first_break_reason: null };
      case 'agent_set_secret':
        return saveSecret(request as unknown as SetSecretRequest, false);
      case 'agent_rotate_secret':
        return saveSecret(request as unknown as SetSecretRequest, true);
      case 'agent_reveal':
        requireUnlocked();
        return {
          value: values.get(`${request.profile_id}:${request.secret_name}`) ?? 'preview-only-value',
          ttl_seconds: 20,
        };
      case 'agent_copy_secret':
        requireUnlocked();
        return {
          kind: 'unsupported',
          unsupported_reason: 'Temporary value copying is available in the macOS app',
        };
      case 'desktop_copy_text_plain':
        await navigator.clipboard.writeText(String(args.text));
        return;
      case 'desktop_get_launch_at_login':
        return launchAtLogin;
      case 'desktop_set_launch_at_login':
        launchAtLogin = args.enabled === true;
        return launchAtLogin;
      case 'desktop_pick_directory':
        return selected.root;
      case 'desktop_pick_file':
        return args.save
          ? `/Users/justin/Downloads/${args.defaultName ?? 'locket-backup.lkb'}`
          : args.title === 'Browse for an env file'
            ? `${selected.root}/.env`
            : '/Users/justin/Downloads/locket-backup.lkb';
      case 'desktop_mcp_config_snippet':
        return { ...mcp, json: JSON.stringify({ mcpServers: { locket: mcp } }, null, 2) };
      case 'desktop_import_env':
        saveSecret(
          {
            project_id: selected.project_id,
            profile_id: selected.profile_id,
            secret_name: 'REDIS_URL',
            value: 'preview-imported-value',
          },
          false,
        );
        return { summary: 'Imported 1 variable.' };
      case 'desktop_run_policy':
        return { launched: true, command: `locket run ${request.policy_name}` };
      case 'desktop_scan_project':
        return { launched: true, command: 'locket scan --require-known' };
      case 'desktop_save_policy': {
        const { policy, mode, original_name } = request as unknown as DesktopSavePolicyRequest;
        const index = policies.findIndex((row) => row.name === original_name);
        if (index >= 0) policies.splice(index, 1);
        if (mode !== 'delete')
          policies.push({ ...policy, id: `policy-new-${++sequence}`, updated_at_unix_nanos: now });
        return;
      }
      case 'desktop_variable_readiness':
        return {
          project_id: selected.project_id,
          profile_id: selected.profile_id,
          profile_name: selected.profile_name,
          policies: policies.map((policy) => ({
            policy_name: policy.name,
            profile_id: selected.profile_id,
            rows: secrets
              .filter((row) => row.profile_id === selected.profile_id)
              .map((row) => ({
                name: row.name,
                required: row.required,
                classification: 'secret',
                state: unlocked ? 'ready' : 'unverified',
                selected_source: row.source,
              })),
          })),
        };
      case 'desktop_team_sync_configure':
        teamFolder = String(request.folder);
        return syncStatus();
      case 'desktop_team_sync_status':
      case 'desktop_team_sync_now':
        return syncStatus();
      case 'agent_export_bundle':
        return {
          action: 'export',
          status: request.preview_only ? 'preview' : 'ok',
          message: request.preview_only
            ? '6 variables and 1 environment selected.'
            : 'Sealed bundle exported.',
        };
      case 'agent_import_bundle':
        return { action: 'import', status: 'ok', message: 'Sealed bundle imported.' };
      case 'agent_verify_bundle':
        return {
          structural_valid: true,
          schema_version: 1,
          project_id: selected.project_id,
          profile_count: 1,
          recipient_count: 1,
          payload_digest: 'a'.repeat(64),
          decryptable_by_this_device: true,
          message: 'Bundle verified.',
        };
      case 'agent_recovery_rotate':
        return { action: 'rotate', status: 'ok', message: 'Recovery code rotated.' };
      default:
        throw new Error(`Unsupported preview command: ${command}`);
    }
  };

  function syncStatus() {
    return {
      epoch: 3,
      state: unlocked ? 'verified' : 'locked',
      conflicts: 0,
      waiting: 0,
      waiting_known: true,
      last_verified_at: now - minute,
      published: 1,
      applied: 2,
      folder: teamFolder,
    };
  }
}

function matchesGlob(name: string, glob: string): boolean {
  const literal = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${literal.replaceAll('*', '.*').replaceAll('?', '.')}$`, 'i').test(name);
}
