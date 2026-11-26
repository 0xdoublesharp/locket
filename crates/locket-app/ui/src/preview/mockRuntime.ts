import type {
  AgentClientError,
  AgentConfigSettings,
  AgentStatus,
  AuditWireRow,
  CommandPolicyWireRow,
  DesktopCopySecretToSharedRequest,
  DesktopCopySecretToSharedResponse,
  DesktopCreateProfileRequest,
  DesktopCreateProfileResponse,
  DesktopDeleteSecretRequest,
  DesktopDeleteSecretResponse,
  DesktopProjectContext,
  DesktopImportEnvRequest,
  DesktopImportEnvResponse,
  DesktopLinkSecretRequest,
  DesktopLinkSecretResponse,
  DesktopUnlinkSecretRequest,
  DesktopUnlinkSecretResponse,
  DesktopListDuplicatesResponse,
  DesktopListSharedUsagesResponse,
  DuplicateMemberRow,
  ImportDuplicateMatch,
  SharedUsageRow,
  VersionSourceWire,
  DesktopSavePolicyRequest,
  DetectedCommandRow,
  DeviceMemberWireRow,
  DiscoverSecretsRequest,
  DiscoveredSecretWire,
  EffectiveUserVerificationSettings,
  ProjectSummaryWire,
  RuntimeSessionWireRow,
  SecretWireRow,
  SetActiveProfileResponse,
  TeamSyncStatus,
  TeamSyncTestResult,
  TeamSyncTransportInput,
  UnlockRequest,
  VersionWireRow,
  WriteConfigRequest,
} from '../agent/types';
import type { SetSecretRequest, SetSecretResponse } from '../agent/client';
import { validDeliveryUrl } from '../team/sync';
import { unlinkAllConfirmation } from '../secret/sharedLinks';

const workspace = '/Users/justin/Workspaces';
const mcp = { command: 'locket', args: ['mcp'] };
const noResponse = new Promise<never>(() => {});
type PersistedSecret = SecretWireRow & { source: VersionSourceWire };
const precedence: Record<SecretWireRow['source'], number> = {
  'team-managed': 1,
  'shared-link': 2,
  'user-local': 3,
  'machine-local': 4,
};
type TeamDelivery =
  | { transport_kind: 'folder'; folder: string }
  | {
      transport_kind: 's3' | 'webdav';
      folder: null;
      remote_target: string;
      remote_endpoint?: string;
      remote_region?: string;
      credential_mode: 'none' | 'vault' | 'env';
    };

export function createMockRuntime(params: URLSearchParams) {
  const scenario = params.get('state');
  const startView = params.get('view') ?? 'dashboard';
  const now = Date.now() * 1_000_000;
  const minute = 60_000_000_000;
  const day = 1440 * minute;
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

  const isWelcome = scenario === 'welcome';
  const projects: DesktopProjectContext[] = isWelcome
    ? []
    : [
        {
          root: '',
          project_id: 'lk_proj_shared_preview',
          project_name: '@shared',
          profile_id: 'shared-default',
          profile_name: 'default',
          is_shared: true,
        },
        {
          root: `${workspace}/acme-api`,
          project_id: 'acme-api',
          project_name: 'acme-api',
          profile_id: 'acme-api-dev',
          profile_name: 'dev',
          is_shared: false,
        },
        {
          root: `${workspace}/web-app`,
          project_id: 'web-app',
          project_name: 'web-app',
          profile_id: 'web-app-dev',
          profile_name: 'dev',
          is_shared: false,
        },
      ];
  let selected = projects.find((project) => !project.is_shared) ?? null;
  const unlockedProjects = new Map(
    scenario === 'locked' ? [] : projects.map(({ project_id }) => [project_id, 3600]),
  );
  const profiles = new Map([
    ['acme-api-dev', { project: 'acme-api', name: 'dev', dangerous: false }],
    ['acme-api-staging', { project: 'acme-api', name: 'staging', dangerous: false }],
    ['acme-api-prod', { project: 'acme-api', name: 'prod', dangerous: true }],
    ['shared-default', { project: 'lk_proj_shared_preview', name: 'default', dangerous: false }],
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
  const secrets: PersistedSecret[] =
    scenario === 'empty'
      ? []
      : names.map(([name, source, owner, tag], index) => ({
          id: `variable-${index + 1}`,
          profile_id: 'acme-api-dev',
          name,
          source,
          source_precedence: precedence[source],
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
      {
        ...secrets[4]!,
        id: 'variable-shared-email',
        profile_id: 'shared-default',
        source: 'user-local',
        source_precedence: precedence['user-local'],
      },
      { ...secrets[5]!, id: 'variable-web-monitoring', profile_id: 'web-app-dev' },
      { ...secrets[0]!, id: 'variable-staging-database', profile_id: 'acme-api-staging' },
      { ...secrets[2]!, id: 'variable-prod-billing', profile_id: 'acme-api-prod' },
    );
  }

  const definitions = [
    ['dev-server', 'pnpm run dev', ['DATABASE_URL', 'OPENAI_API_KEY'], ['SENTRY_DSN']],
    ['db-migrate', 'pnpm db:migrate', ['DATABASE_URL'], []],
    [
      'deploy-prod',
      'pnpm deploy lk://dev/STRIPE_SECRET_KEY@v2',
      ['STRIPE_SECRET_KEY'],
      ['POSTMARK_TOKEN'],
    ],
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
  const fixtureGroups = new Map([
    ['variable-5', 'email'],
    ['variable-shared-email', 'email'],
    ['variable-6', 'monitoring'],
    ['variable-web-monitoring', 'monitoring'],
  ]);
  const links: SharedUsageRow[] = [];
  if (secrets.length) {
    links.push({
      link_id: 'link-notifications',
      project_id: 'acme-api',
      project_name: 'acme-api',
      profile_id: 'acme-api-dev',
      profile_name: 'dev',
      profile_dangerous: false,
      local_name: 'NOTIFICATION_TOKEN',
      target_secret_id: 'variable-shared-email',
      target_secret_name: 'POSTMARK_TOKEN',
      created_at: now,
      updated_at: now,
    });
  }

  function dedupKey(row: PersistedSecret): string {
    const value = values.get(row.id);
    return fixtureGroups.has(row.id)
      ? `fixture:${fixtureGroups.get(row.id)}`
      : value === undefined
        ? `id:${row.id}`
        : `value:${value}`;
  }
  const teamDeliveries = new Map<string, TeamDelivery | null>();

  function unlockTtl(): number | null {
    return selected ? (unlockedProjects.get(selected.project_id) ?? null) : null;
  }

  function status(): AgentStatus {
    const ttl = unlockTtl();
    return {
      lock_state: ttl === null ? 'locked' : 'unlocked',
      project_id: selected?.project_id ?? null,
      profile_name: selected?.profile_name ?? null,
      live_grant_count: ttl === null ? 0 : 1,
      agent_version: '0.3.1',
      unlock_ttl_seconds: ttl,
      running_session_count: selected
        ? sessions.filter((session) => session.state === 'running').length
        : 0,
      scan_warning_count: 0,
      recent_audit_status: ttl === null ? 'unknown' : 'ok',
      pinned_reference_warning_count: selected && policies.length ? 1 : 0,
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
    const source: VersionSourceWire =
      request.source === 'team-managed' || request.source === 'machine-local'
        ? request.source
        : 'user-local';
    const existing = secrets.find(
      (row) =>
        row.name === request.secret_name &&
        row.profile_id === request.profile_id &&
        row.source === source,
    );
    const row: PersistedSecret = existing ?? {
      id: `variable-new-${++sequence}`,
      profile_id: request.profile_id,
      name: request.secret_name,
      source,
      source_precedence: precedence[source],
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
    values.set(row.id, request.value);
    fixtureGroups.delete(row.id);
    return {
      action: rotate ? 'rotated' : 'set',
      secret_id: row.id,
      version: row.current_version,
      source: row.source,
    };
  }

  function createProfile(request: DesktopCreateProfileRequest): DesktopCreateProfileResponse {
    requireUnlocked();
    if (
      [...profiles.values()].some(
        (profile) =>
          profile.project === request.project_id && profile.name === request.profile_name,
      )
    )
      fail(
        'SecretAlreadyExists',
        'An environment with this name already exists.',
        'Choose another name.',
      );
    const id = `${request.project_id}-profile-${++sequence}`;
    profiles.set(id, { project: request.project_id, name: request.profile_name, dangerous: false });
    return { profile_id: id, profile_name: request.profile_name, dangerous: false, created: true };
  }

  function requireDangerousConfirmation(
    request: Record<string, unknown>,
    projectWide = false,
    force = false,
  ): void {
    const project = requireSelectedProject();
    const active = profiles.get(project.profile_id);
    const dangerous = projectWide
      ? [...profiles.values()].some(
          (profile) => profile.project === project.project_id && profile.dangerous,
        )
      : active?.dangerous;
    if (
      (dangerous || force) &&
      (!active?.name || request.confirm_dangerous_profile !== active.name)
    ) {
      fail(
        'ConfirmationFailed',
        'Type the exact active profile name to confirm this action.',
        'Confirm the dangerous profile and retry.',
      );
    }
  }

  function requireProfileConfirmation(profileId: string, confirmation?: string): void {
    const profile = profiles.get(profileId);
    if (profile?.dangerous && confirmation !== profile.name) {
      fail(
        'DangerousProfileConfirmationRequired',
        'Confirm the dangerous environment.',
        'Confirm the action with the environment name.',
      );
    }
  }

  function sharedProject(): DesktopProjectContext {
    const target = projects.find((project) => project.is_shared);
    if (!target) fail('ProjectNotFound', 'Set up the Global Vault first.', 'Open Global Vault.');
    return target;
  }

  function findSharedSecret(name: string): PersistedSecret | undefined {
    const target = sharedProject();
    return secrets.find(
      (row) =>
        row.profile_id === target.profile_id && row.source === 'user-local' && row.name === name,
    );
  }

  function linkToTarget(
    profileId: string,
    localName: string,
    target: PersistedSecret,
  ): SharedUsageRow {
    const profile = profiles.get(profileId);
    const project = projects.find((entry) => entry.project_id === profile?.project);
    if (!profile || !project)
      fail('ProfileNotFound', 'Environment not found.', 'Choose an environment.');
    const existing = links.find(
      (link) => link.profile_id === profileId && link.local_name === localName,
    );
    const link: SharedUsageRow = {
      link_id: existing?.link_id ?? `link-${++sequence}`,
      project_id: project.project_id,
      project_name: project.project_name,
      profile_id: profileId,
      profile_name: profile.name,
      profile_dangerous: profile.dangerous,
      local_name: localName,
      target_secret_id: target.id,
      target_secret_name: target.name,
      created_at: existing?.created_at ?? now,
      updated_at: now,
    };
    if (existing) Object.assign(existing, link);
    else links.push(link);
    return link;
  }

  function sharedUsages(targetId: string, redact = false): DesktopListSharedUsagesResponse {
    return {
      usages: links
        .filter((link) => link.target_secret_id === targetId)
        .map((link, index) => ({
          ...link,
          profile_dangerous: profiles.get(link.profile_id)?.dangerous ?? false,
          ...(redact && {
            project_name: `Project ${index + 1}`,
            profile_id: `Environment ${index + 1}`,
            profile_name: `Environment ${index + 1}`,
            local_name: `Variable ${index + 1}`,
            target_secret_name: 'Shared variable',
          }),
        })),
    };
  }

  function duplicates(redact: boolean): DesktopListDuplicatesResponse {
    const groups = new Map<string, DuplicateMemberRow[]>();
    secrets.forEach((row, index) => {
      const profile = profiles.get(row.profile_id);
      const project = projects.find((entry) => entry.project_id === profile?.project);
      if (!profile || !project) return;
      const key = dedupKey(row);
      const members = groups.get(key) ?? [];
      members.push({
        secret_id: row.id,
        project_id: project.project_id,
        project_name: redact ? `Project ${projects.indexOf(project) + 1}` : project.project_name,
        is_shared: project.is_shared === true,
        profile_id: redact ? 'Environment' : row.profile_id,
        profile_name: redact ? 'Environment' : profile.name,
        profile_dangerous: profile.dangerous,
        name: redact ? `Variable ${index + 1}` : row.name,
        source: row.source,
        current_version: row.current_version,
        updated_at: row.updated_at,
      });
      groups.set(key, members);
    });
    return {
      groups: [...groups.values()]
        .filter((members) => members.length > 1)
        .map((members, index) => ({ group_id: `dup-${index + 1}`, members })),
    };
  }

  function linkSecret(request: DesktopLinkSecretRequest): DesktopLinkSecretResponse {
    requireUnlocked();
    if (requireSelectedProject().is_shared)
      fail('InvalidReference', 'Choose a project to link this secret.', 'Open a project.');
    requireProfileConfirmation(request.profile_id, request.confirmation);
    const target = findSharedSecret(request.target_secret_name);
    if (!target)
      fail('SecretNotFound', 'The Global Vault secret was not found.', 'Check the target name.');
    const link = linkToTarget(request.profile_id, request.local_name, target);
    return {
      link_id: link.link_id,
      local_name: link.local_name,
      target_project_id: sharedProject().project_id,
      target_secret_id: target.id,
      target_secret_name: target.name,
    };
  }

  function unlinkSecret(request: DesktopUnlinkSecretRequest): DesktopUnlinkSecretResponse {
    requireUnlocked();
    requireProfileConfirmation(request.profile_id, request.confirmation);
    const index = links.findIndex(
      (link) => link.profile_id === request.profile_id && link.local_name === request.local_name,
    );
    if (index >= 0) links.splice(index, 1);
    return { local_name: request.local_name, unlinked: index >= 0 };
  }

  function removeSecret(row: PersistedSecret): void {
    secrets.splice(secrets.indexOf(row), 1);
    values.delete(row.id);
    fixtureGroups.delete(row.id);
  }

  function deleteSecret(request: DesktopDeleteSecretRequest): DesktopDeleteSecretResponse {
    requireUnlocked();
    requireProfileConfirmation(request.profile_id, request.confirmation);
    const row = secrets.find(
      (row) =>
        row.profile_id === request.profile_id &&
        row.name === request.secret_name &&
        row.source === request.source,
    );
    if (!row) fail('SecretNotFound', 'The secret was not found.', 'Refresh the secret list.');
    const { usages } = sharedUsages(row.id);
    if (request.expected_link_ids) {
      const current = usages.map((usage) => usage.link_id).sort();
      const expected = [...request.expected_link_ids].sort();
      if (expected.length !== current.length || expected.some((id, i) => id !== current[i]))
        fail(
          'LinkSetChanged',
          'Linked projects changed while you were reviewing them.',
          'Refresh and confirm again.',
        );
    }
    if (usages.length && !request.unlink_all)
      fail(
        'LinkedSecretInUse',
        'Projects are linked to this secret.',
        'Review and unlink all usages.',
      );
    const confirmation = unlinkAllConfirmation(usages, row.name);
    if (confirmation && request.confirmation !== confirmation)
      fail(
        'ConfirmationFailed',
        'Confirm linked dangerous environments.',
        'Enter the requested name.',
      );
    for (const usage of usages) {
      const index = links.findIndex((link) => link.link_id === usage.link_id);
      links.splice(index, 1);
    }
    removeSecret(row);
    return {
      secret_name: row.name,
      source: row.source,
      version: row.current_version,
      deleted: true,
      ...(usages.length && { unlinked_count: usages.length }),
    };
  }

  function copyToShared(
    request: DesktopCopySecretToSharedRequest,
  ): DesktopCopySecretToSharedResponse {
    requireUnlocked();
    const target = sharedProject();
    if (!unlockedProjects.has(target.project_id))
      fail(
        'UnlockRequired',
        'Unlock the Global Vault before copying the secret.',
        'Open Global Vault and unlock it.',
      );
    requireProfileConfirmation(request.from_profile_id, request.confirmation);
    requireProfileConfirmation(target.profile_id, request.confirmation);
    const source = secrets
      .filter(
        (row) =>
          row.profile_id === request.from_profile_id &&
          row.name === request.secret_name &&
          (request.source === undefined || row.source === request.source),
      )
      .sort((left, right) => right.source_precedence - left.source_precedence)[0];
    if (!source) fail('SecretNotFound', 'The secret was not found.', 'Refresh the secret list.');
    const targetName = request.target_name ?? source.name;
    const existing = findSharedSecret(targetName);
    const reuse = Boolean(
      existing && request.replace_with_link && dedupKey(existing) === dedupKey(source),
    );
    if (existing && !request.overwrite && !reuse)
      fail(
        'SecretAlreadyExists',
        'The secret already exists in Global Vault.',
        'Review the existing secret in Global Vault.',
      );
    const matching = secrets.filter((row) => row !== source && dedupKey(row) === dedupKey(source));
    if (!reuse) {
      const saved = saveSecret(
        {
          project_id: target.project_id,
          profile_id: target.profile_id,
          secret_name: targetName,
          source: 'user-local',
          value: values.get(source.id) ?? 'preview-only-value',
        },
        Boolean(existing),
      );
      const fixture = fixtureGroups.get(source.id);
      if (fixture) fixtureGroups.set(saved.secret_id, fixture);
    }
    const targetSecret = findSharedSecret(targetName)!;
    if (request.replace_with_link) {
      linkToTarget(source.profile_id, source.name, targetSecret);
      if (source.source === 'user-local') removeSecret(source);
    }
    let consolidated = 0;
    let skipped = 0;
    if (request.consolidate_duplicates) {
      for (const row of matching) {
        const profile = profiles.get(row.profile_id);
        if (!profile || row.source !== 'user-local' || profile.project === target.project_id)
          continue;
        if (!unlockedProjects.has(profile.project) || profile.dangerous) {
          skipped++;
          continue;
        }
        linkToTarget(row.profile_id, row.name, targetSecret);
        removeSecret(row);
        consolidated++;
      }
    }
    return {
      target_project_id: target.project_id,
      target_profile_id: target.profile_id,
      secret_name: targetName,
      version: targetSecret.current_version,
      action: reuse ? 'reuse' : existing ? 'rotate' : 'create',
      ...(request.replace_with_link && { linked: true }),
      ...(consolidated && { consolidated_count: consolidated }),
      ...(skipped && { skipped_locked_count: skipped }),
    };
  }

  function importEnv(request: DesktopImportEnvRequest): DesktopImportEnvResponse {
    requireUnlocked();
    const project = requireSelectedProject();
    const existing = (name: string) =>
      secrets.find(
        (row) =>
          row.profile_id === project.profile_id && row.name === name && row.source === 'user-local',
      );
    const fixtures = [
      { name: 'REDIS_URL', fixture: undefined },
      { name: 'MAIL_TOKEN', fixture: 'email' },
      { name: 'ERROR_TRACKING_DSN', fixture: 'monitoring' },
    ];
    const matches: ImportDuplicateMatch[] = [];
    let imported = 0;
    let overwritten = 0;
    let skipped = 0;
    let linked = 0;
    let promoted = 0;
    if (!request.dry_run) requireProfileConfirmation(project.profile_id, request.confirmation);
    if (
      !request.dry_run &&
      !project.is_shared &&
      Object.keys(request.promote_to_shared ?? {}).length
    ) {
      const shared = sharedProject();
      if (!unlockedProjects.has(shared.project_id))
        fail(
          'UnlockRequired',
          'Unlock the Global Vault before promoting.',
          'Open Global Vault and unlock it.',
        );
      if (
        profiles.get(shared.profile_id)?.dangerous &&
        (request.target_confirmation ?? request.confirmation) !== 'default'
      )
        fail(
          'ConfirmationFailed',
          'Type default to confirm promotion into the Global Vault.',
          'Enter the requested name.',
        );
    }
    for (const { name, fixture } of fixtures) {
      for (const row of secrets.filter((row) => fixture && fixtureGroups.get(row.id) === fixture)) {
        const profile = profiles.get(row.profile_id);
        const match = projects.find((entry) => entry.project_id === profile?.project);
        if (!profile || !match || (row.profile_id === project.profile_id && row.name === name))
          continue;
        matches.push({
          local_name: name,
          match_kind: match.is_shared ? 'shared' : 'project',
          matched_project_id: match.project_id,
          matched_project_name: match.project_name,
          matched_profile_name: profile.name,
          matched_secret_id: row.id,
          matched_secret_name: row.name,
          is_shared: match.is_shared === true,
        });
      }
      const linkName = !project.is_shared && request.link_to_shared?.[name];
      const promoteName = !project.is_shared && request.promote_to_shared?.[name];
      const useShared = !request.dry_run && (linkName || promoteName);
      if (useShared) {
        const shared = sharedProject();
        let target = findSharedSecret(useShared);
        if (!linkName && (!target || fixtureGroups.get(target.id) !== fixture)) {
          if (target && !request.overwrite)
            fail(
              'SecretAlreadyExists',
              'The secret already exists in Global Vault.',
              'Review the target name.',
            );
          const saved = saveSecret(
            {
              project_id: shared.project_id,
              profile_id: shared.profile_id,
              secret_name: useShared,
              value: 'preview-imported-value',
            },
            Boolean(target),
          );
          if (fixture) fixtureGroups.set(saved.secret_id, fixture);
          target = findSharedSecret(useShared);
        }
        if (!target)
          fail(
            'SecretNotFound',
            'The Global Vault secret was not found.',
            'Check the target name.',
          );
        linkToTarget(project.profile_id, name, target);
        if (linkName) linked++;
        else promoted++;
        continue;
      }
      const previous = existing(name);
      if (previous && !request.overwrite) {
        skipped++;
        continue;
      }
      if (previous) overwritten++;
      else imported++;
      if (!request.dry_run) {
        const saved = saveSecret(
          {
            project_id: project.project_id,
            profile_id: project.profile_id,
            secret_name: name,
            value: 'preview-imported-value',
          },
          Boolean(previous),
        );
        if (fixture) fixtureGroups.set(saved.secret_id, fixture);
      }
    }
    return {
      summary: `Imported ${imported}, linked ${linked}, promoted ${promoted}, overwritten ${overwritten}, skipped ${skipped}. Original file preserved.`,
      imported,
      overwritten,
      skipped,
      linked,
      promoted,
      duplicate_matches: matches,
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
    if (unlockTtl() === null)
      fail('UnlockRequired', 'The vault is locked.', 'Unlock the vault and retry.');
  }
  function requireSelectedProject(): DesktopProjectContext {
    if (!selected) fail('ProjectNotFound', 'No vault is open.', 'Open a vault or project first.');
    return selected;
  }

  return async (command: string, args: Record<string, unknown>): Promise<unknown> => {
    if (command === routeCommands[startView]) {
      if (scenario === 'loading') return noResponse;
    }
    // Variables exercise a metadata failure after a successful status response.
    // Other error routes simulate a disconnected agent from startup.
    const failureCommand = startView === 'secrets' ? 'agent_list_secrets' : 'agent_status';
    if (showFailure && command === failureCommand) {
      fail('AgentUnavailable', 'The Locket agent is offline.', 'Start the agent, then retry.');
    }
    const request = (args.request ?? {}) as Record<string, unknown>;
    const unlocked = unlockTtl() !== null;
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
      case 'desktop_open_shared_vault': {
        let shared = projects.find((entry) => entry.is_shared);
        if (!shared) {
          shared = {
            root: '',
            project_id: 'lk_proj_shared_preview',
            project_name: '@shared',
            profile_id: 'shared-default',
            profile_name: 'default',
            is_shared: true,
          };
          projects.unshift(shared);
        }
        selected = shared;
        return { ...selected };
      }
      case 'desktop_inspect_project_folder': {
        const path = typeof request.path === 'string' ? request.path : '';
        const hasConfig = projects.some((entry) => !entry.is_shared && entry.root === path);
        return {
          path,
          has_config: hasConfig,
          folder_name: path.split('/').filter(Boolean).pop() || path || 'project',
        };
      }
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
            is_shared: false,
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
        const profile = selected ? profiles.get(selected.profile_id) : undefined;
        if (profile && typeof changes.dangerous_profile === 'boolean')
          profile.dangerous = changes.dangerous_profile;
        return {
          settings: readSettings(request.project_id, request.profile_name),
          changed_keys: Object.keys(changes),
        };
      }
      case 'agent_lock':
        unlockedProjects.clear();
        return;
      case 'agent_unlock': {
        const { project_id, ttl_seconds } = request as unknown as UnlockRequest;
        unlockedProjects.set(project_id, ttl_seconds);
        return;
      }
      case 'desktop_create_profile':
        return createProfile(request as unknown as DesktopCreateProfileRequest);
      case 'desktop_delete_secret':
        return deleteSecret(request as unknown as DesktopDeleteSecretRequest);
      case 'desktop_copy_secret_to_shared':
        return copyToShared(request as unknown as DesktopCopySecretToSharedRequest);
      case 'desktop_link_secret':
        return linkSecret(request as unknown as DesktopLinkSecretRequest);
      case 'desktop_unlink_secret':
        return unlinkSecret(request as unknown as DesktopUnlinkSecretRequest);
      case 'desktop_list_shared_usages':
        return sharedUsages(String(request.target_secret_id), redact);
      case 'desktop_list_duplicates':
        return duplicates(redact);
      case 'agent_set_active_profile': {
        requireUnlocked();
        const project = requireSelectedProject();
        const entry = [...profiles].find(
          ([, profile]) =>
            profile.project === project.project_id && profile.name === request.profile_name,
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
        const previous = { ...project };
        project.profile_id = id;
        project.profile_name = profile.name;
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
      case 'agent_list_secrets': {
        const rows: SecretWireRow[] = projectSecrets.map((row) => ({
          ...row,
          link_count: links.filter((link) => link.target_secret_id === row.id).length,
        }));
        for (const link of links.filter((link) => link.profile_id === request.profile_id)) {
          const target = secrets.find((row) => row.id === link.target_secret_id);
          if (!target) continue;
          rows.push({
            ...target,
            id: link.link_id,
            profile_id: link.profile_id,
            name: link.local_name,
            source: 'shared-link',
            source_precedence: precedence['shared-link'],
            origin: 'shared-link',
            linked_target_name: target.name,
            linked_target_secret_id: target.id,
            created_at: link.created_at,
            link_count: 0,
          });
        }
        return {
          rows: rows.map((row, index) =>
            redact
              ? {
                  ...row,
                  name: `Variable ${index + 1}`,
                  owner: undefined,
                  tags: [],
                  linked_target_name: row.linked_target_name ? 'Shared variable' : undefined,
                }
              : row,
          ),
        };
      }
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
        requireDangerousConfirmation(request);
        return saveSecret(request as unknown as SetSecretRequest, false);
      case 'agent_rotate_secret':
        requireDangerousConfirmation(request);
        return saveSecret(request as unknown as SetSecretRequest, true);
      case 'agent_reveal': {
        requireUnlocked();
        requireDangerousConfirmation(request);
        const visibleLink = links.find(
          (entry) => entry.link_id === request.secret_id && entry.profile_id === request.profile_id,
        );
        const name = request.secret_id
          ? (projectSecrets.find((secret) => secret.id === request.secret_id)?.name ??
            visibleLink?.local_name)
          : request.secret_name;
        const row = projectSecrets
          .filter((secret) => secret.name === name)
          .sort((left, right) => right.source_precedence - left.source_precedence)[0];
        const link = links.find(
          (entry) => entry.profile_id === request.profile_id && entry.local_name === name,
        );
        const effectiveId =
          link && (!row || row.source_precedence < precedence['shared-link'])
            ? link.target_secret_id
            : row?.id;
        if (!effectiveId)
          fail('SecretNotFound', 'The secret was not found.', 'Refresh the secret list.');
        return {
          value: values.get(effectiveId) ?? 'preview-only-value',
          ttl_seconds: 20,
        };
      }
      case 'agent_copy_secret':
        requireUnlocked();
        requireDangerousConfirmation(request);
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
        return selected?.root || `${workspace}/acme-api`;
      case 'desktop_pick_file':
        return args.save
          ? `/Users/justin/Downloads/${args.defaultName ?? 'locket-backup.lkb'}`
          : args.title === 'Browse for an env file'
            ? `${selected?.root || '/Users/justin/Downloads'}/.env`
            : '/Users/justin/Downloads/locket-backup.lkb';
      case 'desktop_mcp_config_snippet':
        return { ...mcp, json: JSON.stringify({ mcpServers: { locket: mcp } }, null, 2) };
      case 'desktop_import_env':
        return importEnv(request as unknown as DesktopImportEnvRequest);
      case 'desktop_run_policy':
        return { launched: true, command: `locket run ${request.policy_name}` };
      case 'desktop_scan_project':
        return { launched: true, command: 'locket scan --require-known' };
      case 'desktop_detect_commands':
        return request.project_id === 'acme-api'
          ? ['dev', 'test', 'lint', 'build'].map((name): DetectedCommandRow => {
              const argv = ['pnpm', 'run', name];
              const command_preview = argv.join(' ');
              return {
                name,
                argv,
                command_preview,
                source_file: 'package.json',
                already_configured: policies.some(
                  (policy) =>
                    policy.name === name ||
                    (policy.command_kind === 'argv' && policy.command_preview === command_preview),
                ),
              };
            })
          : [];
      case 'desktop_save_policy': {
        const { policy, mode, original_name } = request as unknown as DesktopSavePolicyRequest;
        const index = policies.findIndex((row) => row.name === original_name);
        if (index >= 0) policies.splice(index, 1);
        if (mode !== 'delete')
          policies.push({ ...policy, id: `policy-new-${++sequence}`, updated_at_unix_nanos: now });
        return;
      }
      case 'desktop_variable_readiness': {
        const project = requireSelectedProject();
        return {
          project_id: project.project_id,
          profile_id: project.profile_id,
          profile_name: project.profile_name,
          policies: policies.map((policy) => ({
            policy_name: policy.name,
            profile_id: project.profile_id,
            rows: secrets
              .filter((row) => row.profile_id === project.profile_id)
              .map((row) => ({
                name: row.name,
                required: row.required,
                classification: 'secret',
                state: unlocked ? 'ready' : 'unverified',
                selected_source: row.source,
              })),
          })),
        };
      }
      case 'desktop_team_sync_configure': {
        requireDangerousConfirmation(request, false, request.allow_dangerous === true);
        const projectId = String(request.project_id);
        const transport = (request.transport ?? {
          kind: 'folder',
          path: String(request.folder ?? ''),
        }) as TeamSyncTransportInput;
        teamDeliveries.set(projectId, deliveryMetadata(transport));
        return syncStatus(projectId);
      }
      case 'desktop_team_sync_clear': {
        requireDangerousConfirmation(request);
        const projectId = String(request.project_id);
        teamDeliveries.set(projectId, null);
        return syncStatus(projectId);
      }
      case 'desktop_team_sync_test_remote': {
        requireDangerousConfirmation(request);
        const delivery = request.transport
          ? deliveryMetadata(request.transport as TeamSyncTransportInput)
          : teamDelivery(String(request.project_id));
        if (!delivery)
          fail(
            'TeamSyncRejected',
            'No delivery backend configured.',
            'Save a delivery backend and retry.',
          );
        const target =
          delivery.transport_kind === 'folder' ? delivery.folder : delivery.remote_target;
        const ok = scenario !== 'team-connection-error';
        return {
          ok,
          transport_kind: delivery.transport_kind,
          target,
          package_count: ok ? 3 : 0,
          writable_checked: false,
          message: ok
            ? 'Connection succeeded.'
            : 'Could not list encrypted packages at the delivery target.',
        } satisfies TeamSyncTestResult;
      }
      case 'desktop_team_sync_now':
      case 'desktop_team_sync_rename_profile':
      case 'desktop_team_sync_preserve_override':
        requireDangerousConfirmation(request);
        return syncStatus(String(request.project_id));
      case 'desktop_team_sync_status':
        return syncStatus(String(request.project_id));
      case 'agent_export_bundle':
        requireDangerousConfirmation(request, request.scope === 'all-profiles');
        return {
          action: 'export',
          status: request.preview_only ? 'preview' : 'ok',
          message: request.preview_only
            ? '6 variables and 1 environment selected.'
            : 'Sealed bundle exported.',
        };
      case 'agent_import_bundle':
        requireDangerousConfirmation(request, true);
        return { action: 'import', status: 'ok', message: 'Sealed bundle imported.' };
      case 'agent_verify_bundle':
        return {
          structural_valid: true,
          schema_version: 1,
          project_id: requireSelectedProject().project_id,
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

  function teamDelivery(projectId: string): TeamDelivery | null {
    const delivery = teamDeliveries.get(projectId);
    return delivery === undefined
      ? { transport_kind: 'folder', folder: `${workspace}/${projectId}/.locket/team` }
      : delivery;
  }

  function deliveryMetadata(transport: TeamSyncTransportInput): TeamDelivery {
    const invalid = (message: string): never =>
      fail('InvalidTransport', message, 'Check the delivery backend settings and retry.');
    switch (transport.kind) {
      case 'folder':
        if (!transport.path?.trim()) invalid('Enter a shared folder path.');
        return { transport_kind: 'folder', folder: transport.path.trim() };
      case 's3': {
        if (!transport.bucket?.trim() || !transport.region?.trim())
          invalid('Enter an S3 bucket and region.');
        if (transport.endpoint && !validDeliveryUrl(transport.endpoint, true))
          invalid('Enter a valid S3 endpoint URL without credentials.');
        if (
          transport.credential_mode === 'vault' &&
          (!transport.access_key_id || !transport.secret_access_key)
        )
          invalid('Enter the S3 access key ID and secret access key.');
        const prefix = transport.prefix?.trim().replace(/^\/+|\/+$/g, '');
        return {
          transport_kind: 's3',
          folder: null,
          remote_target: `s3://${transport.bucket.trim()}${prefix ? `/${prefix}` : ''}`,
          remote_endpoint: transport.endpoint,
          remote_region: transport.region.trim(),
          credential_mode: transport.credential_mode,
        };
      }
      case 'webdav': {
        if (!validDeliveryUrl(transport.url))
          invalid('Enter a valid WebDAV HTTPS URL without credentials.');
        const auth = transport.auth_kind ?? 'none';
        if (
          (auth === 'none') !== (transport.credential_mode === 'none') ||
          (transport.credential_mode === 'vault' &&
            (!transport.secret || (auth === 'basic' && !transport.username)))
        )
          invalid('Check the WebDAV authentication settings.');
        return {
          transport_kind: 'webdav',
          folder: null,
          remote_target: transport.url.trim(),
          credential_mode: transport.credential_mode,
        };
      }
    }
  }

  function syncStatus(projectId: string): TeamSyncStatus {
    return {
      epoch: 3,
      state: unlockedProjects.has(projectId) ? 'verified' : 'locked',
      conflicts: 0,
      waiting: 0,
      waiting_known: true,
      last_verified_at: now - minute,
      published: 0,
      applied: 2,
      ...teamDelivery(projectId),
    };
  }
}

function matchesGlob(name: string, glob: string): boolean {
  const literal = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${literal.replaceAll('*', '.*').replaceAll('?', '.')}$`, 'i').test(name);
}
