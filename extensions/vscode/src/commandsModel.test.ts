import * as fs from 'node:fs';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClientError } from './agentClient';
import {
  LOCKET_COMMAND_ROUTES,
  agentErrorMessage,
  buildDirectoryGrantPayload,
  buildListAuditRequest,
  buildListPoliciesRequest,
  buildLockRequest,
  buildPrepareExecRequest,
  buildRegisterIdeEnvSessionPayload,
  buildSetActiveProfileRequest,
  buildUnlockRequest,
  policyAllowList,
  uuidV4FromBytes,
} from './commandsModel';

test('lock request always reports the desktop session-lock source', () => {
  assert.deepEqual(buildLockRequest(), { source: 'desktop' });
});

test('switch profile request trims fields and uses agent payload shape', () => {
  assert.deepEqual(
    buildSetActiveProfileRequest(
      ' /tmp/locket.toml ',
      ' /tmp/store.db ',
      ' lk_proj_a ',
      ' dev ',
    ),
    {
      config_path: '/tmp/locket.toml',
      store_path: '/tmp/store.db',
      project_id: 'lk_proj_a',
      profile_name: 'dev',
      privacy_redact_names: false,
    },
  );
});

test('switch profile request rejects blank fields', () => {
  assert.throws(
    () => buildSetActiveProfileRequest('', '/tmp/store.db', 'lk_proj_a', 'dev'),
    /config path is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '', 'lk_proj_a', 'dev'),
    /store path is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '/tmp/store.db', '', 'dev'),
    /project id is required/u,
  );
  assert.throws(
    () => buildSetActiveProfileRequest('/tmp/locket.toml', '/tmp/store.db', 'lk_proj_a', ''),
    /profile name is required/u,
  );
});

test('list policies request requires a project id', () => {
  assert.deepEqual(buildListPoliciesRequest(' lk_proj_a '), {
    project_id: 'lk_proj_a',
    privacy_redact_names: false,
  });
  assert.throws(() => buildListPoliciesRequest(''), /project id is required/u);
});

test('prepare exec request includes project id, profile id, and policy name', () => {
  assert.deepEqual(buildPrepareExecRequest(' lk_proj_a ', ' prof-dev ', ' deploy '), {
    project_id: 'lk_proj_a',
    profile_id: 'prof-dev',
    policy_name: 'deploy',
  });
  assert.throws(() => buildPrepareExecRequest('', 'prof-dev', 'deploy'), /project id is required/u);
  assert.throws(() => buildPrepareExecRequest('lk_proj_a', '', 'deploy'), /profile id is required/u);
  assert.throws(() => buildPrepareExecRequest('lk_proj_a', 'prof-dev', ''), /policy name is required/u);
});

test('list audit request bounds the limit and trims fields', () => {
  const request = buildListAuditRequest(' /tmp/store.db ', ' lk_proj_a ');
  assert.equal(request.store_path, '/tmp/store.db');
  assert.equal(request.project_id, 'lk_proj_a');
  assert.equal(request.limit, 200);
  assert.equal(request.redact_names, false);
});

test('list audit request rejects blank required fields', () => {
  assert.throws(() => buildListAuditRequest('', 'lk_proj_a'), /store path is required/u);
  assert.throws(() => buildListAuditRequest('/tmp/store.db', ''), /project id is required/u);
});

test('command routing table covers every spec command and uses unique ids', () => {
  const expected = [
    { commandId: 'locket.unlock', agentMethod: 'Unlock' },
    { commandId: 'locket.lock', agentMethod: 'Lock' },
    { commandId: 'locket.switchProfile', agentMethod: 'SetActiveProfile' },
    { commandId: 'locket.runPolicy', agentMethod: 'ListPolicies' },
    { commandId: 'locket.openAuditView', agentMethod: 'ListAudit' },
  ];
  assert.deepEqual([...LOCKET_COMMAND_ROUTES], expected);

  const ids = LOCKET_COMMAND_ROUTES.map((row) => row.commandId);
  assert.equal(new Set(ids).size, ids.length, 'command ids must be unique');
});

test('package.json declares every routed command id and lists them in the palette', () => {
  // Compiled tests live in `out/`; the manifest is one level up.
  const manifestPath = path.resolve(__dirname, '..', 'package.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    contributes?: {
      commands?: ReadonlyArray<{ command: string; title?: string; category?: string }>;
      menus?: { commandPalette?: ReadonlyArray<{ command: string; when?: string }> };
    };
  };
  const declared = new Set(
    (manifest.contributes?.commands ?? []).map((entry) => entry.command),
  );
  const palette = new Set(
    (manifest.contributes?.menus?.commandPalette ?? []).map((entry) => entry.command),
  );
  for (const route of LOCKET_COMMAND_ROUTES) {
    assert.ok(
      declared.has(route.commandId),
      `package.json missing contributes.commands entry for ${route.commandId}`,
    );
    assert.ok(
      palette.has(route.commandId),
      `package.json missing commandPalette entry for ${route.commandId}`,
    );
  }
});

test('unlock request defaults to passphrase: null with audit metadata', () => {
  const request = buildUnlockRequest('lk_proj_demo', '/tmp/store.db', 'prof-dev', null);
  assert.equal(request.project_id, 'lk_proj_demo');
  assert.equal(request.passphrase, null);
  assert.equal(request.ttl_seconds, 1800);
  assert.deepEqual(request.audit, { store_path: '/tmp/store.db', profile_id: 'prof-dev' });
});

test('unlock request retries with the supplied passphrase', () => {
  const request = buildUnlockRequest('lk_proj_demo', '/tmp/store.db', null, 'open-sesame');
  assert.equal(request.passphrase, 'open-sesame');
  assert.equal(request.audit.profile_id, null);
});

test('unlock request rejects blank required fields', () => {
  assert.throws(() => buildUnlockRequest('', '/tmp/store.db', null, null), /project id is required/u);
  assert.throws(() => buildUnlockRequest('lk_proj_demo', '', null, null), /store path is required/u);
});

test('directory grant payload binds to the host process and defaults TTL', () => {
  const payload = buildDirectoryGrantPayload({
    projectId: 'lk_proj_demo',
    profileId: 'prof-dev',
    pid: 4242,
    processStartTime: 'token',
  });
  assert.equal(payload.action, 'ResolveReference');
  assert.equal(payload.ttl_seconds, 1800);
  assert.deepEqual(payload.binding, { pid: 4242, process_start_time: 'token' });
});

test('register ide env-session payload preserves env-name order', () => {
  const payload = buildRegisterIdeEnvSessionPayload({
    sessionId: 'session-uuid',
    projectId: 'lk_proj_demo',
    storePath: '/tmp/store.db',
    profileId: 'prof-dev',
    envNames: ['DATABASE_URL', 'REDIS_URL'],
  });
  assert.equal(payload.session_id, 'session-uuid');
  assert.deepEqual(payload.env_names, ['DATABASE_URL', 'REDIS_URL']);
  assert.equal(payload.ttl_seconds, 1800);
});

test('policy allow-list dedupes order-preserved across rows', () => {
  const names = policyAllowList({
    rows: [
      { allowed_secrets: ['DATABASE_URL', 'REDIS_URL'] },
      { allowed_secrets: ['REDIS_URL', 'API_KEY'] },
      { required_secrets: ['API_KEY'], optional_secrets: ['EXTRA'] },
      { allowed_secrets: ['', 'EXTRA'] },
      {},
    ],
  });
  assert.deepEqual([...names], ['DATABASE_URL', 'REDIS_URL', 'API_KEY', 'EXTRA']);
});

test('uuidV4FromBytes formats version and variant bits', () => {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    bytes[i] = i;
  }
  const id = uuidV4FromBytes(bytes);
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.throws(() => uuidV4FromBytes(bytes.subarray(1)), /requires at least 16 bytes/u);
});

test('agent error message uses typed display copy when available', () => {
  const unlockRequired = AgentClientError.agent({
    error: 'UnlockRequired',
    message: 'unlock required',
    retryable: false,
  });
  assert.equal(
    agentErrorMessage(unlockRequired),
    'The vault is locked. Run locket unlock or approve an agent unlock prompt.',
  );

  assert.equal(
    agentErrorMessage(AgentClientError.unavailable('socket gone')),
    'The local agent is unavailable. Run locket agent start, then retry.',
  );

  assert.equal(
    agentErrorMessage(AgentClientError.protocol('bad frame')),
    'Locket agent protocol error: bad frame',
  );

  assert.equal(agentErrorMessage('not an error object'), 'Locket command failed.');
});
