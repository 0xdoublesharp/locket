import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, AgentMethod, RequestEnvelope } from './agentClient';
import { ResolvedLocketProject } from './commandsModel';
import {
  LOCKET_IDE_ENV_SESSION_VARIABLE,
  applyIdeEnvSessionToTerminals,
  clearIdeEnvSessionFromTerminals,
  registerIdeEnvSessionWithAgent,
} from './ideEnvSession';

const PROJECT: ResolvedLocketProject = {
  root: '/workspace/demo',
  projectId: 'lk_proj_demo',
  defaultProfileId: 'prof-dev',
};

test('registerIdeEnvSessionWithAgent posts ListPolicies then RegisterIdeEnvSession', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request);
      if (request.kind === 'ListPolicies') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              rows: [
                {
                  id: 'policy-1',
                  name: 'deploy',
                  allowed_secrets: ['DATABASE_URL'],
                  required_secrets: ['DATABASE_URL'],
                  optional_secrets: [],
                },
                {
                  id: 'policy-2',
                  name: 'run-app',
                  allowed_secrets: ['REDIS_URL', 'API_KEY'],
                  required_secrets: ['REDIS_URL'],
                  optional_secrets: ['API_KEY'],
                },
              ],
            },
          }),
        );
        return;
      }
      if (request.kind === 'RegisterIdeEnvSession') {
        socket.end(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: { session_id: 'session-uuid', ttl_seconds: 1800 },
          }),
        );
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const result = await registerIdeEnvSessionWithAgent({
      agentClient: client,
      project: PROJECT,
      storePath: '/tmp/store.db',
      sessionIdFactory: () => 'session-uuid',
    });
    assert.notEqual(result, undefined);
    const session = required(result, 'expected IDE environment session');
    assert.equal(session.sessionId, 'session-uuid');
    assert.deepEqual(session.envNames, ['DATABASE_URL', 'REDIS_URL', 'API_KEY']);

    // Two requests observed in order.
    assert.equal(observed.length, 2);
    const listPoliciesRequest = requiredAt(observed, 0);
    const registerRequest = requiredAt(observed, 1);
    assert.equal(listPoliciesRequest.kind, 'ListPolicies');
    assert.deepEqual(listPoliciesRequest.payload, {
      project_id: 'lk_proj_demo',
      privacy_redact_names: false,
    });
    assert.equal(registerRequest.kind, 'RegisterIdeEnvSession');
    const body = registerRequest.payload as Record<string, unknown>;
    assert.equal(body.session_id, 'session-uuid');
    assert.equal(body.project_id, 'lk_proj_demo');
    assert.equal(body.store_path, '/tmp/store.db');
    assert.equal(body.profile_id, 'prof-dev');
    assert.deepEqual(body.env_names, ['DATABASE_URL', 'REDIS_URL', 'API_KEY']);
    assert.equal(body.ttl_seconds, 1800);
  } finally {
    server.close();
    await cleanup();
  }
});

test('registerIdeEnvSessionWithAgent skips when ListPolicies returns no rows', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  let registerCalls = 0;
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      if (request.kind === 'ListPolicies') {
        socket.end(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: { rows: [] },
          }),
        );
        return;
      }
      registerCalls += 1;
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: { ttl_seconds: 1800 },
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const result = await registerIdeEnvSessionWithAgent({
      agentClient: client,
      project: PROJECT,
      storePath: '/tmp/store.db',
      sessionIdFactory: () => 'session-uuid',
    });
    assert.equal(result, undefined);
    assert.equal(registerCalls, 0);
  } finally {
    server.close();
    await cleanup();
  }
});

test('registerIdeEnvSessionWithAgent returns undefined if agent rejects', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      if (request.kind === 'ListPolicies') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              rows: [{ id: 'policy-1', name: 'deploy', allowed_secrets: ['A'] }],
            },
          }),
        );
        return;
      }
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: false,
          error: 'AgentUnavailable',
          message: 'agent down',
          retryable: true,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const result = await registerIdeEnvSessionWithAgent({
      agentClient: client,
      project: PROJECT,
      storePath: '/tmp/store.db',
      sessionIdFactory: () => 'session-uuid',
    });
    assert.equal(result, undefined);
  } finally {
    server.close();
    await cleanup();
  }
});

test('applyIdeEnvSessionToTerminals replaces and clears LOCKET_IDE_ENV_SESSION', () => {
  const calls: Array<['replace', string, string] | ['delete', string]> = [];
  const collection = {
    replace: (name: string, value: string): void => {
      calls.push(['replace', name, value]);
    },
    delete: (name: string): void => {
      calls.push(['delete', name]);
    },
  };
  applyIdeEnvSessionToTerminals(collection, 'session-uuid');
  clearIdeEnvSessionFromTerminals(collection);
  assert.deepEqual(calls, [
    ['replace', LOCKET_IDE_ENV_SESSION_VARIABLE, 'session-uuid'],
    ['delete', LOCKET_IDE_ENV_SESSION_VARIABLE],
  ]);
});

test('session registration is best-effort when either operation fails unexpectedly', async (t) => {
  const agentClient = new AgentClient({ socketPath: 'fixture' });
  let listAvailable = false;
  const invoke = t.mock.method(agentClient, 'invoke', async (method: AgentMethod) => {
    if (listAvailable && method === 'ListPolicies') { return { rows: [{ allowed_secrets: ['API_KEY'] }] }; }
    throw new Error('connection lost');
  });
  const deps = { agentClient, project: PROJECT, storePath: '/fixture/store.db' };
  assert.equal(await registerIdeEnvSessionWithAgent(deps), undefined);
  assert.deepEqual(invoke.mock.calls.map(({ arguments: args }) => args[0]), ['ListPolicies']);

  listAvailable = true;
  assert.equal(await registerIdeEnvSessionWithAgent(deps), undefined);
  assert.deepEqual(invoke.mock.calls.map(({ arguments: args }) => args[0]), [
    'ListPolicies', 'ListPolicies', 'RegisterIdeEnvSession',
  ]);
});

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-ide-'));
  return {
    socketPath: path.join(directory, 'agent.sock'),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

function listen(server: net.Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function decodeRequest(frame: Buffer): RequestEnvelope {
  const length = frame.readUInt32LE(0);
  return JSON.parse(frame.subarray(4, 4 + length).toString('utf8')) as RequestEnvelope;
}

function encodeResponse(response: object): Buffer {
  const payload = Buffer.from(JSON.stringify(response), 'utf8');
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function required<T>(value: T | undefined, message: string): T {
  if (value === undefined) {
    assert.fail(message);
  }
  return value;
}

function requiredAt<T>(values: ReadonlyArray<T>, index: number): T {
  const value = values[index];
  if (value === undefined) {
    assert.fail(`expected value at index ${index.toString()}`);
  }
  return value;
}
