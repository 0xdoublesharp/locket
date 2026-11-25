import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, AgentClientError, RequestEnvelope } from './agentClient';
import { ResolvedLocketProject } from './commandsModel';
import { LOCKET_IDE_ENV_SESSION_VARIABLE } from './ideEnvSession';
import { WarnOnceLatch } from './terminalAutobindModel';
import {
  TerminalAutobindHandlerDeps,
  handleOpenTerminal,
  requestDirectoryGrant,
} from './terminalAutobindHandler';

const PROJECT: ResolvedLocketProject = {
  root: '/workspace/demo',
  projectId: 'lk_proj_demo',
  defaultProfileId: 'prof-dev',
};

test('handleOpenTerminal returns a names-only session and fires a RequestGrant without global injection', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  const grantBarrier = createBarrier();
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
                  id: 'p1',
                  name: 'deploy',
                  allowed_secrets: ['DATABASE_URL'],
                },
              ],
            },
          }),
        );
        return;
      }
      if (request.kind === 'RegisterIdeEnvSession') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: { session_id: 'session-uuid', ttl_seconds: 1800 },
          }),
        );
        return;
      }
      if (request.kind === 'RequestGrant') {
        socket.end(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              grant_id: 'lk_grant_test',
              ttl_seconds: 1800,
              expires_at_unix_nanos: 1,
            },
          }),
        );
        grantBarrier.resolve();
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const collectionMutations: Array<['replace', string, string]> = [];
    const warnings: string[] = [];
    const deps: TerminalAutobindHandlerDeps = {
      agentClient: client,
      environmentVariableCollection: {
        replace: (name, value) => collectionMutations.push(['replace', name, value]),
        delete: () => undefined,
      },
      autobindContext: {
        resolveProject: () => PROJECT,
        pid: 4242,
        processStartTime: 'start-token',
        ttlSeconds: 1800,
      },
      storePath: '/tmp/store.db',
      sessionIdFactory: () => 'session-uuid',
      notifyDirectoryGrantRejected: (reason) => warnings.push(reason),
      warnOnce: new WarnOnceLatch(),
    };

    const outcome = await handleOpenTerminal('/workspace/demo', deps);
    await grantBarrier.promise;

    assert.equal(outcome.applied, true);
    assert.equal(outcome.sessionId, 'session-uuid');
    assert.deepEqual(collectionMutations, []);
    const grantRequest = observed.find((r) => r.kind === 'RequestGrant');
    assert.notEqual(grantRequest, undefined);
    const body = required(grantRequest, 'expected RequestGrant payload').payload as Record<
      string,
      unknown
    >;
    assert.equal(body.action, 'ResolveReference');
    assert.equal(body.project_id, 'lk_proj_demo');
    assert.equal(body.profile_id, 'prof-dev');
    assert.deepEqual(body.binding, { pid: 4242, process_start_time: 'start-token' });
    assert.equal(warnings.length, 0);
  } finally {
    server.close();
    await cleanup();
  }
});

test('handleOpenTerminal returns applied:false outside a Locket project', async () => {
  const deps: TerminalAutobindHandlerDeps = {
    agentClient: new AgentClient({ socketPath: '/dev/null', connectTimeoutMs: 100 }),
    environmentVariableCollection: { replace: () => undefined, delete: () => undefined },
    autobindContext: {
      resolveProject: () => undefined,
      pid: 1,
      processStartTime: 'x',
    },
    storePath: '/tmp/store.db',
    notifyDirectoryGrantRejected: () => undefined,
    warnOnce: new WarnOnceLatch(),
  };
  const outcome = await handleOpenTerminal('/elsewhere', deps);
  assert.deepEqual(outcome, { applied: false });
});

test('requestDirectoryGrant fires a once-per-session warning on agent rejection', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: false,
          error: 'ProjectRootUntrusted',
          message: 'directory not trusted',
          retryable: false,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const warnings: string[] = [];
    const warnOnce = new WarnOnceLatch();
    const baseDeps: TerminalAutobindHandlerDeps = {
      agentClient: client,
      environmentVariableCollection: { replace: () => undefined, delete: () => undefined },
      autobindContext: {
        resolveProject: () => PROJECT,
        pid: 1,
        processStartTime: 'x',
      },
      storePath: '/tmp/store.db',
      notifyDirectoryGrantRejected: (reason) => warnings.push(reason),
      warnOnce,
    };
    const grantPayload = {
      project_id: PROJECT.projectId,
      profile_id: PROJECT.defaultProfileId,
      action: 'ResolveReference' as const,
      ttl_seconds: 60,
      binding: { pid: 1, process_start_time: 'x' },
    };

    await requestDirectoryGrant(baseDeps, grantPayload);
    await requestDirectoryGrant(baseDeps, grantPayload);
    await requestDirectoryGrant(baseDeps, grantPayload);

    assert.equal(warnings.length, 1);
    assert.match(requiredAt(warnings, 0), /not trusted/u);
  } finally {
    server.close();
    await cleanup();
  }
});

function createBarrier(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolveFn: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    resolveFn = resolve;
  });
  return { promise, resolve: () => resolveFn() };
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

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-autobind-'));
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

test('terminal outside a project clears stale global project authorization', async () => {
  const deleted:string[]=[];
  const deps:TerminalAutobindHandlerDeps={
    agentClient:new AgentClient({socketPath:'/dev/null',connectTimeoutMs:100}),
    environmentVariableCollection:{replace:()=>assert.fail('never set project sessions globally'),delete:(name)=>deleted.push(name)},
    autobindContext:{resolveProject:()=>undefined,pid:1,processStartTime:'fixture'},
    storePath:'/fixture/store.db',notifyDirectoryGrantRejected:()=>undefined,warnOnce:new WarnOnceLatch(),
  };
  assert.deepEqual(await handleOpenTerminal('/project-b',deps),{applied:false});
  assert.deepEqual(deleted,[LOCKET_IDE_ENV_SESSION_VARIABLE]);
});

test('async terminal resolution registers actual project/profile/store metadata without global injection', async()=>{
  const calls:Array<{method:string;payload:unknown}>=[];
  const deleted:string[]=[];
  const deps:TerminalAutobindHandlerDeps={
    agentClient:{invoke:async(method:string,payload:unknown)=>{calls.push({method,payload});return method==='ListPolicies'?{rows:[{allowed_secrets:['API_KEY']}]}:{};}} as unknown as AgentClient,
    environmentVariableCollection:{replace:()=>assert.fail('project sessions must stay per-terminal'),delete:(name)=>deleted.push(name)},
    autobindContext:{resolveProject:()=>undefined,pid:1,processStartTime:'fixture'},
    resolveProject:async()=>({...PROJECT,storePath:'/actual/context/store.db'}),
    storePath:'/wrong/legacy/store.db',sessionIdFactory:()=> 'project-session',
    notifyDirectoryGrantRejected:()=>undefined,warnOnce:new WarnOnceLatch(),
  };
  const outcome=await handleOpenTerminal('/workspace/demo',deps);
  assert.equal(outcome.sessionId,'project-session');
  assert.deepEqual(deleted,[LOCKET_IDE_ENV_SESSION_VARIABLE]);
  const registration=calls.find(call=>call.method==='RegisterIdeEnvSession')?.payload as Record<string,unknown>;
  assert.equal(registration.store_path,'/actual/context/store.db');
  assert.equal(registration.project_id,PROJECT.projectId);
  assert.equal(registration.profile_id,PROJECT.defaultProfileId);
});

test('terminal metadata failure clears stale global state and skips agent calls', async (t) => {
  const agentClient = new AgentClient({ socketPath: 'fixture' });
  const invoke = t.mock.method(agentClient, 'invoke', async () => assert.fail('unexpected RPC'));
  const deleteVariable = t.mock.fn();
  const deps: TerminalAutobindHandlerDeps = {
    agentClient,
    environmentVariableCollection: { replace: () => assert.fail('unexpected global update'), delete: deleteVariable },
    autobindContext: { resolveProject: () => assert.fail('unexpected fallback'), pid: 1, processStartTime: 'fixture' },
    resolveProject: async () => { throw new Error('metadata unavailable'); },
    storePath: '/fixture/store.db',
    notifyDirectoryGrantRejected: () => assert.fail('unexpected warning'),
    warnOnce: new WarnOnceLatch(),
  };
  assert.deepEqual(await handleOpenTerminal(PROJECT.root, deps), { applied: false });
  assert.equal(invoke.mock.callCount(), 0);
  assert.deepEqual(deleteVariable.mock.calls[0]?.arguments, [LOCKET_IDE_ENV_SESSION_VARIABLE]);
});

test('directory grant transport failures preserve the latch for agent denials', async (t) => {
  const agentClient = new AgentClient({ socketPath: 'fixture' });
  const invoke = t.mock.method(agentClient, 'invoke', async () => {
    throw AgentClientError.agent({ error: 'ProjectRootUntrusted', message: 'denied', retryable: false });
  });
  invoke.mock.mockImplementationOnce(async () => { throw new Error('unexpected transport error'); }, 0);
  invoke.mock.mockImplementationOnce(async () => { throw AgentClientError.unavailable('disconnected'); }, 1);
  const notify = t.mock.fn();
  const deps: TerminalAutobindHandlerDeps = {
    agentClient,
    environmentVariableCollection: { replace: () => undefined, delete: () => undefined },
    autobindContext: { resolveProject: () => PROJECT, pid: 1, processStartTime: 'fixture' },
    storePath: '/fixture/store.db', notifyDirectoryGrantRejected: notify, warnOnce: new WarnOnceLatch(),
  };
  const grant = {
    project_id: PROJECT.projectId, profile_id: PROJECT.defaultProfileId, action: 'ResolveReference' as const,
    ttl_seconds: 60, binding: { pid: 1, process_start_time: 'fixture' },
  };
  await requestDirectoryGrant(deps, grant);
  await requestDirectoryGrant(deps, grant);
  assert.equal(notify.mock.callCount(), 0);
  await requestDirectoryGrant(deps, grant);
  assert.equal(notify.mock.callCount(), 1);
});
