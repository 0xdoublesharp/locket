import childProcess from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';

import {
  AgentClient,
  AgentClientError,
  RequestEnvelope,
  displayCopyForAgentCode,
  encodeFrame,
  resolveAgentSocketPath,
} from './agentClient';

test('status round trips over the agent socket frame protocol', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      assert.equal(request.kind, 'Status');
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: {
            lock_state: 'locked',
            project_id: null,
            profile_name: null,
            live_grant_count: 0,
            agent_version: 'test-agent',
            unlock_ttl_seconds: null,
          },
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const status = await client.status();
    assert.equal(status.lock_state, 'locked');
    assert.equal(status.agent_version, 'test-agent');
    assert.equal(status.live_grant_count, 0);
  } finally {
    server.close();
    await cleanup();
  }
});

test('agent error envelopes become typed client errors', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: false,
          error: 'UnlockRequired',
          message: 'unlock required',
          retryable: false,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    await assert.rejects(
      () => client.invoke('Reveal', {}),
      (error: unknown) => {
        assert.ok(error instanceof AgentClientError);
        assert.equal(error.kind, 'agent');
        assert.equal(error.code, 'UnlockRequired');
        assert.equal(error.message, 'unlock required');
        assert.equal(error.displayReason, 'The vault is locked.');
        assert.equal(error.nextAction, 'Run locket unlock or approve an agent unlock prompt.');
        assert.equal(error.retryable, false);
        return true;
      },
    );
  } finally {
    server.close();
    await cleanup();
  }
});

test('typed display copy mirrors shared Locket error text', () => {
  assert.deepEqual(displayCopyForAgentCode('GrantRequired'), {
    reason: 'No live grant covers this action.',
    nextAction: 'Run locket allow or refresh the shell or editor grant.',
  });
  assert.deepEqual(displayCopyForAgentCode('AgentUnavailable'), {
    reason: 'The local agent is unavailable.',
    nextAction: 'Run locket agent start, then retry.',
  });
  assert.equal(displayCopyForAgentCode('ProtocolError'), undefined);

  const unavailable = AgentClientError.unavailable('socket missing');
  assert.equal(unavailable.displayReason, 'The local agent is unavailable.');
  assert.equal(unavailable.nextAction, 'Run locket agent start, then retry.');
});

test('status subscription streams status events until disposed', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  let sawDispose = false;
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      assert.equal(request.kind, 'SubscribeStatus');
      socket.write(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: {
            kind: 'status',
            sequence: 1,
            lock_state: 'unlocked',
            project_id: 'lk_proj_test',
            profile_name: 'dev',
            live_grant_count: 1,
            agent_version: 'test-agent',
            unlock_ttl_seconds: 60,
          },
        }),
      );
    });
    socket.once('close', () => {
      sawDispose = true;
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const event = await new Promise<{ sequence: number; lock_state: string }>((resolve, reject) => {
      client
        .subscribeStatus(
          (status) => resolve(status),
          (error) => reject(error),
        )
        .then((subscription) => {
          setTimeout(() => subscription.dispose(), 10);
        })
        .catch(reject);
    });
    assert.equal(event.sequence, 1);
    assert.equal(event.lock_state, 'unlocked');
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(sawDispose, true);
  } finally {
    server.close();
    await cleanup();
  }
});

test('socket path honors LOCKET_AGENT_SOCKET override', () => {
  assert.equal(resolveAgentSocketPath({ LOCKET_AGENT_SOCKET: '/tmp/locket-test.sock' }), '/tmp/locket-test.sock');
});

test('default socket follows the CLI platform data directory', () => {
  if (process.platform === 'darwin') {
    assert.equal(resolveAgentSocketPath({}), path.join(os.homedir(), 'Library', 'Application Support', 'locket', 'agent.sock'));
  } else if (process.platform === 'linux') {
    assert.equal(resolveAgentSocketPath({ XDG_RUNTIME_DIR: '/run/user/fixture' }), '/run/user/fixture/locket/agent.sock');
  } else if (process.platform === 'win32') {
    assert.match(resolveAgentSocketPath({}), /^\\\\\.\\pipe\\locket-agent-S-\d+(?:-\d+)+$/u);
  }
});

test('endpoint discovery matches CLI defaults on every supported platform', () => {
  const home = '/home/fixture';
  assert.equal(resolveAgentSocketPath({}, { platform: 'darwin', home }), `${home}/Library/Application Support/locket/agent.sock`);
  assert.equal(resolveAgentSocketPath({ XDG_RUNTIME_DIR: '/run/user/42' }, { platform: 'linux', home }), '/run/user/42/locket/agent.sock');
  assert.equal(resolveAgentSocketPath({}, { platform: 'linux', home }), `${home}/.locket/agent.sock`);
  assert.equal(resolveAgentSocketPath({ XDG_RUNTIME_DIR: '' }, { platform: 'linux', home }), `${home}/.locket/agent.sock`);
  assert.equal(resolveAgentSocketPath({}, { platform: 'win32', home: 'C:\\Users\\fixture', windowsSid: () => 'S-1-5-21-42' }), '\\\\.\\pipe\\locket-agent-S-1-5-21-42');
});

test('an explicit endpoint overrides platform discovery and missing SID fails closed', () => {
  let sidCalls = 0;
  const platform = { platform: 'win32' as const, home: 'C:\\Users\\fixture', windowsSid: () => { sidCalls++; return 'invalid\\pipe'; } };
  assert.equal(resolveAgentSocketPath({ LOCKET_AGENT_SOCKET: ' custom-endpoint ' }, platform), 'custom-endpoint');
  assert.equal(sidCalls, 0);
  assert.throws(() => resolveAgentSocketPath({}, platform), /Unable to determine the Windows agent pipe/u);
});

test('Windows discovery derives the pipe from whoami and rejects invalid or unavailable identity', (t) => {
  const windowsCommand: {
    execFileSync: (file: string, args: readonly string[], options: childProcess.ExecFileSyncOptionsWithStringEncoding) => string;
  } = childProcess;
  const whoami = t.mock.method(windowsCommand, 'execFileSync', () => '"fixture\\user","S-1-5-21-42"\r\n');
  const platform = { platform: 'win32' as const, home: 'C:\\Users\\fixture' };
  const environment = { SYSTEMROOT: 'D:\\Windows' };
  assert.equal(resolveAgentSocketPath(environment, platform), '\\\\.\\pipe\\locket-agent-S-1-5-21-42');
  assert.deepEqual(whoami.mock.calls[0]?.arguments.slice(0, 2), [
    'D:\\Windows\\System32\\whoami.exe', ['/user', '/fo', 'csv', '/nh'],
  ]);
  whoami.mock.mockImplementationOnce(() => '"fixture","no sid"');
  assert.throws(() => resolveAgentSocketPath({}, platform), { code: 'AgentUnavailable' });
  whoami.mock.mockImplementationOnce(() => { throw new Error('unexpected process output'); });
  assert.throws(() => resolveAgentSocketPath({}, platform), {
    message: 'Unable to determine the Windows agent pipe. Set LOCKET_AGENT_SOCKET explicitly.',
  });
});

test('unknown agent error codes provide stable display copy', () => {
  const error = AgentClientError.agent({ error: 'FutureError', message: 'details', retryable: true });
  assert.equal(error.code, 'FutureError');
  assert.equal(error.retryable, true);
  assert.equal(error.displayReason, 'The agent rejected the request.');
  assert.equal(error.nextAction, 'See the agent logs for details.');
});

test('request reads a frame split across header and payload boundaries and closes the socket', async (t) => {
  const { client, socket } = scriptedSocket(t, (connection, request) => {
    const frame = encodeResponse({ v: 1, id: request.id, ok: true, payload: { lock_state: 'locked' } });
    for (const chunk of [frame.subarray(0, 2), frame.subarray(2, 5), frame.subarray(5)]) {
      connection.emit('data', chunk);
    }
  });
  assert.deepEqual(await client.status(), { lock_state: 'locked' });
  assert.equal(socket.destroyed, true);
});

const invalidResponses: Array<{
  name: string;
  response: (id: string) => Buffer;
  message: RegExp;
}> = [
  {
    name: 'wrong request id',
    response: () => encodeResponse({ v: 1, id: 'other', ok: true, payload: null }),
    message: /did not match/u,
  },
  {
    name: 'unsupported protocol version',
    response: (id) => encodeResponse({ v: 2, id, ok: true, payload: null }),
    message: /envelope is invalid/u,
  },
  {
    name: 'missing success payload',
    response: (id) => encodeResponse({ v: 1, id, ok: true }),
    message: /envelope is invalid/u,
  },
  {
    name: 'invalid JSON',
    response: () => encodeBody('{'),
    message: /JSON/u,
  },
  {
    name: 'oversized frame',
    response: () => encodeResponse({ payload: 'x'.repeat(256) }),
    message: /response frame exceeds maximum size/u,
  },
];

for (const { name, response, message } of invalidResponses) {
  test(`request rejects a response with ${name} and closes the socket`, async (t) => {
    const { client, socket } = scriptedSocket(t, (connection, request) => connection.emit('data', response(request.id)));
    await assert.rejects(client.status(), { kind: 'protocol', message });
    assert.equal(socket.destroyed, true);
  });
}

test('frame encoding rejects requests over the configured limit', () => {
  assert.throws(() => encodeFrame({ v: 1, id: 'fixture', kind: 'Status', payload: {} }, 1), {
    kind: 'protocol',
    message: 'agent request frame exceeds maximum size',
  });
});

test('connection timeout closes a socket that never connects', async (t) => {
  const socket = new net.Socket();
  t.after(() => { socket.destroy(); });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const client = new AgentClient({ socketPath: 'fixture', connectTimeoutMs: 50 }, () => socket);
  const result = assert.rejects(client.status(), { code: 'AgentUnavailable', message: /connection timed out/u });
  t.mock.timers.tick(50);
  await result;
  assert.equal(socket.destroyed, true);
});

test('connection failure reports agent unavailable before writing', async (t) => {
  const socket = new net.Socket();
  t.after(() => { socket.destroy(); });
  const write = t.mock.method(socket, 'write');
  const client = new AgentClient({ socketPath: 'fixture' }, () => socket);
  const result = assert.rejects(client.status(), { code: 'AgentUnavailable', message: 'socket refused' });
  socket.emit('error', new Error('socket refused'));
  await result;
  assert.equal(write.mock.callCount(), 0);
});

test('request reports socket errors or premature close after connecting', async (t) => {
  const failed = scriptedSocket(t, (socket) => socket.emit('error', new Error('connection lost')));
  await assert.rejects(failed.client.status(), { code: 'AgentUnavailable', message: 'connection lost' });
  assert.equal(failed.socket.destroyed, true);

  const closed = scriptedSocket(t, (socket) => socket.destroy());
  await assert.rejects(closed.client.status(), { code: 'AgentUnavailable', message: 'agent socket closed before response' });
  assert.equal(closed.socket.destroyed, true);
});

test('status subscription reassembles partial frames and dispatches consecutive events', async (t) => {
  const events: unknown[] = [];
  const errors: AgentClientError[] = [];
  const { client, socket } = scriptedSocket(t, (connection, request) => {
    assert.equal(request.kind, 'SubscribeStatus');
    const frame = Buffer.concat([1, 2].map((sequence) => encodeResponse({
      v: 1, id: request.id, ok: true, payload: { kind: 'status', sequence },
    })));
    connection.emit('data', frame.subarray(0, 6));
    assert.deepEqual(events, []);
    connection.emit('data', frame.subarray(6));
  });
  const subscription = await client.subscribeStatus((event) => events.push(event), (error) => errors.push(error));
  assert.deepEqual(events, [{ kind: 'status', sequence: 1 }, { kind: 'status', sequence: 2 }]);
  const closed = new Promise<void>((resolve) => socket.once('close', resolve));
  subscription.dispose();
  await closed;
  assert.deepEqual(errors, []);
});

test('status subscription rejects a response for a different request without duplicate close error', async (t) => {
  const errors: AgentClientError[] = [];
  const { client, socket } = scriptedSocket(t, (connection) => {
    connection.emit('data', encodeResponse({ v: 1, id: 'other', ok: true, payload: null }));
  });
  const closed = new Promise<void>((resolve) => socket.once('close', resolve));
  const subscription = await client.subscribeStatus(
    () => assert.fail('unexpected status event'),
    (error) => errors.push(error),
  );
  await closed;
  assert.equal(errors.length, 1);
  assert.equal(errors[0]?.kind, 'protocol');
  assert.match(errors[0]?.message ?? '', /stream response id did not match/u);
  assert.equal(socket.destroyed, true);
  subscription.dispose();
});

test('status subscription reports a socket error once when the connection closes', async (t) => {
  const errors: AgentClientError[] = [];
  const { client, socket } = scriptedSocket(t, (connection) => { connection.destroy(new Error('stream lost')); });
  const closed = new Promise<void>((resolve) => socket.once('close', resolve));
  const subscription = await client.subscribeStatus(
    () => assert.fail('unexpected status event'),
    (error) => errors.push(error),
  );
  await closed;
  assert.deepEqual(errors.map(({ code, message }) => ({ code, message })), [
    { code: 'AgentUnavailable', message: 'stream lost' },
  ]);
  subscription.dispose();
});

for (const [failure, expected] of [
  [new Error('listener failed'), 'listener failed'],
  ['listener failed', 'unknown agent client failure'],
] as const) {
  test(`status subscription wraps a thrown ${typeof failure} from its listener once`, async (t) => {
    const errors: AgentClientError[] = [];
    const { client, socket } = scriptedSocket(t, (socket, request) => {
      socket.emit('data', encodeResponse({ v: 1, id: request.id, ok: true, payload: { kind: 'heartbeat' } }));
    });
    const closed = new Promise<void>((resolve) => socket.once('close', resolve));
    const subscription = await client.subscribeStatus(() => { throw failure; }, (error) => errors.push(error));
    await closed;
    assert.equal(errors.length, 1);
    assert.equal(errors[0]?.kind, 'protocol');
    assert.equal(errors[0]?.message, expected);
    subscription.dispose();
  });
}

function scriptedSocket(t: TestContext, onRequest: (socket: net.Socket, request: RequestEnvelope) => void) {
  const socket = new net.Socket();
  t.after(() => { socket.destroy(); });
  t.mock.method(socket, 'write', (frame: Buffer) => {
    queueMicrotask(() => onRequest(socket, decodeRequest(frame)));
    return true;
  });
  const client = new AgentClient({ socketPath: 'fixture', maxMessageSize: 256 }, () => {
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  });
  return { client, socket };
}

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-agent-'));
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
  return encodeBody(JSON.stringify(response));
}

function encodeBody(body: string): Buffer {
  const payload = Buffer.from(body, 'utf8');
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32LE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}
