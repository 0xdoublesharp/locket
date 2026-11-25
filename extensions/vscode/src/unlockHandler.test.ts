// End-to-end unit test for the `locket.unlock` command flow.
//
// Drives `runUnlockFlow` against a real `AgentClient` connected to a
// fake agent socket. Each test scripts the agent responses for the
// `Unlock` envelopes the handler is expected to emit and asserts the
// wire payloads, the user-facing messages, and the final outcome.

import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, AgentClientError, RequestEnvelope } from './agentClient';
import { UnlockHandlerUi, runUnlockFlow } from './unlockHandler';

const PROJECT_ID = 'lk_proj_demo';
const STORE_PATH = '/tmp/locket-unlock/store.db';
const PASSPHRASE = 'open-sesame';

interface RecordedUi extends UnlockHandlerUi {
  readonly info: string[];
  readonly warnings: string[];
  readonly errors: string[];
  readonly passphrasePrompts: { count: number };
}

function recordedUi(passphrase: string | undefined = PASSPHRASE): RecordedUi {
  const info: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  const passphrasePrompts = { count: 0 };
  return {
    info,
    warnings,
    errors,
    passphrasePrompts,
    promptProjectId: () => Promise.resolve(PROJECT_ID),
    promptStorePath: () => Promise.resolve(STORE_PATH),
    promptPassphrase: () => {
      passphrasePrompts.count += 1;
      return Promise.resolve(passphrase);
    },
    showInfo: (message) => {
      info.push(message);
    },
    showWarning: (message) => {
      warnings.push(message);
    },
    showError: (message) => {
      errors.push(message);
    },
    profileId: null,
  };
}

test('first unlock attempt sends passphrase: null and announces vault unlocked on success', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request);
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: null,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const ui = recordedUi();

    const outcome = await runUnlockFlow(client, ui);

    assert.equal(outcome.status, 'unlocked');
    assert.equal(observed.length, 1);
    const unlockRequest = requiredAt(observed, 0);
    assert.equal(unlockRequest.kind, 'Unlock');
    const payload = unlockRequest.payload as Record<string, unknown>;
    // Wire shape from agent-real-unlock: { project_id, passphrase, ttl_seconds, audit }.
    assert.equal(payload.project_id, PROJECT_ID);
    assert.equal(payload.passphrase, null);
    assert.equal(payload.ttl_seconds, 1800);
    assert.deepEqual(payload.audit, { store_path: STORE_PATH, profile_id: null });
    assert.equal(ui.passphrasePrompts.count, 0);
    assert.deepEqual(ui.info, ['vault unlocked']);
    assert.deepEqual(ui.errors, []);
    assert.deepEqual(ui.warnings, []);
  } finally {
    server.close();
    await cleanup();
  }
});

test('UnlockRequired triggers a passphrase prompt and a retry that includes the input', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  let attempt = 0;
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request);
      attempt += 1;
      if (attempt === 1) {
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
        return;
      }
      socket.end(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: null,
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const ui = recordedUi();

    const outcome = await runUnlockFlow(client, ui);

    assert.equal(outcome.status, 'unlocked');
    assert.equal(observed.length, 2);
    const first = requiredAt(observed, 0).payload as Record<string, unknown>;
    const second = requiredAt(observed, 1).payload as Record<string, unknown>;
    assert.equal(first.passphrase, null, 'first attempt must omit passphrase');
    assert.equal(second.passphrase, PASSPHRASE, 'retry must carry the user input');
    // Both attempts target the same project + audit metadata.
    assert.equal(second.project_id, PROJECT_ID);
    assert.deepEqual(second.audit, { store_path: STORE_PATH, profile_id: null });
    assert.equal(ui.passphrasePrompts.count, 1);
    assert.deepEqual(ui.info, ['vault unlocked']);
    assert.deepEqual(ui.errors, []);
  } finally {
    server.close();
    await cleanup();
  }
});

test('a second UnlockRequired surfaces the failed-passphrase notice', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      socket.write(
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
    const ui = recordedUi('bogus-passphrase');

    const outcome = await runUnlockFlow(client, ui);

    assert.equal(outcome.status, 'auth_failed');
    assert.equal(ui.passphrasePrompts.count, 1);
    assert.deepEqual(ui.errors, ['passphrase did not authenticate']);
    assert.deepEqual(ui.info, []);
  } finally {
    server.close();
    await cleanup();
  }
});

test('non-UnlockRequired errors short-circuit before prompting for a passphrase', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  let attempts = 0;
  const server = net.createServer((socket) => {
    socket.once('data', (frame: Buffer) => {
      attempts += 1;
      const request = decodeRequest(frame);
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
    const ui = recordedUi();

    const outcome = await runUnlockFlow(client, ui);

    assert.equal(outcome.status, 'agent_error');
    assert.equal(attempts, 1, 'no retry on a non-UnlockRequired failure');
    assert.equal(ui.passphrasePrompts.count, 0);
    assert.equal(ui.info.length, 0);
    assert.equal(ui.errors.length, 1);
    assert.match(requiredAt(ui.errors, 0), /unavailable/iu);
  } finally {
    server.close();
    await cleanup();
  }
});

test('cancelling the project prompt skips the network entirely', async () => {
  const { socketPath, cleanup } = await temporarySocketPath();
  let connected = false;
  const server = net.createServer(() => {
    connected = true;
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const ui: RecordedUi = {
      ...recordedUi(),
      promptProjectId: () => Promise.resolve(undefined),
    };

    const outcome = await runUnlockFlow(client, ui);
    assert.equal(outcome.status, 'cancelled');
    assert.equal(connected, false, 'agent must not be contacted when the user cancels');
    assert.deepEqual(ui.info, []);
    assert.deepEqual(ui.errors, []);
  } finally {
    server.close();
    await cleanup();
  }
});

test('cancelled store path and invalid metadata stop unlock before an agent request', async (t) => {
  const agent = new AgentClient({ socketPath: 'fixture' });
  const invoke = t.mock.method(agent, 'invoke', async () => assert.fail('unexpected RPC'));
  const ui = recordedUi();
  assert.deepEqual(await runUnlockFlow(agent, { ...ui, promptStorePath: async () => undefined }), { status: 'cancelled' });
  assert.deepEqual(await runUnlockFlow(agent, { ...ui, promptStorePath: async () => ' ' }), { status: 'invalid_input' });
  assert.equal(invoke.mock.callCount(), 0);
  assert.deepEqual(ui.warnings, ['store path is required']);
  assert.equal(ui.passphrasePrompts.count, 0);
});

test('dismissing the passphrase prompt cancels without retrying unlock', async (t) => {
  const agent = new AgentClient({ socketPath: 'fixture' });
  const invoke = t.mock.method(agent, 'invoke', async () => {
    throw AgentClientError.agent({ error: 'UnlockRequired', message: 'passphrase needed', retryable: true });
  });
  const ui = { ...recordedUi(), promptPassphrase: async () => undefined };
  assert.deepEqual(await runUnlockFlow(agent, ui), { status: 'cancelled' });
  assert.equal(invoke.mock.callCount(), 1);
  assert.deepEqual([ui.info, ui.errors], [[], []]);
});

test('a non-authentication retry error retains its agent code', async (t) => {
  const agent = new AgentClient({ socketPath: 'fixture' });
  const invoke = t.mock.method(agent, 'invoke', async () => { throw AgentClientError.unavailable('socket closed'); });
  invoke.mock.mockImplementationOnce(async () => {
    throw AgentClientError.agent({ error: 'UnlockRequired', message: 'passphrase needed', retryable: true });
  });
  const ui = recordedUi();
  assert.deepEqual(await runUnlockFlow(agent, ui), { status: 'agent_error', code: 'AgentUnavailable' });
  assert.equal(invoke.mock.callCount(), 2);
  assert.equal(ui.passphrasePrompts.count, 1);
  assert.deepEqual(ui.info, []);
  assert.match(ui.errors[0] ?? '', /agent.*unavailable/u);
});

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-unlock-'));
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

function requiredAt<T>(values: ReadonlyArray<T>, index: number): T {
  const value = values[index];
  if (value === undefined) {
    assert.fail(`expected value at index ${index.toString()}`);
  }
  return value;
}
