// Behavior tests for the Locket VS Code status-bar controller.
//
// Drive `LocketStatusBarController` against a real `AgentClient`
// connected to a fake agent socket. Each test scripts the responses
// the agent emits and asserts the resulting status-bar plans, the
// reconnect bookkeeping, and the `CancelSubscription` RPC sent on
// dispose. The host abstraction (`StatusBarHost`) lets the test stub
// `setTimeout`/`clearTimeout` so the backoff schedule is observable
// without sleeping.

import { mkdtemp, rm } from 'node:fs/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { AgentClient, RequestEnvelope } from './agentClient';
import type { StatusBarHost } from './statusBar';
import { StatusBarPlan } from './statusBarModel';

interface ScheduledTimer {
  readonly handle: number;
  readonly handler: () => void;
  readonly delay: number;
}

interface RecordingHost extends StatusBarHost {
  readonly plans: StatusBarPlan[];
  readonly timers: ScheduledTimer[];
  readonly cleared: number[];
  shown: boolean;
  itemDisposed: boolean;
  fireNextTimer: () => void;
}

function recordingHost(): RecordingHost {
  const plans: StatusBarPlan[] = [];
  const timers: ScheduledTimer[] = [];
  const cleared: number[] = [];
  let nextHandle = 1;
  const host: RecordingHost = {
    plans,
    timers,
    cleared,
    shown: false,
    itemDisposed: false,
    showItem: () => {
      host.shown = true;
    },
    apply: (plan) => {
      plans.push(plan);
    },
    setTimeout: (handler, delay) => {
      const handle = nextHandle;
      nextHandle += 1;
      timers.push({ handle, handler, delay });
      return handle;
    },
    clearTimeout: (handle) => {
      cleared.push(handle as number);
    },
    disposeItem: () => {
      host.itemDisposed = true;
    },
    fireNextTimer: () => {
      const next = timers.shift();
      assert.ok(next, 'no scheduled timer to fire');
      next.handler();
    },
  };
  return host;
}

test('status bar controller module loads under plain Node', async () => {
  const statusBar = await loadStatusBarModule();

  assert.equal(typeof statusBar.LocketStatusBarController, 'function');
});

test('controller subscribes to SubscribeStatus and renders status events', async () => {
  const { LocketStatusBarController } = await loadStatusBarModule();
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: RequestEnvelope[] = [];
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request);
      if (request.kind === 'SubscribeStatus') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              kind: 'status',
              sequence: 1,
              lock_state: 'unlocked',
              live_grant_count: 1,
              agent_version: 'test-agent',
              unlock_ttl_seconds: 60,
            },
          }),
        );
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const host = recordingHost();
    const controller = new LocketStatusBarController(client, host);
    controller.start();

    await waitFor(() => host.plans.length >= 2);
    const connectingPlan = requiredAt(host.plans, 0);
    const statusPlan = requiredAt(host.plans, 1);
    assert.equal(host.shown, true);
    assert.equal(
      connectingPlan.text,
      '$(sync~spin) Locket',
      'first plan is the connecting placeholder',
    );
    assert.equal(statusPlan.text, '$(key) Locket');
    assert.match(statusPlan.tooltip, /unlocked/u);
    assert.match(statusPlan.tooltip, /sequence 1/u);
    const subscribeRequest = observed.find((r) => r.kind === 'SubscribeStatus');
    assert.ok(subscribeRequest, 'controller must send SubscribeStatus');

    controller.dispose();
    assert.equal(host.itemDisposed, true);
  } finally {
    server.close();
    await cleanup();
  }
});

test('heartbeat events refresh the tooltip without flipping the badge text', async () => {
  const { LocketStatusBarController } = await loadStatusBarModule();
  const { socketPath, cleanup } = await temporarySocketPath();
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      if (request.kind === 'SubscribeStatus') {
        // First a status snapshot, then a heartbeat at the same id.
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              kind: 'status',
              sequence: 1,
              lock_state: 'unlocked',
              live_grant_count: 0,
              agent_version: 'test-agent',
            },
          }),
        );
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              kind: 'heartbeat',
              sequence: 7,
              lock_state: 'unlocked',
              live_grant_count: 0,
              agent_version: 'test-agent',
            },
          }),
        );
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const host = recordingHost();
    const controller = new LocketStatusBarController(client, host);
    controller.start();

    await waitFor(() => host.plans.length >= 3);
    const status = requiredAt(host.plans, 1);
    const heartbeat = requiredAt(host.plans, 2);
    assert.equal(status.text, '$(key) Locket');
    assert.equal(heartbeat.text, status.text, 'heartbeat must keep the existing badge text');
    assert.equal(heartbeat.background, status.background);
    assert.match(heartbeat.tooltip, /last seen sequence 7/u);

    controller.dispose();
  } finally {
    server.close();
    await cleanup();
  }
});

test('controller schedules a reconnect with backoff after the stream errors', async () => {
  const { LocketStatusBarController } = await loadStatusBarModule();
  const { socketPath, cleanup } = await temporarySocketPath();
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    socket.once('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      if (connections === 1) {
        // First connection: drop after subscribe to force a reconnect.
        socket.destroy();
        return;
      }
      // Second connection: serve a successful status snapshot.
      socket.write(
        encodeResponse({
          v: 1,
          id: request.id,
          ok: true,
          payload: {
            kind: 'status',
            sequence: 5,
            lock_state: 'locked',
            live_grant_count: 0,
            agent_version: 'test-agent',
          },
        }),
      );
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const host = recordingHost();
    const controller = new LocketStatusBarController(client, host);
    controller.start();

    await waitFor(() => host.timers.length >= 1);
    assert.equal(
      requiredAt(host.timers, 0).delay,
      500,
      'first reconnect uses the 500ms base delay',
    );
    // Plan history should include the connecting placeholder followed
    // by the unavailable warning before the reconnect runs.
    assert.ok(
      host.plans.some((plan) => plan.background === 'warning'),
      'expected an unavailable warning plan before reconnect',
    );

    host.fireNextTimer();
    await waitFor(() => host.plans.some((plan) => plan.text === '$(lock) Locket'));
    assert.equal(connections, 2, 'reconnect attempt must open a fresh socket');

    controller.dispose();
  } finally {
    server.close();
    await cleanup();
  }
});

test('dispose sends CancelSubscription and tears down the stream', async () => {
  const { LocketStatusBarController } = await loadStatusBarModule();
  const { socketPath, cleanup } = await temporarySocketPath();
  const observed: string[] = [];
  const server = net.createServer((socket) => {
    socket.on('data', (frame: Buffer) => {
      const request = decodeRequest(frame);
      observed.push(request.kind);
      if (request.kind === 'SubscribeStatus') {
        socket.write(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: {
              kind: 'status',
              sequence: 1,
              lock_state: 'unlocked',
              live_grant_count: 0,
              agent_version: 'test-agent',
            },
          }),
        );
      }
      if (request.kind === 'CancelSubscription') {
        socket.end(
          encodeResponse({
            v: 1,
            id: request.id,
            ok: true,
            payload: null,
          }),
        );
      }
    });
  });

  try {
    await listen(server, socketPath);
    const client = new AgentClient({ socketPath, connectTimeoutMs: 500 });
    const host = recordingHost();
    const controller = new LocketStatusBarController(client, host);
    controller.start();

    await waitFor(() => host.plans.length >= 2);
    controller.dispose();

    await waitFor(() => observed.includes('CancelSubscription'));
    assert.equal(host.itemDisposed, true);
  } finally {
    server.close();
    await cleanup();
  }
});

async function waitFor(condition: () => boolean, timeoutMs = 1500): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error('waitFor timeout');
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, 5));
  }
}

async function temporarySocketPath(): Promise<{ socketPath: string; cleanup: () => Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'locket-vscode-statusbar-'));
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

function loadStatusBarModule(): Promise<typeof import('./statusBar')> {
  return import('./statusBar.js');
}

function requiredAt<T>(values: ReadonlyArray<T>, index: number): T {
  const value = values[index];
  if (value === undefined) {
    assert.fail(`expected value at index ${index.toString()}`);
  }
  return value;
}
