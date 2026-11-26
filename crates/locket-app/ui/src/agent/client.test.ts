// Unit tests for the SubscribeStatus event dispatcher.
//
// Tests run under vitest (or any compatible runner that resolves
// `vitest`). When the runner is not configured locally, the file is
// skipped at collection time, but the assertions below are
// hand-verifiable for code review.
//
// These tests pin the heartbeat-filter contract: heartbeats must reach
// `onHeartbeat` (so the connection-health badge can advance its "last
// seen" timestamp) but must not reach `onStatus` (so the rest of the UI
// does not re-render on idle keepalives).

import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  actionError,
  fetchStatus,
  handleStatusEvent,
  policyDoctor,
  prepareExec,
  registerCommandPolicies,
  resolveReference,
  scan,
  subscribeStatus,
} from './client';
import { defaultPolicyForm, policyFormToSnapshot } from '../policy/form';
import type { AgentStatusEvent } from './types';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

describe('subscribeStatus setup and teardown', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(isTauri).mockReturnValue(true);
    vi.mocked(invoke).mockResolvedValue(undefined);
  });

  it.each([0, 1, 2])('releases acquired listeners when registration %i fails', async (failure) => {
    const cleanup = [vi.fn(), vi.fn(), vi.fn()];
    for (let index = 0; index < failure; index++) {
      vi.mocked(listen).mockResolvedValueOnce(cleanup[index]!);
    }
    vi.mocked(listen).mockRejectedValueOnce('listener unavailable');
    await expect(subscribeStatus(vi.fn(), vi.fn())).resolves.toEqual({
      ok: false,
      error: { kind: 'protocol', reason: 'listener unavailable' },
    });
    for (let index = 0; index < cleanup.length; index++) {
      expect(cleanup[index]).toHaveBeenCalledTimes(index < failure ? 1 : 0);
    }
    expect(invoke).not.toHaveBeenCalled();
  });

  it('releases every listener when the backend subscription fails', async () => {
    const cleanup = [vi.fn(), vi.fn(), vi.fn()];
    cleanup.forEach((unlisten) => vi.mocked(listen).mockResolvedValueOnce(unlisten));
    vi.mocked(invoke).mockRejectedValueOnce('agent unavailable');
    expect(await subscribeStatus(vi.fn(), vi.fn())).toEqual({
      ok: false,
      error: { kind: 'protocol', reason: 'agent unavailable' },
    });
    cleanup.forEach((unlisten) => expect(unlisten).toHaveBeenCalledTimes(1));
  });

  it('returns an idempotent cleanup after successful setup', async () => {
    const cleanup = [vi.fn(), vi.fn(), vi.fn()];
    cleanup.forEach((unlisten) => vi.mocked(listen).mockResolvedValueOnce(unlisten));
    const result = await subscribeStatus(vi.fn(), vi.fn());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('subscription failed');
    expect(invoke).toHaveBeenCalledWith('agent_subscribe_status');
    result.value();
    result.value();
    cleanup.forEach((unlisten) => expect(unlisten).toHaveBeenCalledTimes(1));
  });
});

function makeEvent(kind: 'status' | 'heartbeat', sequence: number): AgentStatusEvent {
  return {
    kind,
    sequence,
    lock_state: 'locked',
    project_id: null,
    profile_name: null,
    live_grant_count: 0,
    agent_version: '0.0.0-test',
    unlock_ttl_seconds: null,
    running_session_count: 0,
    scan_warning_count: 0,
    recent_audit_status: 'unknown',
    pinned_reference_warning_count: 0,
  };
}

describe('handleStatusEvent', () => {
  it('routes status frames to onStatus and onHeartbeat', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const event = makeEvent('status', 1);
    handleStatusEvent(event, onStatus, onHeartbeat);
    expect(onStatus).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenCalledWith(event);
    expect(onHeartbeat).toHaveBeenCalledTimes(1);
    expect(onHeartbeat).toHaveBeenCalledWith(event);
  });

  it('routes heartbeats to onHeartbeat only', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const event = makeEvent('heartbeat', 2);
    handleStatusEvent(event, onStatus, onHeartbeat);
    expect(onStatus).not.toHaveBeenCalled();
    expect(onHeartbeat).toHaveBeenCalledTimes(1);
    expect(onHeartbeat).toHaveBeenCalledWith(event);
  });

  it('still calls onStatus for status frames when onHeartbeat is omitted', () => {
    const onStatus = vi.fn();
    const event = makeEvent('status', 3);
    handleStatusEvent(event, onStatus);
    expect(onStatus).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenCalledWith(event);
  });

  it('drops heartbeats silently when onHeartbeat is omitted', () => {
    const onStatus = vi.fn();
    const event = makeEvent('heartbeat', 4);
    handleStatusEvent(event, onStatus);
    expect(onStatus).not.toHaveBeenCalled();
  });

  it('only fires onStatus for non-heartbeat events across a mixed stream', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const stream: AgentStatusEvent[] = [
      makeEvent('status', 1),
      makeEvent('heartbeat', 2),
      makeEvent('heartbeat', 3),
      makeEvent('status', 4),
    ];
    for (const event of stream) {
      handleStatusEvent(event, onStatus, onHeartbeat);
    }
    expect(onStatus).toHaveBeenCalledTimes(2);
    expect(onHeartbeat).toHaveBeenCalledTimes(4);
    expect(onStatus.mock.calls.map((call) => (call[0] as AgentStatusEvent).sequence)).toEqual([
      1, 4,
    ]);
  });
});

describe('actionError', () => {
  it('avoids double periods when protocol reasons end with punctuation', () => {
    expect(actionError({ kind: 'protocol', reason: 'Locket CLI failed during agent.' })).toBe(
      'Locket CLI failed during agent. Fix the reported issue, then retry.',
    );
  });
});

describe('desktop invocation errors', () => {
  it.each([null, new Error('IPC failed'), { kind: 'unexpected' }, { kind: 'protocol' }])(
    'maps malformed rejection %j to usable protocol feedback',
    async (rejection) => {
      vi.mocked(isTauri).mockReturnValue(true);
      vi.mocked(invoke).mockRejectedValueOnce(rejection);

      const result = await fetchStatus();
      if (result.ok) throw new Error('expected IPC failure');
      expect(result.error).toEqual({ kind: 'protocol', reason: 'unknown agent error' });
      expect(actionError(result.error)).toBe(
        'unknown agent error. Fix the reported issue, then retry.',
      );
    },
  );
});

it('dispatches registered IPC status, failure and disconnect events', async () => {
  vi.mocked(isTauri).mockReturnValue(true);
  vi.mocked(listen).mockResolvedValue(() => {});
  vi.mocked(listen).mockClear();
  vi.mocked(invoke).mockResolvedValue(undefined);
  const onStatus = vi.fn();
  const onHeartbeat = vi.fn();
  const onError = vi.fn();
  const onDisconnected = vi.fn();
  await subscribeStatus(onStatus, onError, { onHeartbeat, onDisconnected });

  function emit(event: string, payload: unknown) {
    const registration = vi.mocked(listen).mock.calls.find(([name]) => name === event);
    expect(registration).toBeDefined();
    registration![1]({ event, id: 1, payload });
  }

  const status = makeEvent('status', 1);
  const heartbeat = makeEvent('heartbeat', 2);
  emit('agent-status', status);
  emit('agent-status', heartbeat);
  emit('agent-status-error', { kind: 'protocol', reason: 'lost framing' });
  emit('agent-status-disconnected', null);
  expect(onStatus).toHaveBeenCalledExactlyOnceWith(status);
  expect(onHeartbeat.mock.calls).toEqual([[status], [heartbeat]]);
  expect(onError).toHaveBeenCalledExactlyOnceWith({ kind: 'protocol', reason: 'lost framing' });
  expect(onDisconnected).toHaveBeenCalledOnce();
});

it('returns typed offline feedback when there is no desktop shell', async () => {
  vi.mocked(isTauri).mockReturnValue(false);
  vi.mocked(invoke).mockClear();
  const status = await fetchStatus();
  const subscription = await subscribeStatus(vi.fn(), vi.fn());
  expect(status).toMatchObject({ ok: false, error: { kind: 'unavailable', socket_path: '' } });
  expect(subscription).toEqual(status);
  expect(invoke).not.toHaveBeenCalled();
});

it('forwards diagnostic and policy requests to their typed Tauri commands', async () => {
  vi.mocked(isTauri).mockReturnValue(true);
  vi.mocked(invoke).mockResolvedValue(undefined);
  const scope = { project_id: 'fixture', profile_id: 'dev' };
  const scanRequest = {
    ...scope,
    store_path: '/fixture/store.db',
    grant_id: 'fixture-grant',
    inputs: [],
    require_known: true,
  };
  const resolveRequest = { ...scope, reference: 'lk://dev/TOKEN' };
  const prepareRequest = { ...scope, policy_name: 'check' };
  const policy = policyFormToSnapshot(
    {
      ...defaultPolicyForm(),
      name: 'check',
      commandPreview: 'echo check',
    },
    scope.project_id,
    0,
  );
  const doctorRequest = { ...scope, policy };
  const registerRequest = { project_id: scope.project_id, policies: [policy] };
  await scan(scanRequest);
  await resolveReference(resolveRequest);
  await prepareExec(prepareRequest);
  await policyDoctor(doctorRequest);
  await registerCommandPolicies(registerRequest);
  for (const [command, request] of [
    ['agent_scan', scanRequest],
    ['agent_resolve', resolveRequest],
    ['agent_prepare_exec', prepareRequest],
    ['agent_policy_doctor', doctorRequest],
    ['agent_register_command_policies', registerRequest],
  ]) {
    expect(invoke).toHaveBeenCalledWith(command, { request });
  }
});
