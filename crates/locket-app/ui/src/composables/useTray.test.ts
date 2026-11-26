import { invoke } from '@tauri-apps/api/core';
import { effectScope, ref } from 'vue';
import { describe, expect, it, vi } from 'vitest';

import { deriveTrayState, useTray } from './useTray';
import type { AgentStatus } from '../agent/types';
import { deferred, settle } from '../test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

function status(overrides: Partial<AgentStatus> = {}): AgentStatus {
  return {
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
    ...overrides,
  };
}

describe('deriveTrayState', () => {
  it('returns scan-warning when unresolved scan warnings exist', () => {
    expect(deriveTrayState(status({ lock_state: 'unlocked', scan_warning_count: 2 }), null)).toBe(
      'scan-warning',
    );
  });

  it('keeps agent errors ahead of scan-warning status metadata', () => {
    expect(
      deriveTrayState(status({ scan_warning_count: 2 }), {
        kind: 'unavailable',
        reason: 'socket missing',
        display_reason: 'Agent unavailable',
        next_action: 'Start the agent.',
        socket_path: '/tmp/locket.sock',
      }),
    ).toBe('agent-stopped');
  });

  it('falls back to lock state when scan warnings are resolved', () => {
    expect(deriveTrayState(status({ lock_state: 'unlocked', scan_warning_count: 0 }), null)).toBe(
      'agent-unlocked',
    );
  });
});

it('keeps global scan warnings visible when project-specific counts are unknown', () => {
  expect(
    deriveTrayState(status({ scan_warning_count: 2, scan_warning_count_known: false }), null),
  ).toBe('scan-warning');
});

it('restores the newest tray state when a prior IPC update is still pending', async () => {
  const current = ref(status({ lock_state: 'locked' }));
  const pending = deferred<void>();
  const send = vi.mocked(invoke);
  send.mockReset().mockResolvedValue(undefined);
  const scope = effectScope();
  try {
    scope.run(() => useTray(current, ref(null)));
    await settle();
    send.mockImplementationOnce(() => pending.promise);
    current.value = status({ lock_state: 'unlocked' });
    await settle();
    current.value = status({ lock_state: 'locked' });
    await settle();
    pending.resolve();
    await settle();
    expect(send.mock.calls.map(([, args]) => args)).toEqual([
      { state: 'agent-locked' },
      { state: 'agent-unlocked' },
      { state: 'agent-locked' },
    ]);
  } finally {
    scope.stop();
  }
});

it('sends the desired lock state again after a partially applied tray update fails', async () => {
  const current = ref(status());
  const pending = deferred<void>();
  const send = vi.mocked(invoke);
  send.mockReset().mockResolvedValue(undefined);
  const scope = effectScope();
  try {
    scope.run(() => useTray(current, ref(null)));
    await settle();
    send.mockImplementationOnce(() => pending.promise);
    current.value = status({ lock_state: 'unknown' });
    await settle();
    current.value = status();
    await settle();
    pending.reject(new Error('tooltip failed'));
    await settle();
    expect(send.mock.calls.map(([, args]) => args)).toEqual([
      { state: 'agent-locked' },
      { state: 'error-degraded' },
      { state: 'agent-locked' },
    ]);
  } finally {
    scope.stop();
  }
});
