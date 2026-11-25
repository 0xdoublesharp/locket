import { expect, it } from 'vitest';
import { auditLogRow } from './audit';
import { deviceMemberRow } from './deviceMembers';
import { runtimeSessionRow } from './runtimeSessions';
import { isProtocol, isRejected, isUnavailable, type AgentClientError } from './types';
import type { RuntimeSessionWireRow } from './types';

it.each([
  ['SUCCESS', 'OK'],
  ['DENIED', 'DENIED'],
  ['ERROR', 'FAILED'],
  ['UNKNOWN', 'FAILED'],
])('maps audit status %s to %s without copying command data', (status, presentation) => {
  const row = auditLogRow(
    {
      sequence: 7,
      action: 'RUN_POLICY',
      status,
      timestamp: 1_750_000_000_000_000_000,
      profile_id: 'fixture-profile',
      secret_name: null,
      command: 'fixture-opaque-metadata',
    },
    false,
  );
  expect(row).toEqual({
    sequence: 7,
    action: 'RUN_POLICY',
    status: presentation,
    timestamp: '2025-06-15T15:06:40.000Z',
    profile: 'fixture-profile',
    secretName: undefined,
    metadataJson: '{}',
    hmacOk: false,
  });
  expect(JSON.stringify(row)).not.toContain('fixture-opaque-metadata');
});

it('handles invalid timestamps and recognizes stale sessions with no completion', () => {
  const session: RuntimeSessionWireRow = {
    session_id: 'stale-run',
    profile: 'dev',
    policy: 'fixture-run',
    pid: 42,
    process_start_time: Number.NaN,
    started_at: 1_750_000_000_000_000_000,
    state: 'stale',
    secret_name_count: 1,
    spawn_audit_sequence: 1,
  };
  expect(runtimeSessionRow(session)).toMatchObject({
    sessionId: 'stale-run',
    processStartTime: 'Invalid timestamp',
    state: 'stale',
    endedAt: undefined,
  });
  expect(
    deviceMemberRow({
      id: 'member',
      kind: 'member',
      name: 'Fixture member',
      role: 'read-only',
      status: 'active',
      created_at: Number.NaN,
    }),
  ).toMatchObject({ createdAt: 'Invalid timestamp', role: 'viewer', lastSeenAt: undefined });
  expect(
    auditLogRow(
      {
        sequence: 9,
        action: 'VERIFY',
        status: 'OK',
        timestamp: Number.NaN,
        profile_id: null,
        secret_name: null,
        command: null,
      },
      true,
    ),
  ).toMatchObject({ timestamp: 'Invalid timestamp', hmacOk: true });
});

it('classifies available error variants by discriminant', () => {
  const errors: AgentClientError[] = [
    { kind: 'protocol', reason: 'Malformed fixture response' },
    {
      kind: 'unavailable',
      reason: 'Offline',
      display_reason: 'Agent unavailable',
      next_action: 'Retry',
      socket_path: '',
    },
    {
      kind: 'rejected',
      code: 'Denied',
      message: 'Denied',
      display_reason: 'Rejected',
      next_action: 'Check access',
      retryable: false,
    },
  ];
  expect(errors.filter(isProtocol)).toEqual([errors[0]]);
  expect(errors.filter(isUnavailable)).toEqual([errors[1]]);
  expect(errors.filter(isRejected)).toEqual([errors[2]]);
});
