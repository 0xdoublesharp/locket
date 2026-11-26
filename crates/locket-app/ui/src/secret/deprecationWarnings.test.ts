import { describe, expect, it } from 'vitest';

import type { CommandPolicyRow, SecretRowMeta, VersionHistoryRow } from '../types/views';
import { secretRowsWithDeprecationWarnings } from './deprecationWarnings';

const NOW = Date.parse('2026-05-01T00:00:00.000Z') * 1_000_000;

function secret(overrides: Partial<SecretRowMeta>): SecretRowMeta {
  return {
    id: 'secret-1',
    name: 'DATABASE_URL',
    source: 'user-local',
    required: true,
    optional: false,
    createdAt: '2026-01-01T00:00:00.000Z',
    currentVersion: 3,
    hasDeprecatedGrace: false,
    ...overrides,
  };
}

function version(overrides: Partial<VersionHistoryRow>): VersionHistoryRow {
  return {
    secretName: 'DATABASE_URL',
    source: 'user-local',
    version: 2,
    state: 'deprecated',
    graceUntil: '2026-05-02T00:00:00.000Z',
    pinnedReferenceEligible: true,
    scanInclusion: true,
    ...overrides,
  };
}

function policy(overrides: Partial<CommandPolicyRow>): CommandPolicyRow {
  return {
    id: 'policy-1',
    name: 'deploy',
    commandKind: 'argv',
    commandPreview: 'echo',
    requiredSecrets: [],
    optionalSecrets: [],
    allowedSecrets: [],
    confirm: false,
    requireUserVerification: true,
    requireAgent: false,
    allowRemoteDocker: false,
    ttlSeconds: 60,
    envMode: 'minimal',
    overrideMode: 'locket',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('secretRowsWithDeprecationWarnings', () => {
  it('surfaces active grace warnings from pinned lk command-preview references', () => {
    const rows = secretRowsWithDeprecationWarnings(
      [secret({})],
      [version({})],
      [policy({ commandPreview: 'run lk://dev/DATABASE_URL@v2' })],
      NOW,
    );

    expect(rows[0]?.hasDeprecatedGrace).toBe(true);
    expect(rows[0]?.deprecatedReferenceWarnings).toEqual([
      {
        version: 2,
        status: 'active-grace',
        surface: 'command-preview',
        graceUntil: '2026-05-02T00:00:00.000Z',
        referenceCount: 1,
      },
    ]);
  });

  it('surfaces expired grace warnings without exposing command text', () => {
    const rows = secretRowsWithDeprecationWarnings(
      [secret({})],
      [version({ graceUntil: '2026-04-30T00:00:00.000Z', pinnedReferenceEligible: false })],
      [policy({ commandPreview: 'deploy lk://dev/DATABASE_URL@v2' })],
      NOW,
    );

    expect(rows[0]?.deprecatedReferenceWarnings).toEqual([
      {
        version: 2,
        status: 'expired-grace',
        surface: 'command-preview',
        graceUntil: '2026-04-30T00:00:00.000Z',
        referenceCount: 1,
      },
    ]);
  });

  it('counts pinned policy-list references separately from command previews', () => {
    const rows = secretRowsWithDeprecationWarnings(
      [secret({})],
      [version({})],
      [
        policy({
          commandPreview: 'echo lk://dev/DATABASE_URL@v2 lk://dev/DATABASE_URL@v2',
          requiredSecrets: ['DATABASE_URL@v2'],
        }),
      ],
      NOW,
    );

    expect(rows[0]?.deprecatedReferenceWarnings).toEqual([
      {
        version: 2,
        status: 'active-grace',
        surface: 'command-preview',
        graceUntil: '2026-05-02T00:00:00.000Z',
        referenceCount: 2,
      },
      {
        version: 2,
        status: 'active-grace',
        surface: 'policy',
        graceUntil: '2026-05-02T00:00:00.000Z',
        referenceCount: 1,
      },
    ]);
  });

  it('ignores current versions and unpinned references', () => {
    const rows = secretRowsWithDeprecationWarnings(
      [secret({})],
      [version({ state: 'current' })],
      [policy({ commandPreview: 'echo lk://dev/DATABASE_URL' })],
      NOW,
    );

    expect(rows[0]?.hasDeprecatedGrace).toBe(false);
    expect(rows[0]?.deprecatedReferenceWarnings).toEqual([]);
  });
});

it('sorts multiple pinned versions by expiry and then by version', () => {
  const [row] = secretRowsWithDeprecationWarnings(
    [secret({})],
    [
      version({ version: 1, graceUntil: '2026-04-30T00:00:00.000Z' }),
      version({ version: 2, graceUntil: '2026-05-03T00:00:00.000Z' }),
      version({ version: 3, graceUntil: '2026-05-04T00:00:00.000Z' }),
    ],
    [
      policy({
        requiredSecrets: [
          'DATABASE_URL',
          'lk://dev/DATABASE_URL@v3',
          'DATABASE_URL@v2',
          'DATABASE_URL@v1',
          'DATABASE_URL@v9007199254740992',
        ],
      }),
    ],
    NOW,
  );
  expect(row?.deprecatedReferenceWarnings?.map(({ version, status }) => [version, status])).toEqual(
    [
      [1, 'expired-grace'],
      [2, 'active-grace'],
      [3, 'active-grace'],
    ],
  );
});
