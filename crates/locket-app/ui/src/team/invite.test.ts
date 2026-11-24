// Tests for the desktop team-invite form models.

import { describe, expect, it } from 'vitest';

import type { AuditWireRow } from '../agent/types';
import {
  acceptFormToPayload,
  agentInviteAcceptCliCommand,
  agentInviteCreateCliCommand,
  agentInviteRequestCliCommand,
  defaultAcceptForm,
  defaultIssueForm,
  defaultRevokeForm,
  expiresAtToDurationArgument,
  filterTeamInviteRows,
  issueDangerousConfirmationMatches,
  issueFormToPayload,
  issueRequiresDangerousConfirmation,
  parseProfileList,
  revokeFormToPayload,
  teamInviteAcceptCliCommand,
  teamInviteIssueCliCommand,
  TEAM_INVITE_DESKTOP_NOTICE,
  teamInviteRevokeCliCommand,
  teamInviteRowsFromAudit,
  validateAcceptForm,
  validateIssueForm,
  validateRevokeForm,
  type TeamInviteRow,
} from './invite';

describe('parseProfileList', () => {
  it('trims, dedupes, and skips empties', () => {
    expect(parseProfileList(' dev , prod, dev ,, qa ')).toEqual(['dev', 'prod', 'qa']);
  });
});

describe('filterTeamInviteRows', () => {
  const rows: TeamInviteRow[] = [
    {
      id: 'lk_invite_alpha',
      direction: 'issued',
      status: 'pending',
      recipientLabel: 'Build Agent',
      role: 'developer',
      profiles: ['dev', 'qa'],
      createdAt: '2026-06-26T12:00:00.000Z',
    },
    {
      id: 'lk_invite_beta',
      direction: 'received',
      status: 'accepted',
      issuerLabel: 'Platform Team',
      role: 'maintainer',
      profiles: ['prod'],
      createdAt: '2026-06-26T13:00:00.000Z',
    },
  ];

  it('returns rows in original order for blank search', () => {
    expect(filterTeamInviteRows(rows, '   ')).toEqual(rows);
  });

  it('matches invite metadata case-insensitively', () => {
    expect(filterTeamInviteRows(rows, 'platform')).toEqual([rows[1]]);
    expect(filterTeamInviteRows(rows, 'QA')).toEqual([rows[0]]);
    expect(filterTeamInviteRows(rows, 'received')).toEqual([rows[1]]);
  });
});

describe('desktop notice copy', () => {
  it('keeps invite availability user-facing', () => {
    expect(TEAM_INVITE_DESKTOP_NOTICE).toContain('Locket CLI');
    expect(TEAM_INVITE_DESKTOP_NOTICE).not.toMatch(/RPC|unsupported|not yet|ships/i);
  });

  it('builds CLI commands for handoff actions', () => {
    expect(
      teamInviteIssueCliCommand({
        ...defaultIssueForm(),
        recipientLabel: 'Alice Smith',
        deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
        role: 'developer',
        profiles: 'dev, qa',
      }),
    ).toBe(
      "locket team invite 'Alice Smith' --device lkdev2_abcdef0123456789abcdef --profile dev --profile qa --role developer",
    );
    expect(
      teamInviteAcceptCliCommand('-----BEGIN LOCKET TEAM INVITE-----\nabc123\n-----END-----'),
    ).toBe(
      "cat <<'LOCKET_INVITE' | locket team accept -\n" +
        '-----BEGIN LOCKET TEAM INVITE-----\n' +
        'abc123\n' +
        '-----END-----\n' +
        'LOCKET_INVITE',
    );
    expect(teamInviteRevokeCliCommand('lk_invite_123')).toBe(
      'locket team revoke-invite lk_invite_123',
    );
    expect(
      teamInviteIssueCliCommand({
        ...defaultIssueForm(),
        recipientLabel: "$(touch '/tmp/pwned')",
        deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
        role: 'developer',
        profiles: 'dev',
      }),
    ).toContain("'$(touch '\\''/tmp/pwned'\\'')'");
  });

  it('adds an expires-in duration when the issue expiry field is set', () => {
    const nowMs = Date.parse('2026-06-26T12:00:00.000Z');
    const command = teamInviteIssueCliCommand(
      {
        ...defaultIssueForm(),
        recipientLabel: 'Alice Smith',
        deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
        role: 'developer',
        profiles: 'dev',
        expiresAt: '2026-06-28T12:00:00.000Z',
      },
      { nowMs },
    );
    expect(command).toContain('--expires-in 2d');
  });

  it('normalizes ISO expiry values to the CLI duration grammar', () => {
    const nowMs = Date.parse('2026-06-26T12:00:00.000Z');
    expect(expiresAtToDurationArgument('2026-06-26T12:45:00.000Z', nowMs)).toBe('45m');
    expect(expiresAtToDurationArgument('2026-06-26T12:00:30.000Z', nowMs)).toBe('30s');
    expect(expiresAtToDurationArgument('2026-07-10T12:00:00.000Z', nowMs)).toBe('2w');
  });

  it('chooses a safe heredoc delimiter for pasted invite text', () => {
    const command = teamInviteAcceptCliCommand(
      'header\nLOCKET_INVITE\nLOCKET_INVITE_1\npayload\nfooter',
    );
    expect(command).toContain("cat <<'LOCKET_INVITE_2' | locket team accept -\n");
    expect(command).toContain('\nLOCKET_INVITE_2');
    expect(command).not.toContain('<invite-file>');
  });

  it('builds an agent invite request command from a local device descriptor', () => {
    expect(agentInviteRequestCliCommand(' lkdev2_abcdef0123456789abcdef ')).toBe(
      'locket agent invite request --device lkdev2_abcdef0123456789abcdef',
    );
    expect(agentInviteRequestCliCommand("lkdev2_abc'quoted value")).toBe(
      "locket agent invite request --device 'lkdev2_abc'\\''quoted value'",
    );
  });

  it('builds an agent invite create command with shell-safe fields', () => {
    const nowMs = Date.parse('2026-06-26T12:00:00.000Z');
    const command = agentInviteCreateCliCommand(
      {
        ...defaultIssueForm(),
        recipientLabel: "Build Agent 'West'",
        deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
        role: 'maintainer',
        profiles: 'dev, qa-prod',
        expiresAt: '2026-06-26T14:00:00.000Z',
      },
      { nowMs },
    );

    expect(command).toBe(
      "locket agent invite create 'Build Agent '\\''West'\\''' --device lkdev2_abcdef0123456789abcdef --profile dev --profile qa-prod --role maintainer --expires-in 2h",
    );
  });

  it('builds a heredoc stdin command for accepting pasted agent invite text', () => {
    const command = agentInviteAcceptCliCommand(
      '-----BEGIN LOCKET AGENT INVITE-----\nLOCKET_AGENT_INVITE\nsealed\n-----END-----',
    );

    expect(command).toBe(
      "cat <<'LOCKET_AGENT_INVITE_1' | locket agent invite accept -\n" +
        '-----BEGIN LOCKET AGENT INVITE-----\n' +
        'LOCKET_AGENT_INVITE\n' +
        'sealed\n' +
        '-----END-----\n' +
        'LOCKET_AGENT_INVITE_1',
    );
  });
});

describe('validateIssueForm', () => {
  it('accepts a well-formed invite with a developer role', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
      role: 'developer',
      profiles: 'dev, qa',
      dangerousProfiles: 'prod',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    });
    expect(result.valid).toBe(true);
    expect(result.dangerousMatches).toEqual([]);
  });

  it('rejects an invalid descriptor prefix', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'badprefix_xxxx',
      profiles: 'dev',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.deviceDescriptor).toMatch(/lkdev2_/);
  });

  it('flags dangerous profile inclusion', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
      profiles: 'dev, prod',
      dangerousProfiles: 'prod',
    });
    expect(result.valid).toBe(true);
    expect(result.dangerousMatches).toEqual(['prod']);
    expect(issueRequiresDangerousConfirmation(result)).toBe(true);
    expect(issueDangerousConfirmationMatches(result, 'prod')).toBe(true);
    expect(issueDangerousConfirmationMatches(result, '')).toBe(false);
  });

  it('rejects past expiry', () => {
    const result = validateIssueForm({
      ...defaultIssueForm(),
      recipientLabel: 'alice',
      deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
      profiles: 'dev',
      expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
    });
    expect(result.valid).toBe(false);
    expect(result.errors.expiresAt).toMatch(/future/);
  });
});

describe('issueFormToPayload', () => {
  it('echoes dangerous matches into the confirmation array', () => {
    const payload = issueFormToPayload({
      ...defaultIssueForm(),
      recipientLabel: 'bob',
      deviceDescriptor: 'lkdev2_abcdef0123456789abcdef',
      profiles: 'dev, prod, qa',
      dangerousProfiles: 'prod',
      role: 'maintainer',
      expiresAt: '',
    });
    expect(payload.profiles).toEqual(['dev', 'prod', 'qa']);
    expect(payload.dangerous_profile_confirmation).toEqual(['prod']);
    expect(payload.role).toBe('maintainer');
    expect(payload.expires_at_unix_nanos).toBeNull();
  });
});

describe('validateAcceptForm', () => {
  const longInvite = 'a'.repeat(80);

  it('accepts well-formed input with hex fingerprint', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'a'.repeat(64),
      requireUserVerification: false,
      userVerified: false,
    });
    expect(result.valid).toBe(true);
  });

  it('requires user verification when gated', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'b'.repeat(64),
      requireUserVerification: true,
      userVerified: false,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.userVerified).toMatch(/verification/);
  });

  it('rejects a non-hex fingerprint', () => {
    const result = validateAcceptForm({
      inviteText: longInvite,
      fingerprintConfirmation: 'not-hex',
      requireUserVerification: false,
      userVerified: false,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.fingerprintConfirmation).toMatch(/hexadecimal/);
  });
});

describe('acceptFormToPayload', () => {
  it('lowercases the fingerprint', () => {
    const payload = acceptFormToPayload({
      inviteText: 'a'.repeat(80),
      fingerprintConfirmation: 'A'.repeat(64),
      requireUserVerification: false,
      userVerified: true,
    });
    expect(payload.fingerprint_confirmation).toBe('a'.repeat(64));
    expect(payload.user_verified).toBe(true);
  });
});

describe('validateRevokeForm', () => {
  it('requires the typed confirmation to match the id exactly', () => {
    expect(
      validateRevokeForm({ ...defaultRevokeForm(), inviteId: 'lk_invite_1', confirmation: '' })
        .valid,
    ).toBe(false);
    expect(
      validateRevokeForm({
        ...defaultRevokeForm(),
        inviteId: 'lk_invite_1',
        confirmation: 'lk_invite_2',
      }).valid,
    ).toBe(false);
    expect(
      validateRevokeForm({
        ...defaultRevokeForm(),
        inviteId: 'lk_invite_1',
        confirmation: 'lk_invite_1',
      }).valid,
    ).toBe(true);
  });

  it('requires an lk_invite id without control characters', () => {
    const wrongPrefix = validateRevokeForm({
      ...defaultRevokeForm(),
      inviteId: 'invite_123',
      confirmation: 'invite_123',
    });
    expect(wrongPrefix.valid).toBe(false);
    expect(wrongPrefix.errors.inviteId).toMatch(/lk_invite_/);

    const controlCharacter = validateRevokeForm({
      ...defaultRevokeForm(),
      inviteId: 'lk_invite_12\n34',
      confirmation: 'lk_invite_12\n34',
    });
    expect(controlCharacter.valid).toBe(false);
    expect(controlCharacter.errors.inviteId).toMatch(/control characters/);
  });
});

describe('revokeFormToPayload', () => {
  it('returns the typed invite id', () => {
    expect(
      revokeFormToPayload({
        ...defaultRevokeForm(),
        inviteId: ' lk_invite_99 ',
        confirmation: 'lk_invite_99',
      }),
    ).toEqual({ invite_id: 'lk_invite_99' });
  });
});

describe('teamInviteRowsFromAudit', () => {
  function row(overrides: Partial<AuditWireRow>): AuditWireRow {
    return {
      sequence: 0,
      timestamp: 1_700_000_000_000_000_000,
      profile_id: null,
      action: 'TEAM_INVITE',
      status: 'OK',
      secret_name: null,
      command: null,
      ...overrides,
    };
  }

  it('reconstructs metadata-only rows from audit metadata', () => {
    const future = Date.now() * 1_000_000 + 86_400_000_000_000;
    const rows = teamInviteRowsFromAudit([
      row({
        sequence: 1,
        command: JSON.stringify({
          invite_id: 'inv-1',
          recipient_label: 'alice',
          role: 'developer',
          profiles: ['dev'],
          direction: 'issued',
          expires_at_unix_nanos: future,
        }),
      }),
    ]);
    expect(rows).toHaveLength(1);
    const single = rows[0];
    expect(single?.id).toBe('inv-1');
    expect(single?.status).toBe('pending');
    expect(single?.role).toBe('developer');
    expect(single?.profiles).toEqual(['dev']);
    expect(single?.direction).toBe('issued');
  });

  it('marks revoked invites as revoked', () => {
    const rows = teamInviteRowsFromAudit([
      row({
        sequence: 2,
        command: JSON.stringify({ invite_id: 'inv-2', recipient_label: 'bob' }),
      }),
      row({
        sequence: 3,
        status: 'REVOKED',
        command: JSON.stringify({ invite_id: 'inv-2' }),
      }),
    ]);
    expect(rows[0]?.status).toBe('revoked');
  });

  it('marks expired invites as expired', () => {
    const past = 1_500_000_000_000_000_000;
    const rows = teamInviteRowsFromAudit(
      [
        row({
          sequence: 4,
          command: JSON.stringify({
            invite_id: 'inv-3',
            expires_at_unix_nanos: past,
            direction: 'received',
          }),
        }),
      ],
      { now_unix_nanos: past + 1_000_000_000 },
    );
    expect(rows[0]?.status).toBe('expired');
  });

  it('skips non-TEAM_INVITE rows', () => {
    const rows = teamInviteRowsFromAudit([
      row({ sequence: 5, action: 'REVEAL' }),
      row({
        sequence: 6,
        command: JSON.stringify({ invite_id: 'inv-only' }),
      }),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.id).toBe('inv-only');
  });
});

describe('defaults', () => {
  it('provide stable starting values', () => {
    expect(defaultIssueForm().role).toBe('developer');
    expect(defaultAcceptForm().requireUserVerification).toBe(false);
    expect(defaultRevokeForm().inviteId).toBe('');
  });
});
