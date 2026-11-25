import { afterEach, expect, it, vi } from 'vitest';
import TeamInviteView from './TeamInviteView.vue';
import type { AuditWireRow } from '../agent/types';
import {
  button,
  byProp,
  check,
  click,
  control,
  findNode,
  input,
  mountComponent,
  nodeText,
  settle,
} from '../test/renderer';

const mounts: ReturnType<typeof mountComponent>[] = [];
function teamInvites(props: Record<string, unknown> = {}) {
  const onRefresh = vi.fn();
  const view = mountComponent(TeamInviteView, {
    auditRows: [],
    dangerousProfiles: 'prod',
    requireAcceptUserVerification: true,
    loading: false,
    metadataLoaded: true,
    onRefresh,
    ...props,
  });
  mounts.push(view);
  return { ...view, onRefresh };
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
});

function auditInvite(sequence: number, status: string, details: object): AuditWireRow {
  return {
    sequence,
    timestamp: 1_750_000_000_000_000_000,
    action: 'TEAM_INVITE',
    status,
    command: JSON.stringify({ invite_id: `lk_invite_${sequence}`, ...details }),
    profile_id: null,
    secret_name: null,
  };
}

it('renders searchable metadata-only invite history and hides the advanced surface in privacy mode', async () => {
  const { root, setProps, onRefresh } = teamInvites({
    loading: true,
    lastRefreshedAt: '2026-06-26T12:00:00Z',
    auditRows: [
      auditInvite(1, 'OK', {
        direction: 'issued',
        recipient_label: 'Build Runner',
        profiles: ['dev'],
        role: 'developer',
        encrypted_payload: 'fixture-opaque-payload',
      }),
      auditInvite(2, 'ACCEPTED', { direction: 'received', issuer_label: 'Platform Team' }),
      auditInvite(3, 'REVOKED', { direction: 'issued' }),
      auditInvite(4, 'OK', { expires_at_unix_nanos: 1_500_000_000_000_000_000 }),
      auditInvite(5, 'UNKNOWN', {}),
    ],
  });
  expect(nodeText(root)).toContain('Loading invite history');
  expect(button(root, 'Refresh').props.disabled).toBe(true);
  setProps({
    loading: false,
    actionGuidance: 'Unlock to retrieve history.',
    errorMessage: 'Invite history unavailable.',
  });
  await settle();
  expect(nodeText(root)).toContain('Unlock to retrieve history.');
  expect(nodeText(root)).toContain('Invite history unavailable.');
  setProps({ actionGuidance: null, errorMessage: null });
  await settle();
  expect(nodeText(root)).toContain('lk_invite_1 issued pending Build Runner developer dev');
  expect(nodeText(root)).toContain('lk_invite_2 received accepted Platform Team');
  expect(nodeText(root)).toContain('lk_invite_3 issued revoked');
  expect(nodeText(root)).toContain('lk_invite_4 unknown expired');
  expect(nodeText(root)).toContain('lk_invite_5 unknown unknown');
  expect(nodeText(root)).not.toContain('fixture-opaque-payload');
  const search = byProp(root, 'type', 'search');
  await input(search, ' platform TEAM ');
  expect(nodeText(root)).toContain('lk_invite_2');
  expect(nodeText(root)).not.toContain('lk_invite_1');
  await input(search, 'fixture-opaque-payload');
  expect(nodeText(root)).toContain('No matching invites in audit history.');
  await click(button(root, 'Refresh'));
  expect(onRefresh).toHaveBeenCalledOnce();
  setProps({ privacyMode: true });
  await settle();
  expect(nodeText(root)).toContain('Signed team updates');
  expect(nodeText(root)).not.toMatch(
    /Pending and recent invites|Issue invite|Accept invite|Revoke invite/,
  );
  expect(findNode(root, (node) => node.props.type === 'search')).toBeUndefined();
});

it('gates issue commands on validation and exact dangerous environment confirmation', async () => {
  const { root, setProps } = teamInvites({ metadataLoaded: false });
  expect(nodeText(root)).toContain('Complete the fields to show the CLI command.');
  const field = (suffix: string) => byProp(root, 'data-testid', `team-invite-${suffix}`);
  await input(field('recipient'), 'Release Team');
  await input(field('descriptor'), 'lkdev2_fixture2026Descriptor');
  await input(field('profiles'), 'dev, prod');
  await input(byProp(root, 'type', 'datetime-local'), '2000-01-01T00:00');
  expect(nodeText(root)).toMatch(/future/);
  await input(byProp(root, 'type', 'datetime-local'), '');
  expect(nodeText(root)).toContain('dangerous profile(s)');
  expect(nodeText(root)).not.toContain('Agent request command');
  setProps({ metadataLoaded: true });
  await settle();
  expect(byProp(root, 'aria-label', 'Agent request command').value).toContain(
    'locket agent invite request',
  );
  await input(field('dangerous-confirmation'), 'dev');
  expect(nodeText(root)).not.toContain('Issue invite command');
  await input(field('dangerous-confirmation'), 'prod');
  expect(byProp(root, 'aria-label', 'Issue invite command').value).toContain(
    '--profile dev --profile prod',
  );
  expect(byProp(root, 'aria-label', 'Agent invite command').value).toContain(
    'locket agent invite create',
  );
});

it('requires fingerprint and user verification before accept, and matching invite IDs before revoke', async () => {
  const { root } = teamInvites();
  const field = (suffix: string) => byProp(root, 'data-testid', `team-invite-${suffix}`);
  await input(field('accept-text'), 'opaque-fixture-invite-'.repeat(5));
  await input(field('accept-fingerprint'), 'invalid');
  expect(nodeText(root)).toContain('Fingerprint must be 64 hexadecimal characters');
  await input(field('accept-fingerprint'), 'b'.repeat(64));
  expect(nodeText(root)).not.toContain('Accept pasted invite command');
  await check(control(root, 'I have completed local user verification'));
  expect(byProp(root, 'aria-label', 'Accept pasted invite command').value).toContain(
    'locket team accept -',
  );
  expect(byProp(root, 'aria-label', 'Accept pasted agent invite command').value).toContain(
    'locket agent invite accept -',
  );

  await input(field('revoke-id'), 'invalid');
  expect(nodeText(root)).toContain('Invite id must begin with lk_invite_');
  await input(field('revoke-id'), 'lk_invite_fixture');
  await input(field('revoke-confirm'), 'lk_invite_other');
  expect(nodeText(root)).not.toContain('Revoke invite command');
  await input(field('revoke-confirm'), 'lk_invite_fixture');
  expect(byProp(root, 'aria-label', 'Revoke invite command').value).toBe(
    'locket team revoke-invite lk_invite_fixture',
  );
});
