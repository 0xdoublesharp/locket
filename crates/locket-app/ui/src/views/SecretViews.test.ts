import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import SecretEditorView, { type SetSecretAction } from './SecretEditorView.vue';
import SecretMetadataList from './SecretMetadataList.vue';
import SecretVersionHistory from './SecretVersionHistory.vue';
import type { SecretRowMeta, VersionHistoryRow } from '../types/views';
import type { AgentResult, SetSecretResponse } from '../agent/client';
import {
  button,
  byProp,
  click,
  control,
  deferred,
  findNode,
  input,
  mountComponent,
  nodeBy,
  nodeText,
  select,
  settle,
  submit,
} from '../test/renderer';

vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn().mockResolvedValue(() => {}) }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

const mounts: ReturnType<typeof mountComponent>[] = [];
function mount(...args: Parameters<typeof mountComponent>) {
  const mounted = mountComponent(...args);
  mounts.push(mounted);
  return mounted;
}

beforeEach(() => {
  vi.stubGlobal(
    'window',
    Object.assign(new EventTarget(), { matchMedia: () => ({ matches: false }) }),
  );
});

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
  vi.resetAllMocks();
  vi.unstubAllGlobals();
});

const timestamp = '2026-06-26T12:00:00Z';
const fixtureValue = 'fixture-only-plaintext';
const secret: SecretRowMeta = {
  id: 'variable-1',
  name: 'PRIVATE_TOKEN',
  alias: 'Variable A',
  source: 'team',
  required: true,
  optional: false,
  createdAt: timestamp,
  rotatedAt: timestamp,
  currentVersion: 4,
  hasDeprecatedGrace: true,
  ownerLabel: 'Finance',
  tags: ['restricted'],
  deprecatedReferenceWarnings: [
    {
      version: 3,
      status: 'active-grace',
      surface: 'policy',
      graceUntil: '2099-01-01T00:00:00Z',
      referenceCount: 1,
    },
    { version: 2, status: 'expired-grace', surface: 'command-preview', referenceCount: 2 },
  ],
};
const override: SecretRowMeta = {
  id: 'variable-2',
  name: 'PERSONAL_SETTING',
  alias: 'Variable B',
  source: 'user-local',
  required: false,
  optional: true,
  createdAt: timestamp,
  currentVersion: 1,
  hasDeprecatedGrace: false,
};
const machine: SecretRowMeta = {
  ...override,
  id: 'variable-3',
  name: 'MACHINE_SETTING',
  alias: 'Variable C',
  source: 'machine-local',
};
const success: AgentResult<SetSecretResponse> = {
  ok: true,
  value: { action: 'set', secret_id: 'id', version: 5, source: 'team-managed' },
};

it('validates and submits a masked new secret, ignores duplicate submission, and refreshes on success', async () => {
  const pending = deferred<AgentResult<SetSecretResponse>>();
  const onSetSecret = vi.fn<SetSecretAction>().mockReturnValue(pending.promise);
  const onRefresh = vi.fn();
  const onManage = vi.fn();
  const { root, setProps } = mount(SecretEditorView, {
    rows: [secret, override, machine],
    privacyMode: true,
    loading: true,
    metadataLoaded: false,
    projectId: 'project',
    profileId: 'profile',
    grantId: 'grant',
    lastRefreshedAt: timestamp,
    onSetSecret,
    onRotateSecret: vi.fn(),
    onRefresh,
    onManage,
  });
  expect(nodeText(root)).toContain('Loading secret metadata');
  expect(nodeText(root)).toContain('Select an active project and environment');
  setProps({ metadataLoaded: true, loading: false });
  await settle();
  expect(findNode(root, (node) => node.tag === 'table')).toBeUndefined();
  expect(nodeText(root)).not.toContain('PRIVATE_TOKEN');
  expect(
    findNode(root, (node) => node.tag === 'option' && node.value === 'PRIVATE_TOKEN'),
  ).toBeUndefined();
  await click(button(root, 'Back to Secrets'));
  expect(onManage).toHaveBeenCalledOnce();

  const form = byProp(root, 'aria-labelledby', 'secret-editor-set-heading');
  const field = (name: string) => byProp(form, 'data-testid', `secret-editor-set-${name}`);
  expect(field('value').props.type).toBe('password');
  await click(button(form, 'Generate'));
  const token = field('value').value;
  expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(invoke).not.toHaveBeenCalled();
  await click(button(form, 'Show secret value'));
  expect(field('value').props.type).toBe('text');
  await click(button(form, 'Hide secret value'));
  expect(field('value').props.type).toBe('password');
  await input(field('name'), 'invalid-name');
  await input(field('value'), fixtureValue);
  expect(nodeText(form)).toContain('Name must match KEY_FORMAT');
  await submit(form);
  expect(onSetSecret).not.toHaveBeenCalled();
  await input(field('name'), ' NEW_TOKEN ');
  await input(control(form, 'Description'), 'x'.repeat(513));
  expect(nodeText(form)).toContain('Description is too long');
  await input(control(form, 'Description'), 'Fixture metadata');
  await select(field('source'), 'team-managed');
  await click(button(form, 'Show secret value'));
  await submit(form);
  expect(field('value').value).toBe('');
  expect(field('value').props.type).toBe('password');
  await submit(form);
  expect(onSetSecret).toHaveBeenCalledExactlyOnceWith({
    project_id: 'project',
    profile_id: 'profile',
    grant_id: 'grant',
    secret_name: 'NEW_TOKEN',
    source: 'team-managed',
    value: fixtureValue,
  });
  expect(button(form, 'Submitting…').props.disabled).toBe(true);
  pending.resolve(success);
  await settle();
  expect(nodeText(form)).toContain('NEW_TOKEN');
  expect(nodeText(form)).toContain('v5');
  expect(field('value').value).toBe('');
  expect(nodeText(root)).not.toContain(fixtureValue);
  expect(onRefresh).toHaveBeenCalledOnce();
});

it('rotates in the existing source and shows safe error labels with no plaintext', async () => {
  const onRotateSecret = vi
    .fn<SetSecretAction>()
    .mockResolvedValueOnce({ ok: false, error: { kind: 'protocol', reason: fixtureValue } })
    .mockResolvedValueOnce({
      ok: false,
      error: {
        kind: 'rejected',
        code: 'Denied',
        message: fixtureValue,
        display_reason: '',
        next_action: '',
        retryable: false,
      },
    })
    .mockResolvedValue(success);
  const onRefresh = vi.fn();
  const { root } = mount(SecretEditorView, {
    rows: [secret, machine],
    privacyMode: false,
    loading: false,
    metadataLoaded: true,
    projectId: 'project',
    profileId: 'profile',
    onSetSecret: vi.fn(),
    onRotateSecret,
    onRefresh,
    errorMessage: 'Metadata may be stale.',
    actionGuidance: 'Unlock to load updated metadata.',
  });
  expect(nodeText(root)).toContain('Metadata may be stale.');
  expect(nodeText(root)).toContain('Unlock to load updated metadata.');
  const form = byProp(root, 'aria-labelledby', 'secret-editor-rotate-heading');
  const name = control(form, 'Secret name');
  const value = byProp(form, 'id', 'secret-editor-rotate-value');
  const grace = control(form, 'Grace expiry');
  await input(name, secret.name);
  await input(value, fixtureValue);
  await input(grace, '2000-01-01T00:00');
  expect(nodeText(form)).toContain('Grace expiry must be in the future.');
  await submit(form);
  expect(onRotateSecret).not.toHaveBeenCalled();
  await input(grace, '2099-01-01T00:00');
  await submit(form);
  expect(onRotateSecret).toHaveBeenLastCalledWith(
    expect.objectContaining({
      secret_name: secret.name,
      source: 'team-managed',
      value: fixtureValue,
      grace_until: expect.any(Number),
    }),
  );
  expect(nodeText(byProp(form, 'role', 'alert'))).toBe('Request failed.');
  expect(value.value).toBe('');
  await input(value, fixtureValue);
  await submit(form);
  expect(nodeText(byProp(form, 'role', 'alert'))).toBe('Denied');
  expect(nodeText(form)).not.toContain(fixtureValue);
  await input(name, 'UNTRACKED_NAME');
  await input(value, fixtureValue);
  await submit(form);
  expect(onRotateSecret).toHaveBeenLastCalledWith(
    expect.objectContaining({ source: 'user-local' }),
  );
  expect(value.value).toBe('');
  expect(onRefresh).toHaveBeenCalledOnce();
});

it('filters metadata and gates destructive actions on the selected environment', async () => {
  const onDeleteSecret = vi.fn();
  const onCopyToShared = vi.fn();
  const onSelect = vi.fn();
  const onCopyValue = vi.fn();
  const onRevealValue = vi.fn();
  const versions: VersionHistoryRow[] = [
    {
      secretName: secret.name,
      source: 'team',
      version: 3,
      state: 'deprecated',
      graceUntil: '2099-01-01T00:00:00Z',
      pinnedReferenceEligible: true,
      scanInclusion: true,
    },
  ];
  const { root, setProps } = mount(SecretMetadataList, {
    rows: [secret, override, machine],
    versions,
    profileName: 'prod',
    profileLabel: 'Production',
    connected: true,
    canStart: false,
    starting: false,
    privacyMode: false,
    loading: false,
    metadataLoaded: true,
    canAccessValues: true,
    copyVerification: true,
    dangerousProfile: true,
    lastRefreshedAt: timestamp,
    mutationError: { id: secret.id, message: 'Previous change failed.' },
    onDeleteSecret,
    onCopyToShared,
    onSelect,
    onCopyValue,
    onRevealValue,
  });
  await click(button(root, 'Filters'));
  await select(byProp(root, 'aria-label', 'Filter by source'), 'team');
  await select(byProp(root, 'aria-label', 'Filter by requirement'), 'required');
  await select(byProp(root, 'aria-label', 'Filter by status'), 'deprecated');
  expect(nodeText(root)).not.toContain(override.name);
  await input(byProp(root, 'aria-label', 'Search secrets'), 'missing-test');
  expect(nodeText(root)).toContain('No matching secrets.');
  await click(button(root, 'Clear filters'));
  await click(button(root, 'Open metadata for PRIVATE_TOKEN'));
  expect(onSelect).toHaveBeenCalledWith(secret);
  await click(button(root, 'Details for PRIVATE_TOKEN'));
  const inspector = byProp(root, 'id', 'variable-inspector');
  expect(nodeText(inspector)).toContain('lk://prod/PRIVATE_TOKEN');
  expect(nodeText(inspector)).toContain('v3 still accepted');
  expect(nodeText(inspector)).toContain('1 policy reference');
  expect(nodeText(inspector)).toContain('v2 no longer accepted');
  expect(nodeText(inspector)).toContain('2 command preview references');
  expect(nodeText(inspector)).toContain('Previous change failed.');
  await click(button(inspector, 'Version history'));
  expect(onSelect).toHaveBeenCalledTimes(2);
  await click(button(inspector, 'Copy to Global Vault'));
  expect(onCopyToShared).toHaveBeenCalledWith(secret);
  const row = button(root, 'Details for PRIVATE_TOKEN').parent!.parent!;
  await click(button(row, 'Copy value'));
  await click(button(row, 'Reveal'));
  expect(onCopyValue).toHaveBeenCalledWith(secret);
  expect(onRevealValue).toHaveBeenCalledWith(secret);

  await click(button(inspector, 'Delete'));
  expect(button(inspector, 'Confirm delete').props.disabled).toBe(true);
  await input(byProp(inspector, 'data-testid', 'secret-delete-confirmation'), 'prod');
  await click(button(inspector, 'Cancel'));
  await click(button(inspector, 'Delete'));
  expect(button(inspector, 'Confirm delete').props.disabled).toBe(true);
  await input(byProp(inspector, 'data-testid', 'secret-delete-confirmation'), 'prod');
  await click(button(inspector, 'Confirm delete'));
  expect(onDeleteSecret).toHaveBeenCalledExactlyOnceWith(secret, 'prod');

  setProps({ privacyMode: true, canAccessValues: false, profileLabel: 'Environment A' });
  await settle();
  expect(nodeText(root)).toContain('Variable A');
  expect(nodeText(root)).not.toMatch(
    /Finance|restricted|PRIVATE_TOKEN|lk:\/\/prod|Copy value|Confirm delete/,
  );
  await input(byProp(root, 'aria-label', 'Search secrets'), 'restricted');
  expect(nodeText(root)).toContain('No matching secrets.');
  await input(byProp(root, 'aria-label', 'Search secrets'), '');
  await click(button(root, 'Details for Variable A'));
  expect(findNode(root, (node) => node.props.id === 'variable-inspector')).toBeUndefined();
});

it('offers migration guidance in an empty list and forwards only the requested actions', async () => {
  const onAdd = vi.fn();
  const onRefresh = vi.fn();
  const onOpenAgentSetup = vi.fn();
  const onImportEnv = vi.fn();
  const { root, setProps } = mount(SecretMetadataList, {
    rows: [],
    versions: [],
    profileLabel: 'Default',
    connected: true,
    metadataLoaded: true,
    canStart: false,
    starting: false,
    privacyMode: false,
    loading: false,
    onAdd,
    onRefresh,
    onOpenAgentSetup,
    onImportEnv,
    canImportEnv: true,
  });
  await click(
    button(byProp(root, 'aria-labelledby', 'variables-onboarding-heading'), 'Import .env'),
  );
  await click(
    button(
      nodeBy(root, (node) => node.tag === 'header'),
      'Import .env',
    ),
  );
  expect(onImportEnv).toHaveBeenCalledTimes(2);
  await click(button(root, 'Refresh secrets'));
  expect(onRefresh).toHaveBeenCalledOnce();
  expect(nodeText(root)).toContain('No secrets yet');
  await click(button(root, 'Add secret'));
  expect(onAdd).toHaveBeenCalledOnce();
  await click(button(root, 'AI agent & MCP setup'));
  expect(onOpenAgentSetup).toHaveBeenCalledOnce();
  vi.mocked(invoke)
    .mockResolvedValueOnce(undefined)
    .mockRejectedValueOnce({ kind: 'protocol', reason: fixtureValue });
  await click(button(root, 'Copy AI migration prompt'));
  expect(invoke).toHaveBeenCalledWith('desktop_copy_text_plain', {
    text: expect.stringContaining('locket env scan'),
  });
  expect(nodeText(root)).toContain('Copied AI migration prompt.');
  await click(button(root, 'Copy AI migration prompt'));
  expect(nodeText(root)).toContain('Could not copy AI migration prompt.');
  expect(nodeText(root)).not.toContain(fixtureValue);
  setProps({ canImportEnv: false });
  await settle();
  expect(
    findNode(root, (node) => node.tag === 'button' && nodeText(node) === 'Import .env'),
  ).toBeUndefined();
  setProps({ loading: true });
  await settle();
  expect(nodeText(root)).toContain('Loading secret metadata');
  setProps({ loading: false, actionGuidance: 'Unlock to load metadata.' });
  await settle();
  expect(nodeText(root)).toContain('Unlock to load metadata.');
});

it('expands only the chosen version audit summary and supports loading, retry, and empty history', async () => {
  const onRefresh = vi.fn();
  const { root, setProps } = mount(SecretVersionHistory, {
    rows: [],
    secretLabel: 'Variable A',
    loading: true,
    onRefresh,
  });
  expect(nodeText(root)).toContain('Loading version history');
  expect(button(root, 'Refresh').props.disabled).toBe(true);
  const rows: VersionHistoryRow[] = [
    { version: 4, state: 'current', pinnedReferenceEligible: true, scanInclusion: true },
    {
      id: 'historical-v3',
      secretName: 'Variable B',
      source: 'team',
      version: 3,
      state: 'deprecated',
      deprecatedAt: timestamp,
      graceUntil: timestamp,
      pinnedReferenceEligible: true,
      scanInclusion: true,
      rotationAuditSummary: 'Rotated by the project owner.',
    },
    { version: 2, state: 'purged', pinnedReferenceEligible: false, scanInclusion: false },
  ];
  setProps({ rows, loading: false, lastRefreshedAt: timestamp });
  await settle();
  expect(nodeText(root)).toContain('Variable A — v4 current');
  expect(nodeText(root)).toContain('Variable B team v3 deprecated');
  expect(nodeText(root)).toContain('v2 purged');
  expect(nodeText(root)).not.toContain('Rotated by');
  const expand = button(root, 'Toggle rotation audit summary for version 3');
  await click(expand);
  expect(expand.props['aria-expanded']).toBe(true);
  expect(nodeText(byProp(root, 'id', 'rotation-audit-historical-v3'))).toBe(
    'Rotated by the project owner.',
  );
  await click(expand);
  expect(expand.props['aria-expanded']).toBe(false);
  expect(nodeText(root)).not.toContain('Rotated by');
  await click(button(root, 'Refresh'));
  expect(onRefresh).toHaveBeenCalledOnce();
  setProps({ rows: [], errorMessage: 'Version history unavailable.' });
  await settle();
  expect(nodeText(root)).toContain('Version history unavailable.');
  setProps({ errorMessage: null });
  await settle();
  expect(nodeText(root)).toContain('No version history available.');
});
