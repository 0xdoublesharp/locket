import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { desktopVariableReadiness } from '../agent/client';
import { findNode, mountComponent, settle, type TestNode } from '../test/renderer';
import type { CommandPolicyRow } from '../types/views';
import PolicyEditor from './PolicyEditor.vue';

vi.mock('../agent/client', { spy: true });

function textOf(node: TestNode): string {
  if (node.tag === '#comment') return '';
  return `${node.text}${node.children.map(textOf).join(' ')}`.replace(/\s+/g, ' ').trim();
}

const sampleRows: CommandPolicyRow[] = [
  {
    id: 'policy-1',
    name: 'deploy-prod',
    alias: 'Command 1',
    commandKind: 'argv',
    commandPreview: 'curl -H "Authorization: lk://prod/STRIPE_SECRET_KEY" https://api.example.com',
    requiredSecrets: ['STRIPE_SECRET_KEY'],
    optionalSecrets: [],
    allowedSecrets: ['STRIPE_SECRET_KEY'],
    confirm: true,
    requireUserVerification: true,
    requireAgent: true,
    allowRemoteDocker: true,
    ttlSeconds: 900,
    envMode: 'strict',
    overrideMode: 'locket',
    updatedAt: '2026-11-24T17:00:00.000Z',
  },
];

beforeEach(() => {
  vi.resetAllMocks();
  vi.stubGlobal('Document', class {});
  vi.stubGlobal('ShadowRoot', class {});
  vi.mocked(desktopVariableReadiness).mockResolvedValue({
    ok: true,
    value: {
      project_id: 'acme-api',
      profile_id: 'acme-api-dev',
      profile_name: 'dev',
      policies: [{ policy_name: 'deploy-prod', profile_id: 'acme-api-dev', rows: [] }],
    },
  });
});

afterEach(() => vi.unstubAllGlobals());

it('redacts commandPreview from display and search when privacyMode is enabled', async () => {
  const view = mountComponent<{ searchQuery: string }>(PolicyEditor, {
    projectId: 'acme-api',
    profileId: 'acme-api-dev',
    rows: sampleRows,
    privacyMode: true,
    loading: false,
    metadataLoaded: true,
    actionsEnabled: true,
  });

  try {
    await settle();
    const detail = findNode(view.root, (node) => node.props.id === 'policy-detail');
    expect(detail).toBeDefined();
    expect(textOf(detail!)).toContain('Hidden in privacy mode');
    expect(textOf(detail!)).not.toContain('lk://');
    expect(textOf(detail!)).not.toContain('STRIPE_SECRET_KEY');

    view.state.searchQuery = 'lk://prod/STRIPE_SECRET_KEY';
    await settle();
    expect(
      findNode(view.root, (node) => node.text.includes('No matching policies.')),
    ).toBeDefined();

    view.state.searchQuery = 'Command 1';
    await settle();
    expect(findNode(view.root, (node) => node.props.id === 'policy-detail')).toBeDefined();
  } finally {
    view.unmount();
  }
});

it('re-runs configuration checks in place when Refresh is clicked and keeps accessible row and gate consistency', async () => {
  const onRefresh = vi.fn();
  const view = mountComponent(PolicyEditor, {
    projectId: 'acme-api',
    profileId: 'acme-api-dev',
    rows: sampleRows,
    privacyMode: false,
    loading: false,
    metadataLoaded: true,
    actionsEnabled: true,
    onRefresh,
  });

  try {
    await settle();
    expect(desktopVariableReadiness).toHaveBeenCalledTimes(1);

    const row = findNode(view.root, (node) => node.tag === 'tr' && node.props.tabindex === '0');
    expect(row?.props['aria-current']).toBe('true');
    expect(row?.props['aria-selected']).toBeUndefined();

    const detailGates = findNode(
      view.root,
      (node) => node.props['aria-labelledby'] === 'policy-gates-heading',
    );
    expect(detailGates).toBeDefined();
    expect(textOf(detailGates!)).toBe('Gates confirm verify user agent required remote docker');

    const refreshButton = findNode(
      view.root,
      (node) => node.tag === 'button' && node.props['aria-label'] === 'Refresh commands',
    );
    expect(refreshButton).toBeDefined();
    (refreshButton!.props.onClick as () => void)();
    await settle();

    expect(onRefresh).toHaveBeenCalledTimes(1);
    expect(desktopVariableReadiness).toHaveBeenCalledTimes(2);
  } finally {
    view.unmount();
  }
});
