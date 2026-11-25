import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { desktopVariableReadiness } from '../agent/client';
import {
  button,
  byProp,
  click,
  findNode,
  input,
  mountComponent,
  nodeText,
  settle,
  type TestNode,
} from '../test/renderer';
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
  const view = mountComponent(PolicyEditor, {
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

    const search = byProp(view.root, 'type', 'search');
    await input(search, 'lk://prod/STRIPE_SECRET_KEY');
    expect(
      findNode(view.root, (node) => node.text.includes('No matching policies.')),
    ).toBeDefined();

    await input(search, 'Command 1');
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

it('blocks terminal launch on missing required variables and focuses the selected command detail', async () => {
  const first = sampleRows[0]!;
  const other: CommandPolicyRow = {
    ...first,
    id: 'policy-2',
    name: 'inspect',
    commandPreview: 'pnpm run inspect',
    commandKind: 'shell',
    requiredSecrets: [],
    optionalSecrets: [],
    allowedSecrets: [],
    confirm: false,
    requireUserVerification: false,
    requireAgent: false,
    allowRemoteDocker: false,
    ttlSeconds: 0,
  };
  vi.mocked(desktopVariableReadiness).mockResolvedValueOnce({
    ok: true,
    value: {
      project_id: 'acme-api',
      profile_id: 'acme-api-dev',
      profile_name: 'dev',
      policies: [
        {
          policy_name: 'deploy-prod',
          profile_id: 'acme-api-dev',
          rows: [
            {
              name: 'STRIPE_SECRET_KEY',
              required: true,
              classification: 'secret',
              state: 'missing',
            },
          ],
        },
      ],
    },
  });
  const onRun = vi.fn();
  const view = mountComponent(PolicyEditor, {
    projectId: 'acme-api',
    profileId: 'acme-api-dev',
    rows: [first, other],
    privacyMode: false,
    loading: false,
    metadataLoaded: true,
    actionsEnabled: true,
    onRun,
    detectingCommands: true,
  });
  const { root } = view;
  try {
    await settle();
    expect(button(root, 'Run in terminal').props.disabled).toBe(true);
    expect(nodeText(root)).toContain('1 required variable missing');
    expect(nodeText(root)).toContain('Looking for commands');
    expect(onRun).not.toHaveBeenCalled();
    const row = byProp(root, 'aria-label', 'Inspect policy inspect');
    expect(nodeText(row)).toContain('inspect shell 0 0s');
    expect(nodeText(row)).toContain('none');
    row.dispatchEvent(Object.assign(new Event('keydown', { cancelable: true }), { key: 'Enter' }));
    await settle();
    expect(row.props['aria-current']).toBe('true');
    const focus = vi.fn();
    Object.assign(byProp(root, 'id', 'policy-detail'), { focus });
    await click(button(root, 'Show selected command details'));
    expect(focus).toHaveBeenCalledOnce();
    await click(button(root, 'Run in terminal'));
    expect(onRun).toHaveBeenCalledExactlyOnceWith(other);
    view.setProps({ detectingCommands: false, detectionError: 'Command detection failed.' });
    await settle();
    expect(nodeText(root)).toContain('Command detection failed.');
  } finally {
    view.unmount();
  }
});
