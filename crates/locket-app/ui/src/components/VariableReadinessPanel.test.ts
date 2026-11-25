import { expect, it, vi } from 'vitest';
import type { VariableReadinessResponse } from '../agent/types';
import { desktopVariableReadiness, type AgentResult } from '../agent/client';
import {
  button,
  byProp,
  click,
  deferred,
  findNode,
  mountComponent,
  nodeText,
  settle,
} from '../test/renderer';
import VariableReadinessPanel from './VariableReadinessPanel.vue';

vi.mock('../agent/client', { spy: true });

it('summarizes only the selected command even when other checks fail', async () => {
  vi.mocked(desktopVariableReadiness).mockResolvedValueOnce({
    ok: true,
    value: {
      project_id: 'project',
      profile_id: 'dev',
      profile_name: 'dev',
      policies: [
        { policy_name: 'selected', profile_id: 'dev', rows: [] },
        { policy_name: 'other', profile_id: 'dev', rows: [], error: 'Access denied' },
      ],
    },
  });

  const panel = mountComponent(VariableReadinessPanel, {
    projectId: 'project',
    policyName: 'selected',
  });
  try {
    await settle();
    const summary = findNode(panel.root, (node) => node.props.role === 'status');
    expect(summary?.text).toContain('No variables requested');
  } finally {
    panel.unmount();
  }
});

it('ignores a delayed check after an environment switch and reports mismatched or failed results', async () => {
  const old = deferred<AgentResult<VariableReadinessResponse>>();
  const client = vi.mocked(desktopVariableReadiness);
  client
    .mockReturnValueOnce(old.promise)
    .mockResolvedValueOnce({
      ok: true,
      value: { project_id: 'project', profile_id: 'dev', profile_name: 'dev', policies: [] },
    })
    .mockResolvedValueOnce({
      ok: false,
      error: { kind: 'protocol', reason: 'fixture-sensitive-diagnostic' },
    })
    .mockResolvedValueOnce({
      ok: true,
      value: { project_id: 'project', profile_id: 'qa', profile_name: 'qa', policies: [] },
    });
  const onBlocked = vi.fn();
  const panel = mountComponent(VariableReadinessPanel, {
    projectId: 'project',
    profileId: 'dev',
    policyName: 'build',
    onBlocked,
  });
  const { root, setProps } = panel;
  try {
    expect(nodeText(root)).toContain('Checking variable names and sources');
    setProps({ profileId: 'qa' });
    await settle();
    expect(nodeText(byProp(root, 'role', 'alert'))).toBe(
      'The project or environment changed. Refresh configuration checks.',
    );
    old.resolve({
      ok: true,
      value: {
        project_id: 'project',
        profile_id: 'dev',
        profile_name: 'private-old-environment',
        policies: [
          {
            policy_name: 'build',
            profile_id: 'dev',
            rows: [
              {
                name: 'PRIVATE_OLD_KEY',
                required: true,
                classification: 'secret',
                state: 'missing',
              },
            ],
          },
        ],
      },
    });
    await settle();
    expect(nodeText(root)).not.toMatch(/PRIVATE_OLD_KEY|private-old-environment/);
    expect(onBlocked).not.toHaveBeenCalledWith(true);
    await click(button(root, 'Refresh'));
    expect(nodeText(byProp(root, 'role', 'alert'))).toContain(
      'Configuration checks are unavailable.',
    );
    expect(nodeText(root)).not.toContain('fixture-sensitive-diagnostic');
    await click(button(root, 'Refresh'));
    expect(nodeText(root)).toContain('No variables requested.');
    expect(nodeText(root)).toContain('Environment: qa');
  } finally {
    panel.unmount();
    client.mockReset();
  }
});

it('keeps warnings actionable and redacts variable labels, source hints, and diagnostics when privacy is enabled', async () => {
  const response: VariableReadinessResponse = {
    project_id: 'project',
    profile_id: 'prod',
    profile_name: 'production',
    policies: [
      {
        policy_name: 'deploy',
        profile_id: 'prod',
        rows: [
          {
            name: 'PRIVATE_KEY_NAME',
            required: true,
            classification: 'secret',
            state: 'missing',
            selected_source: 'team',
            description: 'private-owner-detail',
            warning: 'private-prefix-warning',
          },
          {
            name: 'PUBLIC_SETTING',
            required: false,
            classification: 'public',
            state: 'unverified',
            selected_source: 'public-default',
          },
        ],
      },
      { policy_name: 'private-command', profile_id: 'prod', rows: [], error: 'private-diagnostic' },
    ],
  };
  vi.mocked(desktopVariableReadiness).mockResolvedValue({ ok: true, value: response });
  const onBlocked = vi.fn();
  const panel = mountComponent(VariableReadinessPanel, {
    projectId: 'project',
    profileId: 'prod',
    policyName: 'deploy',
    onBlocked,
    collapsible: true,
  });
  try {
    await settle();
    expect(onBlocked).toHaveBeenLastCalledWith(true);
    expect(nodeText(panel.root)).toContain('1 required variable missing');
    expect(nodeText(panel.root)).toContain('External sources will be checked at launch.');
    expect(nodeText(panel.root)).toContain('PRIVATE_KEY_NAME Shared');
    expect(nodeText(panel.root)).toContain('private-owner-detail');
    expect(nodeText(panel.root)).toContain('private-prefix-warning');
    panel.setProps({ privacyMode: true, policyName: undefined });
    await settle();
    expect(nodeText(panel.root)).toContain('1 command could not be checked');
    expect(nodeText(panel.root)).toContain('Configuration check unavailable for this command.');
    expect(nodeText(panel.root)).toContain(
      'A secret uses a prefix that may expose values in browser bundles.',
    );
    expect(nodeText(panel.root)).not.toMatch(
      /production|PRIVATE_KEY_NAME|PUBLIC_SETTING|private-(owner-detail|prefix-warning|diagnostic|command)/,
    );
  } finally {
    panel.unmount();
    vi.mocked(desktopVariableReadiness).mockReset();
  }
});
