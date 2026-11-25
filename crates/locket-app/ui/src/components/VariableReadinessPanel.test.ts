import { expect, it, vi } from 'vitest';
import { desktopVariableReadiness } from '../agent/client';
import { findNode, mountComponent, settle } from '../test/renderer';
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
