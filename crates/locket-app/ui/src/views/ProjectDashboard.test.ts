import { expect, it, vi } from 'vitest';
import ProjectDashboard from './ProjectDashboard.vue';
import { button, byProp, click, mountComponent, nodeBy, nodeText, settle } from '../test/renderer';

it('routes setup actions and distinguishes unavailable metadata, empty counts, and failed checks', async () => {
  const onAction = vi.fn();
  const onNavigate = vi.fn();
  const onRefresh = vi.fn();
  const app = mountComponent(ProjectDashboard, {
    lockLabel: 'No project',
    projectLabel: '—',
    profileLabel: '—',
    loading: false,
    setupComplete: false,
    projectConnected: false,
    connected: false,
    secretsLoaded: false,
    policiesLoaded: false,
    secrets: [],
    versions: [],
    sessions: [],
    auditRows: [],
    findings: [],
    policies: [],
    auditChainOk: null,
    scanLocked: false,
    settings: { unlockTtlSeconds: 0, agentVersion: 'fixture' },
    onAction,
    onNavigate,
    onRefresh,
  });
  const { root, setProps } = app;
  const metric = (label: string) =>
    nodeBy(root, (node) => node.tag === 'button' && nodeText(node).startsWith(label));
  try {
    expect(nodeText(metric('Secrets'))).toBe('Secrets — Open a project');
    expect(nodeText(metric('Recorded runs'))).toBe('Recorded runs — Open a project');
    await click(button(root, 'Connect project'));
    expect(onAction).toHaveBeenLastCalledWith('connect');
    setProps({ projectConnected: true, connected: true, lockLabel: 'Connecting…', loading: true });
    await settle();
    expect(button(root, 'Refreshing…').props.disabled).toBe(true);
    expect(nodeText(metric('Secrets'))).toBe('Secrets Unknown Not loaded');
    expect(nodeText(metric('Recorded runs'))).toBe('Recorded runs Unknown Not loaded');

    setProps({ lockLabel: 'Locked', loading: false });
    await settle();
    await click(button(root, 'Unlock'));
    expect(onAction).toHaveBeenLastCalledWith('unlock');

    setProps({ lockLabel: 'Unlocked' });
    await settle();
    await click(button(root, 'Retry load'));
    expect(onAction).toHaveBeenLastCalledWith('refresh');
    await click(button(root, 'Refresh'));
    expect(onRefresh).toHaveBeenCalledOnce();

    const checkedAt = '2026-06-26T12:00:00Z';
    setProps({
      secretsLoaded: true,
      policiesLoaded: true,
      lastScanAt: checkedAt,
      scanLocked: true,
      auditChainOk: false,
      auditLastRefreshed: checkedAt,
      auditError: 'Audit check failed.',
    });
    await settle();
    expect(nodeText(metric('Secrets'))).toBe('Secrets 0 0 required');
    expect(nodeText(metric('Project scan'))).toContain('Limited scan Checked');
    expect(nodeText(metric('Audit chain'))).toContain('Verification failed Checked');
    expect(nodeText(byProp(root, 'role', 'alert'))).toBe(
      'Audit check failed. Retry from Activity.',
    );
    await click(button(root, 'Add variables'));
    expect(onAction).toHaveBeenLastCalledWith('secret-editor');
    await click(metric('Project scan'));
    expect(onNavigate).toHaveBeenLastCalledWith('scan');
    await click(metric('Audit chain'));
    expect(onNavigate).toHaveBeenLastCalledWith('audit');
    await click(metric('Secrets'));
    expect(onNavigate).toHaveBeenLastCalledWith('secrets');

    setProps({ scanError: 'Scan unavailable.' });
    await settle();
    expect(nodeText(metric('Project scan'))).toContain('Scan failed');
    expect(nodeText(root)).toContain('Scan unavailable. Retry the scan.');
  } finally {
    app.unmount();
  }
});
