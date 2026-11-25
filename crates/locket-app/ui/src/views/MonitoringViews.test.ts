import { afterEach, describe, expect, it, vi } from 'vitest';
import AuditLog from './AuditLog.vue';
import DeviceMemberDirectory from './DeviceMemberDirectory.vue';
import ExecutionMonitor from './ExecutionMonitor.vue';
import type { AuditLogRow, DeviceMemberRow, RuntimeSessionRow } from '../types/views';
import {
  button,
  byProp,
  click,
  control,
  input,
  mountComponent,
  nodeText,
  select,
  settle,
} from '../test/renderer';

const timestamp = '2026-06-26T12:00:00Z';
const metadataSentinel = 'fixture-metadata-must-stay-hidden';
const mounts: ReturnType<typeof mountComponent>[] = [];
function mount(...args: Parameters<typeof mountComponent>) {
  const mounted = mountComponent(...args);
  mounts.push(mounted);
  return mounted;
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
});

describe('Audit log', () => {
  const auditRow: AuditLogRow = {
    sequence: 7,
    timestamp,
    action: 'REVEAL',
    status: 'DENIED',
    profile: 'private-prod',
    profileAlias: 'environment-1',
    secretName: 'PRIVATE_TOKEN',
    secretAlias: 'variable-1',
    metadataJson: JSON.stringify({ ignored: metadataSentinel }),
    denialReason: 'intent required',
    hmacOk: false,
  };

  it('renders the chain break and searches the privacy-safe labels and audit status', async () => {
    const verify = vi.fn();
    const rows: AuditLogRow[] = [
      auditRow,
      {
        ...auditRow,
        sequence: 8,
        action: 'COPY',
        status: 'OK',
        hmacOk: true,
        profile: '',
        profileAlias: '',
        secretName: '',
        secretAlias: '',
      },
      { ...auditRow, sequence: 9, action: 'RUN', status: 'FAILED', hmacOk: null },
    ];
    const { root, setProps } = mount(AuditLog, {
      rows,
      privacyMode: true,
      chainOk: false,
      lastCheckedAt: timestamp,
      onVerify: verify,
    });
    expect(nodeText(root)).toContain('Audit chain broken at row 7.');
    expect(nodeText(root)).toContain('environment-1');
    expect(nodeText(root)).toContain('variable-1');
    expect(nodeText(root)).toContain('intent required');
    expect(nodeText(root)).not.toMatch(/private-prod|PRIVATE_TOKEN|fixture-metadata/);
    const search = byProp(root, 'type', 'search');
    await input(search, ' PRIVATE_TOKEN ');
    expect(nodeText(root)).toContain('No matching audit rows.');
    await input(search, 'BROKEN');
    expect(nodeText(root)).toContain('#7');
    expect(nodeText(root)).not.toContain('#8');
    await input(search, 'HMAC OK');
    expect(nodeText(root)).toContain('#8');
    await input(search, 'NOT VERIFIED');
    expect(nodeText(root)).toContain('#9');
    await input(search, '');
    setProps({ privacyMode: false, chainOk: true });
    await settle();
    expect(nodeText(root)).toContain('Audit chain verified.');
    expect(nodeText(root)).toContain('PRIVATE_TOKEN');
    expect(nodeText(root)).not.toContain(metadataSentinel);
    await click(button(root, 'Verify audit chain'));
    expect(verify).toHaveBeenCalledOnce();
  });

  it('shows loading, empty, and retryable error states', async () => {
    const { root, setProps } = mount(AuditLog, {
      rows: [],
      privacyMode: false,
      chainOk: null,
      loading: true,
    });
    expect(nodeText(root)).toContain('Audit chain has not been verified.');
    expect(nodeText(root)).toContain('Loading audit');
    setProps({ loading: false, chainOk: false, errorMessage: 'Audit unavailable.' });
    await settle();
    expect(nodeText(root)).toContain('Audit chain broken.');
    expect(nodeText(root)).toContain('No audit rows.');
    expect(nodeText(byProp(root, 'role', 'alert'))).toBe('Audit unavailable. Retry verification.');
  });
});

describe('Devices and members', () => {
  it('combines search, kind and status constraints while using aliases in privacy mode', async () => {
    const rows: DeviceMemberRow[] = [
      {
        id: 'device-1',
        kind: 'device',
        name: 'Private Laptop',
        alias: 'Device A',
        fingerprint: 'private-fingerprint',
        fingerprintAlias: 'fingerprint-a',
        status: 'active',
        localDevice: true,
        createdAt: timestamp,
        lastSeenAt: timestamp,
      },
      { id: 'device-2', kind: 'device', name: 'Offline', status: 'revoked', createdAt: timestamp },
      {
        id: 'member-1',
        kind: 'member',
        name: 'Private Owner',
        alias: 'Member A',
        role: 'owner',
        trustedDeviceCount: 3,
        status: 'active',
        createdAt: timestamp,
      },
      {
        id: 'member-2',
        kind: 'member',
        name: 'Pending dev',
        role: 'developer',
        status: 'pending',
        createdAt: timestamp,
      },
    ];
    const refresh = vi.fn();
    const { root, setProps } = mount(DeviceMemberDirectory, {
      rows,
      privacyMode: true,
      loading: true,
      onRefresh: refresh,
    });
    expect(nodeText(root)).toContain('Loading');
    expect(nodeText(root)).toContain('Device A device — fingerprint-a local active');
    expect(nodeText(root)).toContain('Member A member owner — 3 active');
    expect(nodeText(root)).not.toMatch(/Private (Laptop|Owner)|private-fingerprint/);
    await select(control(root, 'Type', 'select'), 'member');
    await select(control(root, 'Status', 'select'), 'active');
    await input(control(root, 'Search'), ' OWNER ');
    expect(nodeText(root)).toContain('Member A');
    expect(nodeText(root)).not.toMatch(/Device A|Pending dev/);
    await input(control(root, 'Search'), 'Private Owner');
    expect(nodeText(root)).toContain('No devices or members match the current search.');
    setProps({ privacyMode: false, loading: false, lastRefreshedAt: timestamp });
    await settle();
    expect(nodeText(root)).toContain('Private Owner');
    expect(nodeText(root)).toContain('Updated');
    await click(button(root, 'Refresh'));
    expect(refresh).toHaveBeenCalledOnce();
    setProps({ rows: [] });
    await settle();
    expect(nodeText(root)).toContain('No devices or members. Run locket device init.');
    setProps({ errorMessage: 'Could not load devices.' });
    await settle();
    expect(nodeText(root)).toContain('Could not load devices.');
  });
});

describe('Runtime sessions', () => {
  it('shows session state, process and audit metadata under privacy aliases', async () => {
    const running: RuntimeSessionRow = {
      sessionId: 'session-1',
      profile: 'private-profile',
      profileAlias: 'environment-1',
      policy: 'private-command',
      policyAlias: 'command-1',
      pid: 42,
      startedAt: timestamp,
      processStartTime: timestamp,
      state: 'running',
      secretNameCount: 1,
      spawnAuditSequence: 10,
    };
    const rows: RuntimeSessionRow[] = [
      running,
      {
        ...running,
        sessionId: 'session-2',
        state: 'completed',
        exitStatus: 0,
        endedAt: timestamp,
        completionAuditSequence: 11,
      },
      {
        ...running,
        sessionId: 'session-3',
        state: 'failed',
        exitStatus: 2,
        secretNameCount: 3,
        processStartTime: '2026-06-26T11:59:00Z',
      },
      {
        ...running,
        sessionId: 'session-4',
        state: 'stale',
        spawnAuditSequence: undefined,
        secretNameCount: 0,
      },
    ];
    const refresh = vi.fn();
    const { root, setProps } = mount(ExecutionMonitor, {
      rows: [],
      privacyMode: true,
      loading: true,
      onRefresh: refresh,
    });
    expect(nodeText(root)).toContain('Loading runtime sessions');
    expect(button(root, 'Refresh').props.disabled).toBe(true);
    setProps({ rows, loading: false, lastRefreshedAt: timestamp });
    await settle();
    expect(nodeText(root)).toContain('running command-1 session-1 environment-1 pid 42');
    expect(nodeText(root)).toContain('Process started 2026-06-26T11:59:00Z');
    expect(nodeText(root)).toContain('0 1 secret 10 → 11');
    expect(nodeText(root)).toContain('2 3 secrets 10 → —');
    expect(nodeText(root)).toContain('stale');
    expect(nodeText(root)).not.toMatch(/private-(profile|command)/);
    await click(button(root, 'Refresh'));
    expect(refresh).toHaveBeenCalledOnce();
    setProps({ privacyMode: false });
    await settle();
    expect(nodeText(root)).toContain('private-command');
    setProps({ rows: [], errorMessage: 'Agent disconnected.' });
    await settle();
    expect(nodeText(byProp(root, 'role', 'alert'))).toBe('Agent disconnected.');
    setProps({ errorMessage: null });
    await settle();
    expect(nodeText(root)).toContain('No runtime sessions yet.');
  });
});
