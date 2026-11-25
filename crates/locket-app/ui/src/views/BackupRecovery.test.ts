import { afterEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import BackupRecovery from './BackupRecovery.vue';
import type { BundleAction } from '../backup/actions';
import { exportSelectionKey } from '../backup/actions';
import {
  button,
  byProp,
  check,
  click,
  control,
  input,
  mountComponent,
  nodeText,
  settle,
} from '../test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => true }));

const mounts: ReturnType<typeof mountComponent>[] = [];
function backup() {
  const onAction = vi.fn<(action: BundleAction) => void>();
  const view = mountComponent(BackupRecovery, { onAction });
  mounts.push(view);
  return { ...view, onAction };
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
  vi.resetAllMocks();
});

it('requires a matching preview and clears dangerous consent after scope changes or export', async () => {
  const { root, setProps, onAction } = backup();
  expect(button(root, 'Preview scope').props.disabled).toBe(true);
  expect(button(root, 'Export').props.disabled).toBe(true);
  await input(control(root, 'Recipient descriptor', 'textarea'), '  lkdev2_fixture  ');
  await check(control(root, 'All environments'));
  await check(control(root, 'Include my overrides'));
  await check(control(root, 'Include previous versions'));
  await check(control(root, 'Include audit rows'));
  vi.mocked(invoke).mockResolvedValueOnce('/fixture/output.lkb');
  await click(button(root, 'Browse for a backup destination'));
  expect(invoke).toHaveBeenCalledWith('desktop_pick_file', {
    title: 'Browse for a backup destination',
    save: true,
    defaultName: 'locket-backup.lkb',
  });
  await click(button(root, 'Preview scope'));
  const preview = onAction.mock.calls[0]?.[0];
  const request = {
    recipientDescriptor: 'lkdev2_fixture',
    scope: 'all-profiles',
    includeAudit: true,
    includePersonal: true,
    includeHistory: true,
    confirmDangerous: false,
    previewOnly: true,
    outputPath: '/fixture/output.lkb',
  } as const;
  expect(preview).toEqual({ kind: 'export', label: 'export sealed bundle', request });
  expect(button(root, 'Export').props.disabled).toBe(true);

  setProps({ previewKey: exportSelectionKey(request), previewMessage: 'Four variables selected.' });
  await settle();
  expect(nodeText(root)).toContain('Four variables selected.');
  await check(control(root, 'Confirm export from dangerous'));
  await click(button(root, 'Export'));
  expect(onAction).toHaveBeenLastCalledWith({
    kind: 'export',
    label: 'export sealed bundle',
    request: { ...request, previewOnly: false, confirmDangerous: true },
  });
  expect(control(root, 'Confirm export from dangerous').checked).toBe(false);

  await check(control(root, 'Confirm export from dangerous'));
  await check(control(root, 'Active environment'));
  expect(button(root, 'Export').props.disabled).toBe(true);
  expect(nodeText(root)).not.toContain('Four variables selected.');
  setProps({ busy: true });
  await settle();
  expect(button(root, 'Preview scope').props.disabled).toBe(true);
});

it('keeps review, import, verification and recovery requests distinct', async () => {
  const { root, onAction } = backup();
  const importPanel = byProp(root, 'aria-labelledby', 'backup-import-heading');
  const verifyPanel = byProp(root, 'aria-labelledby', 'backup-verify-heading');
  expect(button(root, 'Review bundle').props.disabled).toBe(true);
  expect(button(root, 'Verify').props.disabled).toBe(true);
  expect(button(root, 'Rotate').props.disabled).toBe(true);
  vi.mocked(invoke).mockResolvedValueOnce('/fixture/input.lkb');
  await click(button(root, 'Browse for a bundle to import'));
  await click(button(root, 'Review bundle'));
  expect(onAction).toHaveBeenLastCalledWith(
    expect.objectContaining({
      kind: 'import',
      request: {
        bundlePath: '/fixture/input.lkb',
        includeAudit: false,
        conflictMode: 'review',
        confirmDangerous: false,
      },
    }),
  );
  await check(control(importPanel, 'Import and replace'));
  await check(control(importPanel, 'Confirm changes'));
  await input(control(importPanel, 'Bundle path'), '/fixture/other.lkb');
  expect(control(importPanel, 'Confirm changes').checked).toBe(false);
  await check(control(importPanel, 'Confirm changes'));
  await check(control(importPanel, 'Import audit evidence'));
  await click(button(root, 'Apply import'));
  expect(onAction).toHaveBeenLastCalledWith(
    expect.objectContaining({
      kind: 'import',
      request: {
        bundlePath: '/fixture/other.lkb',
        includeAudit: true,
        conflictMode: 'accept-incoming',
        confirmDangerous: true,
      },
    }),
  );
  expect(control(importPanel, 'Confirm changes').checked).toBe(false);

  vi.mocked(invoke).mockRejectedValueOnce(new Error('picker unavailable'));
  await click(button(root, 'Browse for a bundle to verify'));
  expect(nodeText(verifyPanel)).toContain('Could not open the picker.');
  vi.mocked(invoke).mockResolvedValueOnce('/fixture/check.lkb');
  await click(button(root, 'Browse for a bundle to verify'));
  await check(control(verifyPanel, 'Require local recipient'));
  await click(button(root, 'Verify'));
  expect(onAction).toHaveBeenLastCalledWith(
    expect.objectContaining({
      kind: 'verify',
      request: { bundlePath: '/fixture/check.lkb', requireDecryptable: true },
    }),
  );

  await check(control(root, 'Current recovery code'));
  await check(control(root, 'One-time display acknowledged'));
  await click(button(root, 'Rotate'));
  expect(onAction).toHaveBeenLastCalledWith(
    expect.objectContaining({
      kind: 'rotate',
      request: {
        verification: 'current-code',
        acknowledgedOneTimeDisplay: true,
        clearAfterDisplay: true,
      },
    }),
  );
});

it('blocks verification and code rotation while another backup operation is running', async () => {
  const { root, setProps, onAction } = backup();
  const verification = byProp(root, 'aria-labelledby', 'backup-verify-heading');
  await input(control(verification, 'Bundle path'), '/fixture/check.lkb');
  await check(control(root, 'One-time display acknowledged'));
  expect(button(root, 'Verify').props.disabled).toBe(false);
  expect(button(root, 'Rotate').props.disabled).toBe(false);
  setProps({ busy: true });
  await settle();
  expect(button(root, 'Verify').props.disabled).toBe(true);
  expect(button(root, 'Rotate').props.disabled).toBe(true);
  expect(onAction).not.toHaveBeenCalled();
});
