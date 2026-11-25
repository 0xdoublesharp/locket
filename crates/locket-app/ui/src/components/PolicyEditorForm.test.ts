import { afterEach, expect, it, vi } from 'vitest';
import PolicyEditorForm from './PolicyEditorForm.vue';
import type { CommandPolicyRow } from '../types/views';
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
  select,
  settle,
  submit,
} from '../test/renderer';

const mounts: ReturnType<typeof mountComponent>[] = [];
function policyForm(props: Record<string, unknown> = {}) {
  const onSubmit = vi.fn();
  const onDismiss = vi.fn();
  const view = mountComponent(PolicyEditorForm, {
    mode: 'create',
    projectId: 'fixture-project',
    dangerousProfile: true,
    profileLabel: 'prod',
    submitting: false,
    onSubmit,
    onDismiss,
    ...props,
  });
  mounts.push(view);
  return { ...view, onSubmit, onDismiss };
}

afterEach(() => {
  for (const mounted of mounts.splice(0)) mounted.unmount();
});

it('validates draft fields, requires dangerous confirmation, and emits a structured policy', async () => {
  const { root, setProps, onSubmit } = policyForm();
  const field = (name: string) => byProp(root, 'data-testid', `policy-form-${name}`);
  expect(button(root, 'Create').props.disabled).toBe(true);
  await submit(root);
  expect(onSubmit).not.toHaveBeenCalled();
  await input(field('name'), 'fixture-run');
  await select(field('kind'), 'shell');
  await input(field('command'), 'pnpm run fixture');
  await input(field('required'), 'bad key');
  await input(control(root, 'Optional secrets'), 'bad key');
  await input(control(root, 'Allowed extra secrets'), 'bad key');
  await input(field('ttl'), '30000');
  expect(button(root, 'Create').props.disabled).toBe(true);
  expect(nodeText(root)).toMatch(/28800|28,800|8h/);
  await input(field('required'), 'REQUIRED_KEY, REQUIRED_KEY');
  await input(control(root, 'Optional secrets'), 'OPTIONAL_KEY');
  await input(control(root, 'Allowed extra secrets'), 'EXTRA_KEY');
  await input(field('ttl'), '120');
  await select(control(root, 'Environment', 'select'), 'strict');
  await select(control(root, 'Override mode', 'select'), 'fail');
  await check(control(root, 'Require typed confirmation'));
  await check(control(root, 'Require user verification'));
  await check(control(root, 'Require local agent'), false);
  await check(control(root, 'Allow remote Docker'));
  expect(button(root, 'Create').props.disabled).toBe(true);

  await input(control(root, 'Type the active environment'), ' prod ');
  setProps({ submitting: true });
  await settle();
  await submit(root);
  expect(onSubmit).not.toHaveBeenCalled();
  setProps({ submitting: false, errorMessage: 'Save failed.' });
  await settle();
  expect(nodeText(byProp(root, 'role', 'alert'))).toBe('Save failed.');
  await submit(root);
  expect(onSubmit).toHaveBeenCalledExactlyOnceWith({
    mode: 'create',
    originalName: 'fixture-run',
    confirmation: 'prod',
    snapshot: expect.objectContaining({
      name: 'fixture-run',
      command_kind: 'shell',
      command_preview: 'pnpm run fixture',
      required_secrets: ['REQUIRED_KEY'],
      optional_secrets: ['OPTIONAL_KEY'],
      allowed_secrets: expect.arrayContaining(['EXTRA_KEY']),
      ttl_seconds: 120,
      confirm: true,
      require_user_verification: true,
      require_agent: false,
      allow_remote_docker: true,
      env_mode: 'strict',
      override_mode: 'fail',
    }),
  });
});

it('reinitializes on mode and row changes, preserving the original name on edit and delete', async () => {
  const row: CommandPolicyRow = {
    id: 'policy-id',
    name: 'fixture-current',
    commandKind: 'argv',
    commandPreview: 'pnpm test',
    requiredSecrets: ['REQUIRED_KEY'],
    optionalSecrets: [],
    allowedSecrets: [],
    confirm: false,
    requireUserVerification: false,
    requireAgent: true,
    allowRemoteDocker: false,
    ttlSeconds: 900,
    envMode: 'minimal',
    overrideMode: 'locket',
    updatedAt: '2026-06-26T12:00:00Z',
  };
  const { root, setProps, onSubmit, onDismiss } = policyForm({
    mode: 'edit',
    row,
    dangerousProfile: false,
  });
  const name = byProp(root, 'data-testid', 'policy-form-name');
  expect(name.value).toBe('fixture-current');
  expect(nodeText(root)).toContain('Edit command');
  await input(name, 'fixture-new');
  await submit(root);
  expect(onSubmit).toHaveBeenLastCalledWith(
    expect.objectContaining({
      mode: 'edit',
      originalName: row.name,
      confirmation: undefined,
      snapshot: expect.objectContaining({ name: 'fixture-new' }),
    }),
  );
  setProps({ mode: 'delete', dangerousProfile: true });
  await settle();
  expect(nodeText(root)).toContain('Delete fixture-current');
  expect(
    findNode(root, (node) => node.props['data-testid'] === 'policy-form-name'),
  ).toBeUndefined();
  expect(button(root, 'Delete').props.disabled).toBe(true);
  await input(control(root, 'Type the active environment'), 'prod');
  await submit(root);
  expect(onSubmit).toHaveBeenLastCalledWith(
    expect.objectContaining({
      mode: 'delete',
      originalName: row.name,
      confirmation: 'prod',
    }),
  );
  await click(button(root, 'Cancel'));
  expect(onDismiss).toHaveBeenCalledOnce();
});
