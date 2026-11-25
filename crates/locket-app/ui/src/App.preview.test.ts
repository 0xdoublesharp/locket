import { afterEach, expect, it, vi } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import {
  button,
  byProp,
  click,
  input,
  mountComponent,
  nodeText,
  settle,
  submit,
} from './test/renderer';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: () => false }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));

const mounts: ReturnType<typeof mountComponent>[] = [];

async function preview(search: string) {
  vi.resetModules();
  vi.stubGlobal(
    'window',
    Object.assign(new EventTarget(), {
      location: { search },
      matchMedia: () => ({ matches: false }),
    }),
  );
  const { default: App } = await import('./App.vue');
  const app = mountComponent(App);
  mounts.push(app);
  return app;
}

afterEach(() => {
  for (const app of mounts.splice(0)) app.unmount();
  vi.unstubAllGlobals();
});

it('starts the welcome preview without native IPC and creates the simulated Global Vault', async () => {
  const { root } = await preview('?preview=1&state=welcome');
  await vi.waitFor(() => expect(nodeText(root)).toContain('Agent live'));
  expect(nodeText(root)).toContain('Welcome to Locket');
  expect(nodeText(root)).not.toContain('Desktop required');
  await click(button(root, 'Create Global Vault (@shared)'));
  await vi.waitFor(() => expect(nodeText(root)).toContain('1 secret · default'));
  expect(nodeText(root)).toContain('Global Vault');
  expect(nodeText(root)).toContain('Unlocked');
  expect(invoke).not.toHaveBeenCalled();
  expect(listen).not.toHaveBeenCalled();
});

it('opens the linked preview view and copies only an explicit reference through the browser clipboard', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  const { root } = await preview('?preview=1&view=discover');
  await vi.waitFor(() => expect(nodeText(root)).toContain('DATABASE_URL'));
  const view = byProp(root, 'aria-labelledby', 'discovery-title');
  const key = byProp(view, 'placeholder', 'Name or keyword');
  await input(key, 'DATABASE_URL');
  await submit(view);
  expect(nodeText(view)).toContain('2 results');
  expect(nodeText(view)).not.toContain('STRIPE_SECRET_KEY');
  const active = view.children
    .find((node) => node.tag === 'ul')
    ?.children.find(
      (node) =>
        node.tag === 'li' &&
        nodeText(node).includes('DATABASE_URL') &&
        nodeText(node).includes('Active'),
    );
  expect(Boolean(active)).toBe(true);
  await click(button(active!, 'Copy ref'));
  await settle();
  expect(writeText).toHaveBeenCalledExactlyOnceWith('lk://dev/DATABASE_URL');
  expect(nodeText(active!)).toContain('Copied lk://dev/DATABASE_URL');
  expect(nodeText(root)).not.toContain('preview-only-value');
  expect(invoke).not.toHaveBeenCalled();
  expect(listen).not.toHaveBeenCalled();
});
