import { expect, it, vi } from 'vitest';
import { findNode, mountComponent, settle, type TestNode } from '../test/renderer';
import CommandPalette from './CommandPalette.vue';

it('uses safe navigation for empty-query Enter and runs Lock vault when searched for', async () => {
  vi.stubGlobal('window', new EventTarget());
  vi.stubGlobal('Document', class {});
  vi.stubGlobal('ShadowRoot', class {});
  const onExecute = vi.fn();
  const view = mountComponent<{ query: string; searchInput: TestNode }>(CommandPalette, {
    open: false,
    onExecute,
    actions: [
      { id: 'vault', label: 'Lock vault', group: 'Actions' },
      { id: 'project', label: 'Project', group: 'Views' },
      { id: 'workspace', label: 'Workspace', group: 'Projects' },
      { id: 'database', label: 'DATABASE_URL', group: 'Variables' },
    ],
  });
  try {
    const dialog = findNode(view.root, (node) => node.tag === 'dialog');
    const onKey = dialog!.props.onKeydown as (event: Partial<KeyboardEvent>) => void;
    const enter = {
      key: 'Enter',
      target: view.state.searchInput as unknown as EventTarget,
      preventDefault: vi.fn(),
    };
    onKey(enter);
    expect(onExecute).toHaveBeenCalledExactlyOnceWith('project');
    onExecute.mockClear();

    view.state.query = 'lock';
    await settle();
    onKey(enter);
    expect(onExecute).toHaveBeenCalledExactlyOnceWith('vault');
  } finally {
    view.unmount();
    vi.unstubAllGlobals();
  }
});

it('filters actions, selects by arrow keys, executes with Enter, and closes with Escape', async () => {
  vi.stubGlobal('window', new EventTarget());
  vi.stubGlobal('document', { getElementById: () => null, querySelector: () => null });
  vi.stubGlobal('Document', class {});
  vi.stubGlobal('ShadowRoot', class {});
  const onExecute = vi.fn();
  const onOpen = vi.fn();
  const view = mountComponent<{ query: string; searchInput: TestNode }>(CommandPalette, {
    open: false,
    'onUpdate:open': onOpen,
    onExecute,
    actions: [
      { id: 'settings', label: 'Settings', group: 'Views', badge: 'View' },
      { id: 'jump', label: 'DATABASE_URL', group: 'Variables', badge: 'Variable' },
      { id: 'copy', label: 'Copy lk://dev/DATABASE_URL', group: 'Variables', badge: 'Reference' },
    ],
  });
  try {
    const shortcut = Object.assign(new Event('keydown', { cancelable: true }), {
      key: 'k',
      metaKey: true,
    });
    window.dispatchEvent(shortcut);
    expect(shortcut.defaultPrevented).toBe(true);
    expect(onOpen).toHaveBeenLastCalledWith(true);
    onOpen.mockClear();
    const dialog = findNode(view.root, (node) => node.tag === 'dialog');
    const onKey = dialog!.props.onKeydown as (event: Partial<KeyboardEvent>) => void;
    const preventDefault = vi.fn();
    view.state.query = 'database variable';
    await settle();
    expect(findNode(view.root, (node) => node.text === 'Settings')).toBeUndefined();
    expect(findNode(view.root, (node) => node.props.id === 'palette-group-Variables')?.text).toBe(
      'Variables',
    );
    const input = view.state.searchInput as unknown as EventTarget;
    onKey({ key: 'ArrowDown', preventDefault, target: input });
    await settle();
    expect(view.state.searchInput.props['aria-activedescendant']).toBe('palette-result-1');
    onKey({ key: 'Enter', preventDefault, target: input });
    expect(onExecute).toHaveBeenCalledExactlyOnceWith('copy');
    expect(onOpen).toHaveBeenLastCalledWith(false);
    onKey({ key: 'Escape', preventDefault });
    expect(onOpen).toHaveBeenCalledTimes(2);
  } finally {
    view.unmount();
    vi.unstubAllGlobals();
  }
});
