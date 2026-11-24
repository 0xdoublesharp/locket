import { expect, it, vi } from 'vitest';
import { findNode, mountComponent, settle, type TestNode } from '../test/renderer';
import CommandPalette from './CommandPalette.vue';

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
      { id: 'settings', label: 'Settings', detail: 'View' },
      { id: 'jump', label: 'DATABASE_URL', detail: 'Variable details' },
      { id: 'copy', label: 'Copy lk://dev/DATABASE_URL', detail: 'Variable reference' },
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
