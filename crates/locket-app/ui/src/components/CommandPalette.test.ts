import { expect, it, vi } from 'vitest';
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
      { id: 'add-secret', label: 'Add secret', group: 'Quick actions' },
      { id: 'workspace', label: 'Workspace', group: 'Projects' },
      { id: 'database', label: 'DATABASE_URL', group: 'Secrets' },
    ],
  });
  try {
    const dialog = findNode(view.root, (node) => node.tag === 'dialog');
    expect(dialog).toBeDefined();
    const options = findNode(view.root, (node) => node.props.role === 'listbox');
    expect(
      options?.children
        .filter((node) => node.props.role === 'group')
        .map((node) => node.children[0]?.text),
    ).toEqual(['Views', 'Quick actions', 'Projects', 'Secrets', 'Actions']);
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
      { id: 'jump', label: 'DATABASE_URL', group: 'Secrets', badge: 'Secret' },
      { id: 'copy', label: 'Copy lk://dev/DATABASE_URL', group: 'Secrets', badge: 'Reference' },
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
    view.state.query = 'database secret';
    await settle();
    expect(findNode(view.root, (node) => node.text === 'Settings')).toBeUndefined();
    expect(findNode(view.root, (node) => node.props.id === 'palette-group-Secrets')?.text).toBe(
      'Secrets',
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

it('focuses and clears the query on reopen, closes on cancel, and suppresses the shortcut while blocked', async () => {
  vi.stubGlobal('window', new EventTarget());
  vi.stubGlobal('document', { querySelector: () => null });
  const onOpen = vi.fn();
  const onExecute = vi.fn();
  const view = mountComponent(CommandPalette, {
    open: false,
    blocked: true,
    'onUpdate:open': onOpen,
    onExecute,
    actions: [
      { id: 'project', label: 'Fixture Project', detail: '/fixture/project', group: 'Projects' },
    ],
  });
  const { root, setProps } = view;
  try {
    const dialog = byProp(root, 'aria-labelledby', 'palette-title');
    const search = byProp(root, 'role', 'combobox');
    let dialogOpen = false;
    const focus = vi.fn();
    Object.assign(search, { focus });
    Object.assign(dialog, {
      showModal: () => {
        dialogOpen = true;
      },
      close: () => {
        dialogOpen = false;
      },
    });
    Object.defineProperty(dialog, 'open', { get: () => dialogOpen });
    const shortcut = Object.assign(new Event('keydown', { cancelable: true }), {
      key: 'k',
      ctrlKey: true,
    });
    window.dispatchEvent(shortcut);
    expect(onOpen).not.toHaveBeenCalled();
    setProps({ open: true, blocked: false });
    await settle();
    expect(dialogOpen).toBe(true);
    expect(focus).toHaveBeenCalledOnce();
    await input(search, 'no such project');
    expect(nodeText(root)).toContain('No matching actions.');
    const cancel = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(cancel);
    expect(cancel.defaultPrevented).toBe(true);
    expect(onOpen).toHaveBeenLastCalledWith(false);
    setProps({ open: false });
    await settle();
    expect(dialogOpen).toBe(false);
    setProps({ open: true });
    await settle();
    expect(search.value).toBe('');
    await click(byProp(root, 'role', 'option'));
    expect(onExecute).toHaveBeenCalledExactlyOnceWith('project');
    await click(button(root, 'Close'));
    expect(onOpen).toHaveBeenLastCalledWith(false);
  } finally {
    view.unmount();
    vi.unstubAllGlobals();
  }
});
