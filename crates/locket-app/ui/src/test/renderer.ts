import { createRenderer, createVNode, nextTick, shallowRef, type Component } from 'vue';

// A small host for mounting real Vue components without a browser dependency.
// EventTarget and the input fields also support Vue's v-model directives.
export class TestNode extends EventTarget {
  parent: TestNode | null = null;
  children: TestNode[] = [];
  props: Record<string, unknown> = {};
  value = '';
  checked = false;
  selected = false;
  selectedIndex = -1;
  constructor(
    readonly tag: string,
    public text = '',
  ) {
    super();
  }
  get tagName(): string {
    return this.tag.toUpperCase();
  }
  get options(): TestNode[] {
    return this.children;
  }
  getRootNode(): TestNode {
    return this.parent?.getRootNode() ?? this;
  }
  setAttribute(key: string, value: unknown): void {
    this.props[key] = value;
  }
  removeAttribute(key: string): void {
    delete this.props[key];
  }
}

function remove(node: TestNode): void {
  if (node.parent) {
    node.parent.children.splice(node.parent.children.indexOf(node), 1);
    node.parent = null;
  }
}

function insert(node: TestNode, parent: TestNode, anchor: TestNode | null = null): void {
  remove(node);
  node.parent = parent;
  const index = anchor ? parent.children.indexOf(anchor) : -1;
  parent.children.splice(index < 0 ? parent.children.length : index, 0, node);
}

const renderer = createRenderer<TestNode, TestNode>({
  createElement: (tag) => new TestNode(tag),
  createText: (text) => new TestNode('#text', text),
  createComment: (text) => new TestNode('#comment', text),
  setText: (node, text) => {
    node.text = text;
  },
  setElementText: (node, text) => {
    for (const child of node.children) child.parent = null;
    node.children = [];
    node.text = text;
  },
  parentNode: (node) => node.parent,
  nextSibling: (node) => {
    const siblings = node.parent?.children ?? [];
    return siblings[siblings.indexOf(node) + 1] ?? null;
  },
  patchProp: (node, key, previous, value) => {
    node.props[key] = value;
    if (key === 'value') node.value = value;
    if (/^on[A-Z]/.test(key) && !key.startsWith('onUpdate:')) {
      const event = key.slice(2).toLowerCase();
      for (const listener of [previous].flat()) {
        if (typeof listener === 'function')
          node.removeEventListener(event, listener as EventListener);
      }
      for (const listener of [value].flat()) {
        if (typeof listener === 'function') node.addEventListener(event, listener as EventListener);
      }
    }
  },
  insert,
  remove,
  setScopeId: () => {},
  insertStaticContent: (content, parent, anchor) => {
    const node = new TestNode('#static', content);
    insert(node, parent, anchor);
    return [node, node];
  },
});

export function mountComponent<State>(component: Component, props?: Record<string, unknown>) {
  const root = new TestNode('root');
  const currentProps = shallowRef(props);
  const app = renderer.createApp({
    render: () => createVNode(component, currentProps.value),
  });
  const host = app.mount(root);
  const vnode = host.$.subTree;
  // Script-setup bindings are inspected only in tests. The component's real
  // template, watchers, event handlers and mount/unmount hooks still execute.
  const instance = vnode.component as typeof vnode.component & { setupState: State };
  let mounted = true;
  return {
    root,
    state: instance!.setupState,
    setProps: (patch: Record<string, unknown>) => {
      currentProps.value = { ...currentProps.value, ...patch };
    },
    unmount: () => {
      if (mounted) app.unmount();
      mounted = false;
    },
  };
}

export function findNode(root: TestNode, match: (node: TestNode) => boolean): TestNode | undefined {
  if (match(root)) return root;
  for (const child of root.children) {
    const found = findNode(child, match);
    if (found) return found;
  }
}

export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

export async function settle(): Promise<void> {
  // Drain the finite chain of IPC promises, watcher updates and nested renders.
  for (let i = 0; i < 20; i++) await nextTick();
}

export function nodeText(node: TestNode): string {
  if (node.tag === '#comment') return '';
  return [node.text, ...node.children.map(nodeText)].join(' ').replace(/\s+/g, ' ').trim();
}

export function nodeBy(root: TestNode, match: (node: TestNode) => boolean): TestNode {
  const node = findNode(root, match);
  if (!node) throw new Error(`Expected element in: ${nodeText(root)}`);
  return node;
}

export function byProp(root: TestNode, key: string, value: unknown): TestNode {
  return nodeBy(root, (node) => node.props[key] === value);
}

export function control(root: TestNode, label: string, tag = 'input'): TestNode {
  const field = nodeBy(root, (node) => node.tag === 'label' && nodeText(node).startsWith(label));
  return nodeBy(field, (node) => node.tag === tag);
}

export function button(root: TestNode, label: string): TestNode {
  return nodeBy(
    root,
    (node) =>
      node.tag === 'button' && (node.props['aria-label'] === label || nodeText(node) === label),
  );
}

export async function click(node: TestNode): Promise<void> {
  if (node.props.disabled || node.props.disabled === '') throw new Error('Button is disabled');
  if (!node.props.onClick) throw new Error('Element has no click handler');
  node.dispatchEvent(new Event('click', { cancelable: true }));
  await settle();
}

export async function input(node: TestNode, value: string): Promise<void> {
  node.value = value;
  node.dispatchEvent(new Event('input'));
  await settle();
}

export async function check(node: TestNode, value = true): Promise<void> {
  node.checked = value;
  node.dispatchEvent(new Event('change'));
  await settle();
}

export async function select(node: TestNode, value: string): Promise<void> {
  const option = node.options.find((child) => child.value === value);
  if (!option) throw new Error(`Missing option: ${value}`);
  for (const child of node.options) child.selected = child === option;
  node.dispatchEvent(new Event('change'));
  await settle();
}

export async function submit(root: TestNode): Promise<void> {
  const form = nodeBy(root, (node) => node.tag === 'form');
  if (typeof form.props.onSubmit !== 'function') throw new Error('Form has no submit handler');
  form.dispatchEvent(new Event('submit', { cancelable: true }));
  await settle();
}
