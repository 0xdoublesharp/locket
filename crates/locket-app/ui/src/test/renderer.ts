import {
  createRenderer,
  createVNode,
  nextTick,
  ssrContextKey,
  type Component,
  type ComponentOptions,
} from 'vue';
import * as vue from 'vue';
import { compileScript, compileTemplate, parse } from 'vue/compiler-sfc';
import { ScriptTarget, transpileModule } from 'typescript';

// The existing Node Vitest runner imports SFC scripts in SSR mode. Compile their
// real templates for this client renderer too, using the installed Vue compiler.
// This keeps the standard test command working without a DOM package or config edit.
const components = import.meta.glob<ComponentOptions>('../**/*.vue', {
  eager: true,
  import: 'default',
});
const sources = import.meta.glob<string>('../**/*.vue', {
  eager: true,
  query: '?raw',
  import: 'default',
});
for (const [filename, component] of Object.entries(components)) {
  const { descriptor } = parse(sources[filename]!, { filename });
  const script = compileScript(descriptor, { id: filename });
  const template = compileTemplate({
    source: descriptor.template!.content,
    filename,
    id: filename,
    compilerOptions: {
      mode: 'function',
      bindingMetadata: script.bindings,
      prefixIdentifiers: true,
      expressionPlugins: ['typescript'],
    },
  });
  if (template.errors.length) throw new Error(`${filename}: ${template.errors.join(', ')}`);
  const { outputText } = transpileModule(template.code, {
    compilerOptions: { target: ScriptTarget.ES2022 },
  });
  component.render = new Function('Vue', outputText)(vue);
}

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
  patchProp: (node, key, _previous, value) => {
    node.props[key] = value;
    if (key === 'value') node.value = value;
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
  const vnode = createVNode(component, props);
  const app = renderer.createApp({ render: () => vnode });
  app.provide(ssrContextKey, {});
  app.mount(root);
  // Script-setup bindings are inspected only in tests. The component's real
  // template, watchers, event handlers and mount/unmount hooks still execute.
  const instance = vnode.component as typeof vnode.component & { setupState: State };
  let mounted = true;
  return {
    root,
    state: instance!.setupState,
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
