import assert from 'node:assert/strict';
import Module from 'node:module';
import test from 'node:test';
import { setImmediate } from 'node:timers/promises';
import type * as vscode from 'vscode';

import { AgentClient, AgentClientError, AgentMethod, StatusEvent, StatusPayload } from './agentClient';
import { LOCKET_EDITOR_COMMAND_IDS } from './commandsModel';
import type { LocketDiagnosticsController } from './diagnostics';
import { LOCKET_IDE_ENV_SESSION_VARIABLE } from './ideEnvSession';
import * as projectContext from './projectContext';

class Disposable {
  public constructor(private readonly cleanup: () => void) {}
  public dispose(): void { this.cleanup(); }
  public static from(...items: Disposable[]): Disposable {
    return new Disposable(() => items.forEach((item) => item.dispose()));
  }
}

function event<T>() {
  const listeners = new Set<(value: T) => void>();
  return {
    subscribe(listener: (value: T) => void) {
      listeners.add(listener);
      return new Disposable(() => { listeners.delete(listener); });
    },
    fire(value: T) { listeners.forEach((listener) => listener(value)); },
    get count() { return listeners.size; },
  };
}

class Range {
  public readonly coordinates: readonly unknown[];

  public constructor(...coordinates: unknown[]) { this.coordinates = coordinates; }
}

class CompletionItem {
  public constructor(public readonly label: string, public readonly kind: number) {}
}

class SnippetString {
  public constructor(public readonly value: string) {}
}

class Diagnostic {
  public source?: string;
  public code?: string;
  public constructor(public readonly range: Range, public readonly message: string, public readonly severity: number) {}
}

class ThemeColor {
  public constructor(public readonly id: string) {}
}

function document(text: string, languageId = 'typescript', scheme = 'file'): vscode.TextDocument {
  return {
    uri: { scheme, fsPath: '/workspace/demo/src/settings.ts' },
    languageId,
    lineAt: () => ({ text }),
    getText: () => text,
    positionAt: (character: number) => ({ line: 0, character }),
  } as unknown as vscode.TextDocument;
}

test('activated extension drives VS Code features and tears down its registrations', async (t) => {
  const project: projectContext.ProjectContext = {
    root: '/workspace/demo',
    projectId: 'fixture-project',
    projectName: 'demo',
    defaultProfileId: 'fixture-profile',
    profileName: 'staging',
    storePath: '/local/store.db',
    cliPath: '/trusted/locket',
  };
  const snapshot: StatusPayload = {
    lock_state: 'locked',
    agent_version: 'fixture',
    live_grant_count: 0,
  };
  const commands = new Map<string, () => Promise<void>>();
  const editorDocument = document('const key = process.env.API_KEY;');
  const openDocument = event<vscode.TextDocument>();
  const changeDocument = event<{ document: vscode.TextDocument }>();
  const closeDocument = event<vscode.TextDocument>();
  const changeFolders = event<void>();
  const openTerminal = event<{ creationOptions: { cwd?: string } }>();
  const diagnostics = new Map<vscode.Uri, Diagnostic[]>();
  const terminalCalls: Array<{ options: vscode.TerminalOptions; shown: boolean }> = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  const collection = new Map([[LOCKET_IDE_ENV_SESSION_VARIABLE, 'stale-session']]);
  const statusItem = {
    name: '', command: '', text: '', tooltip: '', backgroundColor: undefined as ThemeColor | undefined,
    show: t.mock.fn(), dispose: t.mock.fn(),
  };
  const completionKind = { Reference: 1, EnumMember: 2, Value: 3 };
  const severity = { Error: 0, Warning: 1 };
  let completion: { selector: vscode.DocumentSelector; provider: vscode.CompletionItemProvider; triggers: string[] } | undefined;
  let trusted = true;
  let folders = [{ name: 'demo', uri: { fsPath: project.root } }];
  let editor = { document: editorDocument };
  let pickProject = true;
  const vscodeApi = {
    Disposable, Range, CompletionItem, SnippetString, Diagnostic, ThemeColor,
    CompletionItemKind: completionKind, DiagnosticSeverity: severity, StatusBarAlignment: { Left: 1 },
    commands: {
      registerCommand(id: string, callback: () => Promise<void>) {
        assert.ok(!commands.has(id), `duplicate command ${id}`);
        commands.set(id, callback);
        return new Disposable(() => { commands.delete(id); });
      },
    },
    languages: {
      createDiagnosticCollection(name: string) {
        assert.equal(name, 'locket');
        return {
          set: (uri: vscode.Uri, entries: Diagnostic[]) => diagnostics.set(uri, entries),
          delete: (uri: vscode.Uri) => diagnostics.delete(uri),
          dispose: () => diagnostics.clear(),
        };
      },
      match(selector: readonly vscode.DocumentFilter[], item: vscode.TextDocument) {
        return selector.some(({ scheme, language }) => item.uri.scheme === scheme && item.languageId === language) ? 1 : 0;
      },
      registerCompletionItemProvider(
        selector: vscode.DocumentSelector, provider: vscode.CompletionItemProvider, ...triggers: string[]
      ) {
        completion = { selector, provider, triggers };
        return new Disposable(() => { completion = undefined; });
      },
    },
    workspace: {
      get isTrusted() { return trusted; },
      get workspaceFolders() { return folders; },
      textDocuments: [editorDocument],
      onDidOpenTextDocument: openDocument.subscribe,
      onDidChangeTextDocument: changeDocument.subscribe,
      onDidCloseTextDocument: closeDocument.subscribe,
      onDidChangeWorkspaceFolders: changeFolders.subscribe,
    },
    window: {
      get activeTextEditor() { return editor; },
      onDidOpenTerminal: openTerminal.subscribe,
      createStatusBarItem(id: string, align: number, priority: number) {
        assert.deepEqual([id, align, priority], ['locket.status', 1, 100]);
        return statusItem;
      },
      createTerminal(options: vscode.TerminalOptions) {
        const entry = { options, shown: false };
        terminalCalls.push(entry);
        return { show: () => { entry.shown = true; } };
      },
      showQuickPick: async <T>(items: readonly T[]) => pickProject ? items[0] : undefined,
      showWarningMessage: async (message: string) => { warnings.push(message); },
      showErrorMessage: async (message: string) => { errors.push(message); },
    },
  };
  const moduleLoader = Module as unknown as {
    _load(request: string, parent: NodeJS.Module | null, isMain: boolean): unknown;
  };
  const load = moduleLoader._load;
  const resolveProject = t.mock.fn(async () => project);
  t.mock.method(moduleLoader, '_load', (request: string, parent: NodeJS.Module | null, isMain: boolean) => {
    if (request === 'vscode') { return vscodeApi; }
    if (request === './projectContext') { return { ...projectContext, resolveProjectContext: resolveProject }; }
    return load.call(moduleLoader, request, parent, isMain);
  });

  let onStatus: ((value: StatusEvent) => void) | undefined;
  let onStatusError: ((value: AgentClientError) => void) | undefined;
  let policies = [{ allowed_secrets: ['API_KEY'] }];
  const disposeStream = t.mock.fn();
  const disposeClient = t.mock.method(AgentClient.prototype, 'dispose');
  const status = t.mock.method(AgentClient.prototype, 'status', async () => ({ ...snapshot, profile_name: 'staging' }));
  const subscribe = t.mock.method(AgentClient.prototype, 'subscribeStatus', async (
    event: (value: StatusEvent) => void, error: (value: AgentClientError) => void,
  ) => {
    onStatus = event;
    onStatusError = error;
    return { dispose: disposeStream };
  });
  const invoke = t.mock.method(AgentClient.prototype, 'invoke', async (method: AgentMethod, payload: unknown) => {
    if (method === 'ListPolicies') {
      assert.deepEqual(payload, { project_id: project.projectId, privacy_redact_names: false });
      return { rows: policies };
    }
    if (method === 'RequestGrant') {
      throw AgentClientError.agent({ error: 'ConfirmationFailed', message: 'fixture denial', retryable: false });
    }
    return {};
  });

  const { activate, deactivate } = await import('./extension.js');
  const subscriptions: vscode.Disposable[] = [];
  t.after(() => subscriptions.splice(0).forEach((item) => item.dispose()));
  activate({
    subscriptions,
    environmentVariableCollection: {
      delete: (name: string) => collection.delete(name),
      replace: (name: string, value: string) => collection.set(name, value),
    },
  } as unknown as vscode.ExtensionContext);

  assert.deepEqual([...commands.keys()].sort(), [...LOCKET_EDITOR_COMMAND_IDS].sort());
  assert.equal(collection.size, 0);
  assert.equal(subscribe.mock.callCount(), 1);
  assert.equal(statusItem.command, 'locket.revealSecret');
  assert.equal(statusItem.name, 'Locket Agent Status');
  assert.equal(statusItem.show.mock.callCount(), 1);
  assert.equal(statusItem.text, '$(sync~spin) Locket');
  assert.equal(statusItem.backgroundColor, undefined);
  assert.ok(onStatus);
  onStatus({ ...snapshot, kind: 'heartbeat', sequence: 7 });
  assert.equal(statusItem.text, '$(lock) Locket');
  assert.match(statusItem.tooltip, /last seen sequence 7/u);

  await t.test('completion registers triggers and replaces the fragment with typed snippets', async () => {
    assert.ok(completion);
    assert.deepEqual(completion.triggers, ['l', 'k', ':', '/', '?', '@']);
    assert.ok(Array.isArray(completion.selector));
    assert.ok(completion.selector.some((filter) => filter.language === 'typescript' && filter.scheme === 'file'));
    async function complete(prefix: string) {
      assert.ok(completion);
      const token = { isCancellationRequested: false, onCancellationRequested: event<void>().subscribe };
      const context = { triggerKind: 0, triggerCharacter: undefined };
      const position = { line: 0, character: prefix.length } as vscode.Position;
      return completion.provider.provideCompletionItems(document(prefix + '"'), position, token, context);
    }
    assert.equal(await complete('const plain = '), undefined);
    assert.equal(status.mock.callCount(), 0);

    const prefix = 'const ref = "lk://dev/API_KEY';
    const items = await complete(prefix);
    assert.ok(Array.isArray(items));
    assert.deepEqual(items.map(({ label, kind }) => [label, kind]), [
      ['lk://staging/KEY', completionKind.Reference],
      ['lk://dev/API_KEY@v1', completionKind.Value],
      ['lk://dev/API_KEY?source=user-local', completionKind.EnumMember],
      ['lk://dev/API_KEY?source=machine-local', completionKind.EnumMember],
      ['lk://dev/API_KEY?source=team-managed', completionKind.EnumMember],
    ]);
    assert.deepEqual(items[0]?.insertText, new SnippetString('lk://staging/${1:KEY}'));
    assert.deepEqual(items[0]?.range, new Range(0, prefix.indexOf('lk://'), 0, prefix.length));

    status.mock.mockImplementationOnce(async () => snapshot);
    const noProfile = await complete('lk');
    assert.ok(Array.isArray(noProfile));
    assert.equal(noProfile[0]?.label, 'lk://profile/KEY');
    status.mock.mockImplementationOnce(async () => { throw new Error('offline'); });
    const offline = await complete('lk');
    assert.ok(Array.isArray(offline));
    assert.equal(offline[0]?.label, 'lk://profile/KEY');
  });

  await t.test('diagnostics follow context and document lifecycle events', () => {
    const controller = subscriptions.find((item): item is LocketDiagnosticsController => 'updateContext' in item);
    assert.ok(controller);
    assert.equal(diagnostics.size, 0);
    controller.updateContext({
      activeSecrets: [],
      versions: [{ name: 'API_KEY', version: 1, versionState: 'deprecated', pinnedReferenceEligible: false }],
      nowUnixNanos: 100,
    });
    const [missing] = diagnostics.get(editorDocument.uri) ?? [];
    assert.equal(missing?.source, 'Locket');
    assert.equal(missing?.code, 'locket.missingEnvSecret');
    assert.equal(missing?.severity, severity.Warning);
    assert.deepEqual(missing?.range.coordinates, [{ line: 0, character: 12 }, { line: 0, character: 31 }]);

    const other = document('lk://staging/API_KEY@v1', 'typescript');
    openDocument.fire(other);
    const [expired] = diagnostics.get(other.uri) ?? [];
    assert.equal(expired?.code, 'locket.pinnedVersionExpired');
    assert.equal(expired?.severity, severity.Error);
    const changed = { ...other, getText: () => '' };
    changeDocument.fire({ document: changed });
    assert.deepEqual(diagnostics.get(other.uri), []);
    closeDocument.fire(other);
    assert.equal(diagnostics.has(other.uri), false);

    openDocument.fire(document('process.env.API_KEY', 'typescript', 'untitled'));
    assert.equal(diagnostics.size, 1);
    controller.updateContext(undefined);
    assert.equal(diagnostics.size, 0);
  });

  await t.test('terminal sessions are scoped to explicitly created terminals and workspace events clear stale state', async () => {
    const createTerminal = commands.get('locket.createTerminal');
    assert.ok(createTerminal);
    await createTerminal();
    const first = terminalCalls[0];
    assert.ok(first);
    const sessionId = first.options.env?.[LOCKET_IDE_ENV_SESSION_VARIABLE];
    assert.match(sessionId ?? '', /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/u);
    assert.deepEqual(first, {
      options: { cwd: project.root, name: 'Locket', env: { [LOCKET_IDE_ENV_SESSION_VARIABLE]: sessionId } },
      shown: true,
    });
    const registration = invoke.mock.calls.find(({ arguments: args }) => args[0] === 'RegisterIdeEnvSession');
    assert.deepEqual(registration?.arguments[1], {
      session_id: sessionId, project_id: project.projectId, store_path: project.storePath,
      profile_id: project.defaultProfileId, env_names: ['API_KEY'], ttl_seconds: 1800,
    });
    assert.equal(collection.size, 0);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? '', /^Locket: /u);

    policies = [];
    await createTerminal();
    assert.deepEqual(terminalCalls[1], { options: { cwd: project.root, name: 'Locket', env: {} }, shown: true });
    assert.equal(warnings.length, 1);

    collection.set(LOCKET_IDE_ENV_SESSION_VARIABLE, 'stale-session');
    changeFolders.fire();
    assert.equal(collection.size, 0);

    const beforeOpen = resolveProject.mock.callCount();
    openTerminal.fire({ creationOptions: { cwd: project.root } });
    await setImmediate();
    assert.equal(resolveProject.mock.callCount(), beforeOpen + 1);
    assert.equal(terminalCalls.length, 2);
    assert.equal(collection.size, 0);

    trusted = false;
    await createTerminal();
    trusted = true;
    resolveProject.mock.mockImplementationOnce(async () => { throw undefined; });
    await createTerminal();
    assert.deepEqual(errors, ['Locket requires a trusted workspace.', 'Locket project is unavailable.']);

    folders = [...folders, { name: 'other', uri: { fsPath: '/workspace/other' } }];
    editor = { document: document('', 'typescript', 'untitled') };
    pickProject = false;
    await createTerminal();
    assert.equal(terminalCalls.length, 2);
  });

  assert.ok(onStatusError);
  onStatusError(AgentClientError.unavailable('agent offline'));
  assert.deepEqual(statusItem.backgroundColor, new ThemeColor('statusBarItem.warningBackground'));
  collection.set(LOCKET_IDE_ENV_SESSION_VARIABLE, 'stale-session');
  deactivate();
  subscriptions.splice(0).forEach((item) => item.dispose());
  assert.equal(commands.size, 0);
  assert.equal(completion, undefined);
  assert.deepEqual([openDocument, changeDocument, closeDocument, changeFolders, openTerminal].map((item) => item.count), [0, 0, 0, 0, 0]);
  assert.equal(collection.size, 0);
  assert.equal(statusItem.dispose.mock.callCount(), 1);
  assert.equal(disposeClient.mock.callCount(), 1);
  assert.ok(invoke.mock.calls.some(({ arguments: args }) => args[0] === 'CancelSubscription'));
});
