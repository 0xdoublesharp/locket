import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const desktop = join(root, 'crates/locket-app/src-tauri');
const entitlements = join(root, 'dist/installers/macos/entitlements.plist');
const allowedPermissions = new Set([
  'desktop-commands',
  'core:event:allow-listen',
  'core:event:allow-unlisten',
]);

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`${relative(root, file)}: ${error.message}`, { cause: error });
  }
}

function* files(dir, skipDir = () => false) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    assert(!entry.isSymbolicLink(), `${relative(root, path)}: symbolic links must be audited in place`);
    if (entry.isDirectory()) {
      if (!skipDir(entry.name)) yield* files(path, skipDir);
    } else if (entry.isFile()) {
      yield path;
    }
  }
}

function checkCsp(csp, file) {
  assert(typeof csp === 'string' && csp.trim(), `${file}: production CSP must be non-empty`);
  assert(!/\*|https?:|wss?:|'unsafe-inline'|'unsafe-eval'/i.test(csp), `${file}: unsafe production CSP source`);

  const directives = new Map();
  for (const directive of csp.split(';').map((part) => part.trim()).filter(Boolean)) {
    const [name, ...sources] = directive.toLowerCase().split(/\s+/);
    assert(!directives.has(name), `${file}: duplicate CSP directive ${name}`);
    for (const source of sources) {
      assert(
        source === "'self'" || source === "'none'" || (name === 'img-src' && source === 'data:'),
        `${file}: ${name} has an unapproved CSP source ${source}`,
      );
    }
    directives.set(name, sources);
  }
  for (const [name, source] of [
    ['default-src', "'self'"],
    ['script-src', "'self'"],
    ['connect-src', "'self'"],
    ['frame-src', "'none'"],
    ['object-src', "'none'"],
  ]) {
    assert.deepEqual(directives.get(name), [source], `${file}: expected ${name} ${source}`);
  }
}

function checkCapabilities() {
  const dir = join(desktop, 'capabilities');
  const identifiers = new Set();
  const desktopFile = join(dir, 'desktop.json');
  let desktopFound = false;
  for (const path of files(dir)) {
    const file = relative(root, path);
    assert(extname(path) === '.json', `${file}: capability files must use audited JSON format`);
    const document = readJson(path);
    const capabilities = Array.isArray(document) ? document : document?.capabilities ?? [document];
    assert(Array.isArray(capabilities) && capabilities.length, `${file}: missing capabilities`);
    for (const capability of capabilities) {
      const { identifier, permissions, remote, windows = [], webviews = [] } = capability;
      assert(typeof identifier === 'string' && identifier, `${file}: missing capability identifier`);
      assert(!identifiers.has(identifier), `${file}: duplicate capability ${identifier}`);
      identifiers.add(identifier);
      assert(remote == null, `${file}: ${identifier} grants remote IPC access`);
      for (const labels of [windows, webviews]) {
        assert(Array.isArray(labels) && labels.every((label) => label === 'main'), `${file}: ${identifier} must be scoped to the main window or webview`);
      }
      assert(Array.isArray(permissions), `${file}: ${identifier} must declare permissions`);
      for (const permission of permissions) {
        assert(allowedPermissions.has(permission), `${file}: ${identifier} grants unapproved permission ${JSON.stringify(permission)}`);
      }
    }
    if (path === desktopFile) {
      assert.equal(document.identifier, 'desktop-default', `${file}: expected desktop-default capability`);
      assert.deepEqual(document.windows, ['main'], `${file}: expected the main window`);
      assert(document.local !== false, `${file}: expected local IPC access`);
      assert.deepEqual(new Set(document.permissions), allowedPermissions, `${file}: expected the desktop permissions and receive-only events`);
      desktopFound = true;
    }
  }
  assert(desktopFound, 'Missing capabilities/desktop.json');
  const commandsToml = readFileSync(join(desktop, 'permissions/desktop-commands.toml'), 'utf8');
  assert(!/"agent_copy"/.test(commandsToml), 'desktop-commands.toml must not allow plaintext-returning agent_copy');
  const allowedCommands = /^commands\.allow\s*=\s*\[([^\]]*)\]/m.exec(commandsToml)?.[1] ?? '';
  assert(/^\s*"desktop_team_sync_test_remote",\s*$/m.test(allowedCommands), 'desktop-commands.toml must allow desktop_team_sync_test_remote');
  return identifiers;
}

function checkConfig(config, file, capabilityIds) {
  checkCsp(config.app?.security?.csp, file);
  assert.equal(config.bundle?.macOS?.hardenedRuntime, true, `${file}: enable macOS hardened runtime`);
  assert.equal(resolve(desktop, config.bundle.macOS.entitlements ?? ''), entitlements, `${file}: use the audited macOS entitlements`);
  assert(config.app.security.assetProtocol?.enable !== true, `${file}: disable the asset protocol`);
  for (const window of config.app.windows ?? []) {
    assert(window.devtools !== true, `${file}: disable production devtools`);
  }
  const capabilities = config.app.security.capabilities ?? [];
  assert(Array.isArray(capabilities) && capabilities.every((id) => capabilityIds.has(id)), `${file}: declare capabilities in the audited directory`);
}

function mergeConfig(base, patch) {
  const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  if (!isObject(patch)) return patch;
  const merged = new Map(Object.entries(isObject(base) ? base : {}));
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) merged.delete(key);
    else merged.set(key, mergeConfig(merged.get(key), value));
  }
  return Object.fromEntries(merged);
}

function checkEntitlements() {
  // Python's standard library reads both XML and binary plists on every CI host.
  execFileSync('python3', ['-c', `
import plistlib, sys

with open(sys.argv[1], 'rb') as file:
    entitlements = plistlib.load(file)
for key in (
    'com.apple.security.get-task-allow',
    'com.apple.security.cs.allow-jit',
    'com.apple.security.cs.allow-unsigned-executable-memory',
    'com.apple.security.cs.disable-library-validation',
    'com.apple.security.cs.disable-executable-page-protection',
):
    if entitlements.get(key, False) is not False:
        sys.exit(f'{sys.argv[1]}: {key} must be absent or false')
`, entitlements], { stdio: 'inherit' });
}

function checkUi() {
  const ui = join(root, 'crates/locket-app/ui/src');
  const unsafe = /\b(?:localStorage|sessionStorage|indexedDB|eval)\b|\bdocument\s*(?:\??\.\s*cookie\b|(?:\?\.)?\s*\[\s*['"]cookie['"]\s*\])|\bnew\s+Function\b|\bv-html\b/;
  for (const file of files(ui, (name) => ['test', '__tests__'].includes(name))) {
    if (!/\.(?:[cm]?[jt]sx?|vue|html)$/.test(file) || /\.(?:test|spec)\.[^.]+$/.test(file)) continue;
    const source = readFileSync(file, 'utf8');
    const match = unsafe.exec(source);
    if (match) {
      const line = source.slice(0, match.index).split('\n').length;
      throw new Error(`${relative(root, file)}:${line}: disallowed WebView API ${match[0]}`);
    }
  }
}

try {
  const capabilityIds = checkCapabilities();
  const config = readJson(join(desktop, 'tauri.conf.json'));
  checkConfig(config, 'tauri.conf.json', capabilityIds);
  for (const name of readdirSync(desktop)) {
    assert(!/^(?:Tauri(?:\.[^.]+)?\.toml|tauri(?:\.[^.]+)?\.conf\.json5)$/.test(name), `${name}: Tauri config files must use audited JSON format`);
    if (/^tauri\.[^.]+\.conf\.json$/.test(name)) {
      checkConfig(mergeConfig(config, readJson(join(desktop, name))), name, capabilityIds);
    }
  }
  checkEntitlements();
  checkUi();
  console.log('Tauri security checks passed');
} catch (error) {
  console.error(`Tauri security check failed: ${error.message}`);
  process.exitCode = 1;
}
