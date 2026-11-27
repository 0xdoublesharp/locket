<script setup lang="ts">
import AppIcon from '../components/AppIcon.vue';
import { computed, onMounted, ref, shallowRef, watch } from 'vue';

import {
  desktopActionsAvailable,
  desktopCopyTextPlain,
  desktopGetLaunchAtLogin,
  desktopMcpConfigSnippet,
  desktopSetLaunchAtLogin,
} from '../agent/client';
import { dotenvMigrationPrompt, mcpClientSnippets } from '../agent/agentPrompts';
import { configuredDurationSeconds, unlockTtl } from '../dashboard/health';
import type { WriteConfigChanges } from '../agent/types';
import type { SettingsState } from '../types/views';

defineOptions({ name: 'AppSettings' });

const props = defineProps<{
  state: SettingsState;
  loading: boolean;
  canEditVault: boolean;
  projectConnected: boolean;
  errorMessage: string | null;
  saveMessage?: string | null;
}>();
const emit = defineEmits<{ update: [patch: WriteConfigChanges] }>();

const presets = ['15m', '1h', '4h', '8h'];
const themeOptions = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
] as const;
const densityOptions = [
  { value: 'comfortable', label: 'Comfortable' },
  { value: 'compact', label: 'Compact' },
] as const;
const redactionOptions = [
  { value: 'auto', label: 'Auto' },
  { value: 'always', label: 'Always' },
  { value: 'never', label: 'Never' },
] as const;
const shellOptions = [
  { value: 'off', label: 'Off' },
  { value: 'prompt-only', label: 'Prompt only' },
  { value: 'hook', label: 'Hook' },
] as const;
const updateChannelOptions = [
  { value: 'off', label: 'Off' },
  { value: 'stable', label: 'Stable' },
  { value: 'beta', label: 'Beta' },
] as const;
const verificationOptions = [
  { key: 'unlock', label: 'Unlock vault' },
  { key: 'reveal', label: 'Reveal a value' },
  { key: 'copy', label: 'Copy a value' },
  { key: 'dangerous_profile_switch', label: 'Switch to a dangerous environment' },
  { key: 'recovery', label: 'Account recovery' },
  { key: 'team_accept', label: 'Accept team invite' },
  { key: 'device_register', label: 'Register device' },
] as const;

const duration = ref('');
const durationError = ref('');
const revealTtl = ref('');
const revealTtlError = ref('');
const rotationGraceTtl = ref('');
const rotationGraceTtlError = ref('');
const sessionRetention = ref('');
const sessionRetentionError = ref('');
const editorDefault = ref('');
const editorDefaultError = ref('');
const updatesManifestUrl = ref('');
const updatesManifestUrlError = ref('');
watch(
  () => props.state.unlockTtl,
  (value) => {
    duration.value = value ?? '';
    durationError.value = '';
  },
  { immediate: true },
);
watch(
  () => props.state.revealTtl,
  (value) => {
    revealTtl.value = value ?? '';
    revealTtlError.value = '';
  },
  { immediate: true },
);
watch(
  () => props.state.rotationMaxGraceTtl,
  (value) => {
    rotationGraceTtl.value = value ?? '';
    rotationGraceTtlError.value = '';
  },
  { immediate: true },
);
watch(
  () => props.state.sessionSecretNameRetention,
  (value) => {
    sessionRetention.value = value ?? '';
    sessionRetentionError.value = '';
  },
  { immediate: true },
);
watch(
  () => props.state.editorDefault,
  (value) => {
    editorDefault.value = value ?? '';
    editorDefaultError.value = '';
  },
  { immediate: true },
);
watch(
  () => props.state.updatesManifestUrl,
  (value) => {
    updatesManifestUrl.value = value ?? '';
    updatesManifestUrlError.value = '';
  },
  { immediate: true },
);

function saveDuration(value: string): void {
  const next = value.trim();
  const seconds = configuredDurationSeconds(next);
  if (seconds !== unlockTtl(seconds)) {
    durationError.value = 'Enter a duration between 1s and 8h, such as 45m.';
    return;
  }
  durationError.value = '';
  duration.value = next;
  emit('update', { agent_unlock_ttl: next });
}

function saveRevealTtl(): void {
  const next = revealTtl.value.trim();
  if (!next) {
    revealTtlError.value = '';
    emit('update', { unset_keys: ['reveal.ttl'] });
    return;
  }
  const seconds = configuredDurationSeconds(next);
  if (seconds <= 0 || seconds > 300) {
    revealTtlError.value = 'Enter a duration of 5m or less, such as 60s.';
    return;
  }
  revealTtlError.value = '';
  revealTtl.value = next;
  emit('update', { reveal_ttl: next });
}

function saveRotationGraceTtl(): void {
  const next = rotationGraceTtl.value.trim();
  if (!next) {
    rotationGraceTtlError.value = '';
    emit('update', { unset_keys: ['rotation.max_grace_ttl'] });
    return;
  }
  const seconds = configuredDurationSeconds(next);
  if (seconds <= 0 || seconds > 30 * 86400) {
    rotationGraceTtlError.value = 'Enter a duration of 30d or less, such as 7d.';
    return;
  }
  rotationGraceTtlError.value = '';
  rotationGraceTtl.value = next;
  emit('update', { rotation_max_grace_ttl: next });
}

function saveSessionRetention(): void {
  const next = sessionRetention.value.trim();
  if (!next) {
    sessionRetentionError.value = '';
    emit('update', { unset_keys: ['runtime.session_secret_name_retention'] });
    return;
  }
  if (next !== 'off' && configuredDurationSeconds(next) <= 0) {
    sessionRetentionError.value = 'Enter a duration such as 90d, or off.';
    return;
  }
  sessionRetentionError.value = '';
  sessionRetention.value = next;
  emit('update', { runtime_session_secret_name_retention: next });
}

function saveEditorDefault(): void {
  const next = editorDefault.value.trim();
  if (!next) {
    editorDefaultError.value = '';
    emit('update', { unset_keys: ['editor.default'] });
    return;
  }
  if (next.startsWith('~') || next.includes('$') || next.includes('`')) {
    editorDefaultError.value = 'Editor path must not use shell expansion.';
    return;
  }
  const isAbsolute = next.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(next);
  if (!isAbsolute && /[\s/\\|&;<>()]/.test(next)) {
    editorDefaultError.value = 'Enter a command name (like vim) or an absolute path.';
    return;
  }
  editorDefaultError.value = '';
  editorDefault.value = next;
  emit('update', { editor_default: next });
}

function saveManifestUrl(): void {
  const next = updatesManifestUrl.value.trim();
  if (!next) {
    updatesManifestUrlError.value = '';
    emit('update', { unset_keys: ['updates.manifest_url'] });
    return;
  }
  const rest = next.startsWith('https://') ? next.slice('https://'.length) : '';
  const host = rest.split(/[/?#]/)[0] ?? '';
  if (!rest || /\s/.test(next) || !host || host.startsWith(':') || host.includes('@')) {
    updatesManifestUrlError.value = 'Enter a valid https:// manifest URL.';
    return;
  }
  updatesManifestUrlError.value = '';
  updatesManifestUrl.value = next;
  emit('update', { updates_manifest_url: next });
}

function toggle(event: Event, patch: (checked: boolean) => WriteConfigChanges): void {
  const input = event.target as HTMLInputElement;
  const next = input.checked;
  input.checked = !next;
  emit('update', patch(next));
}

const desktop = desktopActionsAvailable();
const launchAtLogin = ref<boolean | null>(null);
const launchBusy = ref(false);
const launchMessage = ref('');
const mcpClients = [
  { id: 'json', label: 'MCP JSON', copyLabel: 'Copy JSON', statusLabel: 'MCP JSON' },
  {
    id: 'claude',
    label: 'Claude Code',
    copyLabel: 'Copy command',
    statusLabel: 'Claude Code command',
  },
  { id: 'codex', label: 'Codex CLI', copyLabel: 'Copy command', statusLabel: 'Codex CLI command' },
] as const;
type McpClient = (typeof mcpClients)[number];

const activeMcpClient = shallowRef<McpClient>(mcpClients[0]);
const mcpConfigPending = ref(desktop);
const mcpSnippets = ref(mcpClientSnippets('locket', ['mcp']));
const mcpTokens = computed(() => {
  const parts = mcpSnippets.value.json.split(/("(?:[^"\\]|\\.)*"|[[\]{},:])/u);
  return parts.map((text, index) => {
    if (index % 2 === 0) return { text, kind: 'plain' };
    if (!text.startsWith('"')) return { text, kind: 'punctuation' };
    const isKey = !parts[index + 1]?.trim() && parts[index + 2] === ':';
    return { text, kind: isKey ? 'key' : 'string' };
  });
});
const mcpMessage = ref('');
const agentPromptMessage = ref('');

onMounted(() => {
  if (!desktop) return;
  void desktopGetLaunchAtLogin().then((login) => {
    if (login.ok) launchAtLogin.value = login.value;
    else launchMessage.value = 'Launch at login is unavailable.';
  });
  void desktopMcpConfigSnippet().then((snippet) => {
    if (snippet.ok && typeof snippet.value?.json === 'string') {
      const { command, args, json } = snippet.value;
      mcpSnippets.value = { ...mcpClientSnippets(command, args), json };
    }
    mcpConfigPending.value = false;
  });
});

async function toggleLaunch(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const next = input.checked;
  input.checked = launchAtLogin.value ?? false;
  launchBusy.value = true;
  launchMessage.value = '';
  const result = await desktopSetLaunchAtLogin(next);
  if (result.ok) {
    launchAtLogin.value = result.value;
    launchMessage.value = result.value ? 'Launch at login enabled.' : 'Launch at login disabled.';
  } else {
    launchMessage.value = 'Could not update launch at login.';
  }
  launchBusy.value = false;
}

function selectMcpClient(client: McpClient): void {
  activeMcpClient.value = client;
  mcpMessage.value = '';
}

function moveMcpTab(event: KeyboardEvent, index: number): void {
  const count = mcpClients.length;
  let next: number;
  switch (event.key) {
    case 'ArrowLeft':
      next = (index + count - 1) % count;
      break;
    case 'ArrowRight':
      next = (index + 1) % count;
      break;
    case 'Home':
      next = 0;
      break;
    case 'End':
      next = count - 1;
      break;
    default:
      return;
  }
  event.preventDefault();
  const client = mcpClients[next]!;
  selectMcpClient(client);
  const tablist = event.currentTarget as HTMLElement;
  tablist.querySelector<HTMLButtonElement>(`#settings-mcp-tab-${client.id}`)?.focus();
}

async function copyMcp(): Promise<void> {
  const client = activeMcpClient.value;
  mcpMessage.value = '';
  const result = await desktopCopyTextPlain(mcpSnippets.value[client.id]);
  if (client !== activeMcpClient.value) return;
  mcpMessage.value = result.ok
    ? `Copied ${client.statusLabel}.`
    : `Could not copy ${client.statusLabel}.`;
}

async function copyAgentPrompt(): Promise<void> {
  agentPromptMessage.value = '';
  const result = await desktopCopyTextPlain(dotenvMigrationPrompt());
  agentPromptMessage.value = result.ok ? 'Copied agent prompt.' : 'Could not copy agent prompt.';
}
</script>

<template>
  <section class="settings" aria-labelledby="settings-heading">
    <header>
      <h2 id="settings-heading">Settings</h2>
      <p>
        Shared Locket configuration (<code>config.toml</code>) · Agent version
        <code>{{ state.agentVersion }}</code>
      </p>
    </header>

    <p v-if="loading || saveMessage || errorMessage" class="settings__feedback" role="status">
      <span v-if="loading">Syncing settings…</span>
      <span v-else-if="errorMessage" class="settings__error">{{ errorMessage }}</span>
      <span v-else>{{ saveMessage }}</span>
    </p>

    <div class="settings__columns">
      <div class="settings__stack">
        <section class="settings__card" aria-labelledby="settings-session">
          <h3 id="settings-session"><AppIcon name="clock" /> Vault session &amp; agent</h3>
          <p>Set how long an unlock stays valid and whether the CLI starts the agent on demand.</p>
          <div class="settings__actions" aria-label="Session length presets">
            <button
              v-for="preset in presets"
              :key="preset"
              type="button"
              :aria-pressed="(state.unlockTtl ?? '15m') === preset"
              :disabled="loading || !canEditVault"
              @click="saveDuration(preset)"
            >
              {{ preset }}
            </button>
          </div>
          <form
            class="settings__actions settings__duration-form"
            @submit.prevent="saveDuration(duration)"
          >
            <label class="settings__duration">
              Custom duration
              <input
                v-model="duration"
                type="text"
                placeholder="45m"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="durationError ? 'true' : undefined"
                aria-describedby="settings-duration-error"
                @input="durationError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault || !duration.trim()">
              Save duration
            </button>
          </form>
          <p id="settings-duration-error" class="settings__error" role="status">
            {{ durationError }}
          </p>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="state.agentAutostart ?? false"
              :disabled="loading || !canEditVault"
              @change="toggle($event, (checked) => ({ agent_autostart: checked }))"
            />
            <span>Autostart agent (<code>agent.autostart</code>)</span>
          </label>
          <p v-if="!canEditVault && !loading && !errorMessage">
            {{
              projectConnected
                ? 'Unlock this project to edit vault settings.'
                : 'Connect a project to edit vault settings.'
            }}
          </p>
        </section>
        <section class="settings__card" aria-labelledby="settings-verification">
          <h3 id="settings-verification">
            <AppIcon name="fingerprint" /> Touch ID &amp; user verification
          </h3>
          <p>Require system verification for individual actions.</p>
          <label v-for="option in verificationOptions" :key="option.key" class="settings__switch">
            <input
              type="checkbox"
              :checked="state.verification?.[option.key] ?? false"
              :disabled="loading || !canEditVault"
              @change="
                toggle($event, (checked) => ({
                  user_verification_required_for: { [option.key]: checked },
                }))
              "
            />
            <span>{{ option.label }}</span>
          </label>
        </section>
        <section class="settings__card" aria-labelledby="settings-limits">
          <h3 id="settings-limits"><AppIcon name="clock" /> Retention &amp; TTL limits</h3>
          <p>Configure reveal windows, rotation grace caps, and runtime session metadata retention.</p>
          <form class="settings__actions settings__duration-form" @submit.prevent="saveRevealTtl">
            <label class="settings__duration">
              Reveal TTL (max 5m)
              <input
                v-model="revealTtl"
                type="text"
                placeholder="60s"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="revealTtlError ? 'true' : undefined"
                aria-describedby="settings-reveal-ttl-error"
                @input="revealTtlError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault">Save</button>
            <button
              v-if="state.revealTtl"
              type="button"
              :disabled="loading || !canEditVault"
              @click="emit('update', { unset_keys: ['reveal.ttl'] })"
            >
              Reset
            </button>
          </form>
          <p id="settings-reveal-ttl-error" class="settings__error" role="status">
            {{ revealTtlError }}
          </p>
          <form
            class="settings__actions settings__duration-form"
            @submit.prevent="saveRotationGraceTtl"
          >
            <label class="settings__duration">
              Rotation grace cap (max 30d)
              <input
                v-model="rotationGraceTtl"
                type="text"
                placeholder="7d"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="rotationGraceTtlError ? 'true' : undefined"
                aria-describedby="settings-grace-ttl-error"
                @input="rotationGraceTtlError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault">Save</button>
            <button
              v-if="state.rotationMaxGraceTtl"
              type="button"
              :disabled="loading || !canEditVault"
              @click="emit('update', { unset_keys: ['rotation.max_grace_ttl'] })"
            >
              Reset
            </button>
          </form>
          <p id="settings-grace-ttl-error" class="settings__error" role="status">
            {{ rotationGraceTtlError }}
          </p>
          <form
            class="settings__actions settings__duration-form"
            @submit.prevent="saveSessionRetention"
          >
            <label class="settings__duration">
              Session secret-name retention
              <input
                v-model="sessionRetention"
                type="text"
                placeholder="90d or off"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="sessionRetentionError ? 'true' : undefined"
                aria-describedby="settings-retention-error"
                @input="sessionRetentionError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault">Save</button>
            <button
              v-if="state.sessionSecretNameRetention"
              type="button"
              :disabled="loading || !canEditVault"
              @click="emit('update', { unset_keys: ['runtime.session_secret_name_retention'] })"
            >
              Reset
            </button>
          </form>
          <p id="settings-retention-error" class="settings__error" role="status">
            {{ sessionRetentionError }}
          </p>
        </section>
        <section class="settings__card" aria-labelledby="settings-environment">
          <div class="settings__actions">
            <h3 id="settings-environment"><AppIcon name="alert" /> Environment safety</h3>
            <span v-if="state.dangerousProfileFlag" class="settings__warning">Dangerous</span>
          </div>
          <div class="settings__risk">
            <label class="settings__switch">
              <input
                type="checkbox"
                :checked="state.dangerousProfileFlag"
                :disabled="loading || !canEditVault || !state.dangerousProfile"
                aria-describedby="settings-environment-risk"
                @change="toggle($event, (checked) => ({ dangerous_profile: checked }))"
              />
              <span>
                Mark
                <strong>{{
                  state.dangerousProfile?.profile_label ?? 'the active environment'
                }}</strong>
                as dangerous
              </span>
            </label>
            <p id="settings-environment-risk">
              Dangerous environments require confirmation for sensitive actions.
            </p>
          </div>
        </section>
      </div>
      <div class="settings__stack">
        <section class="settings__card" aria-labelledby="settings-privacy">
          <h3 id="settings-privacy"><AppIcon name="eye" /> Appearance &amp; privacy</h3>
          <div class="settings__field">
            <span class="settings__label">Theme</span>
            <div class="settings__actions" aria-label="Theme">
              <button
                v-for="option in themeOptions"
                :key="option.value"
                type="button"
                :aria-pressed="(state.uiTheme ?? 'system') === option.value"
                :disabled="loading || (projectConnected && !canEditVault)"
                @click="emit('update', { ui_theme: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
          <div class="settings__field">
            <span class="settings__label">Density</span>
            <div class="settings__actions" aria-label="UI density">
              <button
                v-for="option in densityOptions"
                :key="option.value"
                type="button"
                :aria-pressed="(state.uiDensity ?? 'comfortable') === option.value"
                :disabled="loading || (projectConnected && !canEditVault)"
                @click="emit('update', { ui_density: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="state.privacyRedactNames"
              :disabled="loading || (projectConnected && !canEditVault)"
              @change="toggle($event, (checked) => ({ privacy_redact_names: checked }))"
            />
            <span>Redact names with local aliases</span>
          </label>
          <p>Uses aliases in project, secret, and activity views and the menu bar.</p>
        </section>
        <section class="settings__card" aria-labelledby="settings-cli">
          <h3 id="settings-cli"><AppIcon name="settings" /> CLI &amp; shell workflow</h3>
          <div class="settings__field">
            <span class="settings__label">Command output redaction</span>
            <div class="settings__actions" aria-label="Command output redaction">
              <button
                v-for="option in redactionOptions"
                :key="option.value"
                type="button"
                :aria-pressed="(state.runRedactOutput ?? 'auto') === option.value"
                :disabled="loading || !canEditVault"
                @click="emit('update', { run_redact_output: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
          <div class="settings__field">
            <span class="settings__label">Shell integration</span>
            <div class="settings__actions" aria-label="Shell integration">
              <button
                v-for="option in shellOptions"
                :key="option.value"
                type="button"
                :aria-pressed="(state.shellIntegration ?? 'off') === option.value"
                :disabled="loading || !canEditVault"
                @click="emit('update', { shell_integration: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="state.exampleAutoRefresh ?? true"
              :disabled="loading || !canEditVault"
              @change="toggle($event, (checked) => ({ example_auto_refresh: checked }))"
            />
            <span>Auto-refresh <code>.env.example</code> on secret changes</span>
          </label>
          <form class="settings__actions settings__duration-form" @submit.prevent="saveEditorDefault">
            <label class="settings__duration settings__duration--wide">
              Default editor
              <input
                v-model="editorDefault"
                type="text"
                placeholder="vim or /usr/bin/nano"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="editorDefaultError ? 'true' : undefined"
                aria-describedby="settings-editor-error"
                @input="editorDefaultError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault">Save</button>
            <button
              v-if="state.editorDefault"
              type="button"
              :disabled="loading || !canEditVault"
              @click="emit('update', { unset_keys: ['editor.default'] })"
            >
              Reset
            </button>
          </form>
          <p id="settings-editor-error" class="settings__error" role="status">
            {{ editorDefaultError }}
          </p>
        </section>
        <section class="settings__card" aria-labelledby="settings-companion">
          <h3 id="settings-companion"><AppIcon name="laptop" /> Companion &amp; updates</h3>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="launchAtLogin ?? false"
              :disabled="launchAtLogin === null || launchBusy"
              @change="toggleLaunch"
            />
            <span>Launch at login</span>
          </label>
          <p v-if="!desktop">Available in the macOS desktop app.</p>
          <p v-else-if="launchMessage" role="status">{{ launchMessage }}</p>
          <div class="settings__field">
            <span class="settings__label">Update channel</span>
            <div class="settings__actions" aria-label="Update channel">
              <button
                v-for="option in updateChannelOptions"
                :key="option.value"
                type="button"
                :aria-pressed="(state.updatesChannel ?? 'off') === option.value"
                :disabled="loading || !canEditVault"
                @click="emit('update', { updates_channel: option.value })"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
          <form class="settings__actions settings__duration-form" @submit.prevent="saveManifestUrl">
            <label class="settings__duration settings__duration--wide">
              Signed update manifest URL
              <input
                v-model="updatesManifestUrl"
                type="url"
                placeholder="https://updates.example.com/manifest.json"
                autocomplete="off"
                :disabled="loading || !canEditVault"
                :aria-invalid="updatesManifestUrlError ? 'true' : undefined"
                aria-describedby="settings-manifest-error"
                @input="updatesManifestUrlError = ''"
              />
            </label>
            <button type="submit" :disabled="loading || !canEditVault">Save</button>
            <button
              v-if="state.updatesManifestUrl"
              type="button"
              :disabled="loading || !canEditVault"
              @click="emit('update', { unset_keys: ['updates.manifest_url'] })"
            >
              Reset
            </button>
          </form>
          <p id="settings-manifest-error" class="settings__error" role="status">
            {{ updatesManifestUrlError }}
          </p>
        </section>
        <section class="settings__card" aria-labelledby="settings-mcp">
          <header class="settings__card-header">
            <h3 id="settings-mcp"><AppIcon name="terminal" /> AI agents &amp; MCP</h3>
            <button
              class="icon-label"
              type="button"
              :aria-label="`Copy ${activeMcpClient.statusLabel}`"
              :disabled="!desktop || mcpConfigPending"
              @click="copyMcp"
            >
              <AppIcon name="copy" />
              {{ activeMcpClient.copyLabel }}
            </button>
          </header>
          <p v-if="activeMcpClient.id === 'json'">
            Paste this JSON into your MCP client settings. Locket MCP never exposes plaintext
            reveals.
          </p>
          <p v-else>
            Run this command in your terminal to add Locket to {{ activeMcpClient.label }}.
          </p>
          <div
            class="settings__mcp-tabs"
            role="tablist"
            aria-label="MCP client"
            @keydown="moveMcpTab($event, mcpClients.indexOf(activeMcpClient))"
          >
            <button
              v-for="client in mcpClients"
              :id="`settings-mcp-tab-${client.id}`"
              :key="client.id"
              class="settings__mcp-tab"
              type="button"
              role="tab"
              aria-controls="settings-mcp-snippet"
              :aria-selected="client.id === activeMcpClient.id"
              :tabindex="client.id === activeMcpClient.id ? 0 : -1"
              @click="selectMcpClient(client)"
            >
              {{ client.label }}
            </button>
          </div>
          <div
            id="settings-mcp-snippet"
            class="settings__mcp-panel"
            role="tabpanel"
            :aria-labelledby="`settings-mcp-tab-${activeMcpClient.id}`"
          >
            <pre
              v-if="activeMcpClient.id === 'json'"
              tabindex="0"
            ><code><span v-for="(token, index) in mcpTokens" :key="index" :data-syntax="token.kind">{{ token.text }}</span></code></pre>
            <pre v-else tabindex="0"><code>{{ mcpSnippets[activeMcpClient.id] }}</code></pre>
          </div>
          <p class="settings__copy-status" role="status">{{ mcpMessage }}</p>
          <section class="settings__migration" aria-labelledby="settings-env-migration">
            <h4 id="settings-env-migration">Port <code>.env</code> files with an AI agent</h4>
            <p>
              Copy a zero-secret prompt so your agent scans key names and imports
              <code>.env</code> files without ever reading secret values.
            </p>
            <div class="settings__actions">
              <button
                class="icon-label"
                type="button"
                :disabled="!desktop"
                @click="copyAgentPrompt"
              >
                <AppIcon name="copy" />
                Copy agent prompt
              </button>
              <p class="settings__copy-status" role="status">{{ agentPromptMessage }}</p>
            </div>
          </section>
        </section>
      </div>
    </div>
  </section>
</template>

<style scoped>
.settings,
.settings__stack {
  display: grid;
  align-content: start;
  min-width: 0;
  gap: 0.75rem;
}

.settings__columns {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
  gap: 0.75rem;
}

.settings h2 {
  font-size: var(--font-page-title);
  letter-spacing: -0.025em;
}

.settings__card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.settings h2,
.settings h3,
.settings p,
.settings pre {
  margin: 0;
}

.settings h3 {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.95rem;
}

.settings h3 .app-icon {
  color: var(--info);
}
#settings-environment .app-icon {
  color: var(--warn);
}

.settings p {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.settings__card {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0.75rem;
  min-width: 0;
  padding: 1rem;
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
}

.settings__switch {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  line-height: 1.5;
}

.settings__switch input {
  accent-color: var(--accent);
}

.settings__actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.settings__duration {
  display: grid;
  gap: 0.25rem;
  font-size: 0.875rem;
}

.settings__duration--wide {
  flex: 1 1 13rem;
}

.settings__field {
  display: grid;
  gap: 0.35rem;
}

.settings__label {
  color: var(--text-secondary);
  font-size: 0.8125rem;
  font-weight: 600;
}

.settings__duration input {
  width: 9rem;
  box-sizing: border-box;
  padding: 0.35rem 0.6rem;
  min-height: 2.125rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
  color: var(--text-primary);
  font: inherit;
}

.settings__duration--wide input {
  width: 100%;
}

.settings__duration-form {
  align-items: end;
}

.settings button {
  min-height: 2.125rem;
  padding: 0.35rem 0.7rem;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  color: var(--text-primary);
  font: inherit;
  cursor: pointer;
}

.settings button[aria-pressed='true'] {
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--accent);
}

.settings__card-header button {
  font-size: 0.8125rem;
}

.settings__warning {
  padding: 0.2rem 0.45rem;
  border-radius: var(--radius-sm);
  background: var(--warn-soft);
  color: var(--warn);
  font-size: 0.75rem;
  font-weight: 650;
}
.settings__risk {
  display: grid;
  gap: 0.35rem;
  padding: 0.65rem 0.75rem;
  border: 1px solid color-mix(in srgb, var(--warn), transparent 62%);
  border-radius: var(--radius-sm);
  background: var(--warn-soft);
}
.settings__risk p {
  color: var(--warn);
}

.settings .settings__error {
  color: var(--danger);
}

.settings__error:empty {
  display: none;
}

.settings pre {
  padding: 0.75rem;
  overflow-x: auto;
  background: var(--bg-subtle);
  border-radius: var(--radius-sm);
  font: 0.8125rem/1.5 var(--font-mono);
}
.settings [data-syntax='key'] {
  color: var(--info);
}
.settings [data-syntax='string'] {
  color: var(--success);
}
.settings [data-syntax='punctuation'] {
  color: var(--text-muted);
}

.settings__mcp-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  padding: 0.25rem;
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
}

.settings .settings__mcp-tab {
  flex: 1 1 auto;
  min-width: 0;
  border-color: transparent;
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.8125rem;
}

.settings .settings__mcp-tab:hover,
.settings .settings__mcp-tab[aria-selected='true'] {
  color: var(--text-primary);
}

.settings__mcp-panel {
  min-width: 0;
}

.settings .settings__mcp-tab[aria-selected='true'] {
  border-color: var(--border-subtle);
  background: var(--bg-surface);
  font-weight: 650;
}

.settings__migration {
  display: grid;
  gap: 0.5rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border-subtle);
}

.settings__migration h4 {
  margin: 0;
  font-size: 0.875rem;
}

.settings__copy-status:empty {
  position: absolute;
}

@media (max-width: 767px) {
  .settings__columns {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
