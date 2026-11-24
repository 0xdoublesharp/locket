<script setup lang="ts">
import AppIcon from '../components/AppIcon.vue';
import { onMounted, ref, watch } from 'vue';

import {
  desktopActionsAvailable,
  desktopCopyTextPlain,
  desktopGetLaunchAtLogin,
  desktopMcpConfigSnippet,
  desktopSetLaunchAtLogin,
} from '../agent/client';
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
const verificationOptions = [
  { key: 'unlock', label: 'Unlock vault' },
  { key: 'reveal', label: 'Reveal a value' },
  { key: 'copy', label: 'Copy a value' },
  { key: 'dangerous_profile_switch', label: 'Switch to a dangerous environment' },
] as const;

const duration = ref('');
const durationError = ref('');
watch(
  () => props.state.unlockTtl,
  (value) => {
    duration.value = value ?? '';
    durationError.value = '';
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
const mcpJson = ref(
  JSON.stringify({ mcpServers: { locket: { command: 'locket', args: ['mcp'] } } }, null, 2),
);
const mcpMessage = ref('');

onMounted(async () => {
  if (!desktop) return;
  const [login, snippet] = await Promise.all([
    desktopGetLaunchAtLogin(),
    desktopMcpConfigSnippet(),
  ]);
  if (login.ok) launchAtLogin.value = login.value;
  else launchMessage.value = 'Launch at login is unavailable.';
  if (snippet.ok && typeof snippet.value?.json === 'string') mcpJson.value = snippet.value.json;
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

async function copyMcp(): Promise<void> {
  const result = await desktopCopyTextPlain(mcpJson.value);
  mcpMessage.value = result.ok ? 'Copied MCP JSON.' : 'Could not copy MCP JSON.';
}
</script>

<template>
  <section class="settings" aria-labelledby="settings-heading">
    <header>
      <h2 id="settings-heading">Settings</h2>
      <p>
        Agent version <code>{{ state.agentVersion }}</code>
      </p>
    </header>

    <p v-if="loading || saveMessage || errorMessage" class="settings__feedback" role="status">
      <span v-if="loading">Syncing settings…</span>
      <span v-else-if="errorMessage" class="settings__error">{{ errorMessage }}</span>
      <span v-else>{{ saveMessage }}</span>
    </p>

    <div class="settings__columns">
      <div class="settings__stack">
        <section class="settings__card" aria-labelledby="settings-privacy">
          <h3 id="settings-privacy"><AppIcon name="eye" /> Privacy</h3>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="state.privacyRedactNames"
              :disabled="loading || (projectConnected && !canEditVault)"
              @change="toggle($event, (checked) => ({ privacy_redact_names: checked }))"
            />
            <span>Redact names with local aliases</span>
          </label>
          <p>Uses aliases in project, variable, and activity views and the menu bar.</p>
        </section>
        <section class="settings__card" aria-labelledby="settings-session">
          <h3 id="settings-session"><AppIcon name="clock" /> Vault session</h3>
          <p>Set how long an unlock stays valid.</p>
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
          <p v-if="!canEditVault && !loading && !errorMessage">
            {{
              projectConnected
                ? 'Unlock this project to edit vault settings.'
                : 'Connect a project to edit vault settings.'
            }}
          </p>
        </section>
        <section class="settings__card" aria-labelledby="settings-environment">
          <div class="settings__actions">
            <h3 id="settings-environment"><AppIcon name="alert" /> Environment safety</h3>
            <span v-if="state.dangerousProfileFlag" class="settings__warning">Dangerous</span>
          </div>
          <label class="settings__switch">
            <input
              type="checkbox"
              :checked="state.dangerousProfileFlag"
              :disabled="loading || !canEditVault || !state.dangerousProfile"
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
          <p>Dangerous environments require confirmation for sensitive actions.</p>
        </section>
      </div>
      <div class="settings__stack">
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
        <section class="settings__card" aria-labelledby="settings-companion">
          <h3 id="settings-companion"><AppIcon name="laptop" /> macOS companion</h3>
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
        </section>
        <section class="settings__card" aria-labelledby="settings-mcp">
          <header class="settings__card-header">
            <h3 id="settings-mcp"><AppIcon name="terminal" /> AI agents &amp; MCP</h3>
            <button
              class="icon-label"
              type="button"
              aria-label="Copy MCP JSON"
              :disabled="!desktop"
              @click="copyMcp"
            >
              <AppIcon name="copy" />
              Copy
            </button>
          </header>
          <p>
            Paste this JSON into your MCP client settings. Locket MCP never exposes plaintext
            reveals.
          </p>
          <pre>{{ mcpJson }}</pre>
          <p v-if="mcpMessage" role="status">{{ mcpMessage }}</p>
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

.settings p {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.settings__card {
  display: grid;
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

.settings__warning {
  padding: 0.2rem 0.45rem;
  border-radius: var(--radius-sm);
  background: var(--warn-soft);
  color: var(--warn);
  font-size: 0.75rem;
  font-weight: 650;
}

.settings .settings__error {
  color: var(--danger);
}

.settings__error:empty {
  display: none;
}

.settings pre {
  padding: 0.75rem;
  overflow: auto;
  background: var(--bg-subtle);
  border-radius: var(--radius-sm);
  font: 0.8125rem/1.5 var(--font-mono);
}

@media (max-width: 767px) {
  .settings__columns {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
