<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import PathBrowse from '../components/PathBrowse.vue';
import { shortenProjectPath } from '../utils/projectPath';
import type { DesktopFolderInspection, DesktopProjectContext } from '../agent/types';

const props = defineProps<{
  agentOnline: boolean;
  agentVersion: string;
  desktopAvailable: boolean;
  busy: boolean;
  privacyMode: boolean;
  projectPath: string;
  knownProjects: DesktopProjectContext[];
  pendingInitFolder: DesktopFolderInspection | null;
}>();

const emit = defineEmits<{
  'update:projectPath': [value: string];
  openShared: [];
  pickFolder: [path: string];
  connectPath: [];
  confirmInit: [];
  cancelInit: [];
  openKnown: [project: DesktopProjectContext];
  startAgent: [];
}>();

const hasSharedVault = computed(() => props.knownProjects.some((project) => project.is_shared));
const knownFolderProjects = computed(() =>
  props.knownProjects.filter((project) => !project.is_shared),
);
const folderInput = ref<HTMLInputElement | null>(null);
const initMessage = ref<HTMLElement | null>(null);

watch(
  () => props.pendingInitFolder,
  (folder) => {
    if (folder) initMessage.value?.focus?.();
  },
  { flush: 'post' },
);

async function cancelInitialize(): Promise<void> {
  emit('cancelInit');
  await nextTick();
  folderInput.value?.focus?.();
}
</script>

<template>
  <section class="welcome" aria-labelledby="welcome-heading">
    <header class="welcome__hero">
      <div class="welcome__brand">
        <AppIcon name="brand-lock" :size="40" />
        <div>
          <h2 id="welcome-heading">Welcome to Locket</h2>
          <p class="welcome__subtitle">Store API keys and secrets in an encrypted local vault.</p>
        </div>
      </div>

      <div class="welcome__status" role="group" aria-label="Local vault status">
        <span class="welcome__status-chip" :data-online="agentOnline">
          <span class="welcome__dot" aria-hidden="true" />
          <template v-if="agentOnline">Agent live · {{ agentVersion }}</template>
          <template v-else>Agent offline</template>
        </span>
        <button
          v-if="!agentOnline && desktopAvailable"
          type="button"
          class="companion-button welcome__start-agent"
          :disabled="busy"
          @click="emit('startAgent')"
        >
          Start agent
        </button>
      </div>
    </header>

    <div class="welcome__choices">
      <article class="welcome__card welcome__card--primary" aria-labelledby="welcome-global-title">
        <span class="welcome__card-icon welcome__card-icon--accent">
          <AppIcon name="key" :size="18" />
        </span>
        <h3 id="welcome-global-title">
          {{ hasSharedVault ? 'Open Global Vault' : 'Start with Global Vault' }}
        </h3>
        <p class="welcome__card-copy">
          Keep personal API keys and tokens in <code>@shared</code>. Access them across projects, in
          your terminal, and from AI agents via <code>locket mcp</code>.
        </p>
        <ul class="welcome__bullets">
          <li><AppIcon name="check" :size="14" /> Works without a project folder</li>
          <li><AppIcon name="check" :size="14" /> Protected by your OS keychain</li>
        </ul>
        <button
          type="button"
          class="companion-button companion-button--primary welcome__cta"
          :disabled="busy || !desktopAvailable"
          @click="emit('openShared')"
        >
          <AppIcon name="key" :size="15" />
          {{ hasSharedVault ? 'Open Global Vault (@shared)' : 'Create Global Vault (@shared)' }}
        </button>
      </article>

      <article class="welcome__card" aria-labelledby="welcome-project-title">
        <span class="welcome__card-icon">
          <AppIcon name="folder" :size="18" />
        </span>
        <h3 id="welcome-project-title">Connect a project folder</h3>
        <p id="welcome-project-info" class="welcome__card-copy">
          Open a repository with <code>locket.toml</code>, or pick any folder to initialize
          per-project environments and approved commands.
        </p>

        <form
          class="welcome__folder-form"
          @submit.prevent="!pendingInitFolder && emit('connectPath')"
        >
          <label for="project-path">Project folder</label>
          <div class="welcome__folder-row">
            <input
              id="project-path"
              ref="folderInput"
              :value="projectPath"
              type="text"
              aria-describedby="welcome-project-info"
              placeholder="/path/to/project"
              autocomplete="off"
              spellcheck="false"
              :disabled="busy || !desktopAvailable"
              @input="emit('update:projectPath', ($event.target as HTMLInputElement).value)"
            />
            <PathBrowse
              title="Choose a project folder"
              directory
              :disabled="busy || !desktopAvailable"
              @pick="emit('pickFolder', $event)"
            />
          </div>

          <div v-if="pendingInitFolder" class="welcome__init-prompt">
            <p ref="initMessage" tabindex="-1">
              <strong>{{ privacyMode ? 'This folder' : pendingInitFolder.folder_name }}</strong>
              has no <code>locket.toml</code> yet. Initialize Locket in this folder?
            </p>
            <div class="welcome__init-actions">
              <button
                type="button"
                class="companion-button companion-button--primary"
                :disabled="busy || !desktopAvailable"
                @click="emit('confirmInit')"
              >
                Initialize &amp; open
              </button>
              <button
                type="button"
                class="companion-button"
                :disabled="busy"
                @click="cancelInitialize"
              >
                Cancel
              </button>
            </div>
          </div>

          <button
            v-else
            type="submit"
            class="companion-button welcome__cta"
            :disabled="busy || !desktopAvailable || !projectPath.trim()"
          >
            <AppIcon name="folder" :size="15" />
            Connect folder
          </button>
        </form>
      </article>
    </div>

    <section
      v-if="knownFolderProjects.length"
      class="welcome__known"
      aria-labelledby="welcome-known-heading"
    >
      <h3 id="welcome-known-heading">Connected projects</h3>
      <ul class="welcome__known-list">
        <li v-for="project in knownFolderProjects" :key="project.project_id">
          <button
            type="button"
            class="companion-button welcome__known-item"
            :disabled="busy || !desktopAvailable"
            @click="emit('openKnown', project)"
          >
            <AppIcon name="folder" :size="15" />
            <span class="welcome__known-label">
              <strong>{{ privacyMode ? 'Project' : project.project_name }}</strong>
              <code v-if="!privacyMode" :title="project.root">{{
                shortenProjectPath(project.root)
              }}</code>
            </span>
          </button>
        </li>
      </ul>
    </section>
  </section>
</template>

<style scoped>
.welcome {
  max-width: 780px;
  margin: 0.75rem auto 0;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  color: var(--text-primary);
}

.welcome__hero {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
}

.welcome__brand {
  display: flex;
  align-items: flex-start;
  gap: 0.9rem;
}

.welcome__brand > .app-icon {
  color: var(--accent);
}

.welcome__brand h2 {
  margin: 0;
  font-size: 1.5rem;
  letter-spacing: -0.025em;
  line-height: 1.2;
}

.welcome__subtitle {
  margin: 0.3rem 0 0;
  color: var(--text-secondary);
  font-size: 0.9375rem;
  line-height: 1.45;
  max-width: 58ch;
}

.welcome__card-copy code,
.welcome__init-prompt code {
  font-family: var(--font-mono);
  font-size: 0.85em;
  padding: 0.08rem 0.32rem;
  border-radius: 4px;
  background: var(--bg-subtle);
  color: var(--text-primary);
}

.welcome__status {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
  font-size: 0.8125rem;
}

.welcome__status-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.22rem 0.6rem;
  border-radius: 999px;
  border: 1px solid var(--border-subtle);
  background: var(--bg-surface);
  color: var(--text-secondary);
  font-weight: 550;
}

.welcome__status-chip[data-online='true'] {
  color: var(--success);
  border-color: color-mix(in srgb, var(--success), var(--border-subtle) 65%);
}

.welcome__dot {
  width: 0.45rem;
  height: 0.45rem;
  border-radius: 50%;
  background: var(--danger);
}

.welcome__status-chip[data-online='true'] .welcome__dot {
  background: var(--success);
}

.welcome__start-agent {
  padding: 0.25rem 0.65rem;
  font-size: 0.8125rem;
}

.welcome__choices {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1rem;
  align-items: stretch;
}

.welcome__card {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 1.25rem;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-subtle);
  background: var(--bg-surface);
}

.welcome__card--primary {
  border-color: color-mix(in srgb, var(--accent), var(--border-subtle) 55%);
  background: linear-gradient(
    180deg,
    color-mix(in srgb, var(--accent), var(--bg-surface) 95%) 0%,
    var(--bg-surface) 55%
  );
}

.welcome__card-icon {
  display: inline-flex;
  align-self: flex-start;
  align-items: center;
  justify-content: center;
  width: 2.15rem;
  height: 2.15rem;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-secondary);
}

.welcome__card-icon--accent {
  border-color: color-mix(in srgb, var(--accent), var(--border-subtle) 50%);
  background: color-mix(in srgb, var(--accent), var(--bg-surface) 88%);
  color: var(--accent);
}

.welcome__card h3 {
  margin: 0;
  font-size: 1.0625rem;
  letter-spacing: -0.015em;
}

.welcome__card-copy {
  margin: 0;
  color: var(--text-secondary);
  font-size: 0.875rem;
  line-height: 1.45;
}

.welcome__bullets {
  list-style: none;
  margin: 0.1rem 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  color: var(--text-secondary);
  font-size: 0.8125rem;
}

.welcome__bullets li {
  display: flex;
  align-items: center;
  gap: 0.45rem;
}

.welcome__bullets .app-icon {
  color: var(--success);
}

.welcome__cta {
  margin-top: auto;
  display: flex;
  align-items: center;
  width: 100%;
  justify-content: center;
  gap: 0.45rem;
  padding: 0.6rem 0.9rem;
}

.welcome__folder-form {
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.welcome__folder-form label {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}

.welcome__folder-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.45rem;
}

.welcome__folder-row input {
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong);
  background: var(--bg-app);
  color: var(--text-primary);
  padding: 0.5rem 0.65rem;
  font: inherit;
  font-size: 0.8125rem;
}

.welcome__folder-row :deep(small) {
  grid-column: 1 / -1;
  color: var(--text-secondary);
}

.welcome__init-prompt {
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
  padding: 0.7rem 0.8rem;
  border-radius: var(--radius-sm);
  border: 1px solid color-mix(in srgb, var(--accent), var(--border-subtle) 55%);
  background: color-mix(in srgb, var(--accent), var(--bg-app) 93%);
  font-size: 0.8125rem;
}

.welcome__init-prompt p {
  margin: 0;
  line-height: 1.4;
  overflow-wrap: anywhere;
}

.welcome__init-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}

.welcome__known {
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}

.welcome__known h3 {
  margin: 0;
  font-size: 0.75rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.welcome__known-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(220px, 100%), 1fr));
  gap: 0.5rem;
}

.welcome__known-item {
  width: 100%;
  justify-content: flex-start;
  gap: 0.55rem;
  padding: 0.55rem 0.75rem;
  text-align: left;
}

.welcome__known-label {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.welcome__known-label strong {
  font-size: 0.875rem;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.welcome__known-label code {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 680px) {
  .welcome__choices {
    grid-template-columns: 1fr;
  }
}
</style>
