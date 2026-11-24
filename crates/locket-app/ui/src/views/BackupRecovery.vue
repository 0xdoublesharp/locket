<script setup lang="ts">
import { computed, ref } from 'vue';

import { exportSelectionKey } from '../backup/actions';
import type {
  BundleAction,
  ExportDraft,
  ImportDraft,
  RotateDraft,
  VerifyDraft,
} from '../backup/actions';

defineOptions({ name: 'BackupRecovery' });
const props = defineProps<{
  busy?: boolean;
  previewKey?: string | null;
  previewMessage?: string | null;
}>();

const emit = defineEmits<{
  (e: 'action', action: BundleAction): void;
}>();

const exportDraft = ref<ExportDraft>({
  recipientDescriptor: '',
  scope: 'active-profile',
  includeAudit: false,
  includePersonal: false,
  includeHistory: false,
  previewOnly: false,
  outputPath: '',
});

const importDraft = ref<ImportDraft>({
  bundlePath: '',
  includeAudit: false,
  conflictMode: 'review',
});

const verifyDraft = ref<VerifyDraft>({
  bundlePath: '',
  requireDecryptable: false,
});

const rotateDraft = ref<RotateDraft>({
  verification: 'platform',
  acknowledgedOneTimeDisplay: false,
  clearAfterDisplay: true,
});

const canExport = computed<boolean>(() => exportDraft.value.recipientDescriptor.trim().length > 0);
const canImport = computed<boolean>(() => importDraft.value.bundlePath.trim().length > 0);
const canVerify = computed<boolean>(() => verifyDraft.value.bundlePath.trim().length > 0);
const canRotate = computed<boolean>(() => rotateDraft.value.acknowledgedOneTimeDisplay);

const previewMatches = computed(
  () => props.previewKey === exportSelectionKey(exportDraft.value) && !!props.previewMessage,
);

function exportAction(previewOnly = false): void {
  if (props.busy || (!previewOnly && !previewMatches.value)) return;
  emit('action', {
    kind: 'export',
    label: 'export sealed bundle',
    request: { ...exportDraft.value, previewOnly },
  });
}

function importAction(): void {
  emit('action', {
    kind: 'import',
    label: 'import bundle',
    request: { ...importDraft.value },
  });
}

function verifyAction(): void {
  emit('action', {
    kind: 'verify',
    label: 'verify bundle',
    request: { ...verifyDraft.value },
  });
}

function rotateAction(): void {
  emit('action', {
    kind: 'rotate',
    label: 'rotate recovery code',
    request: { ...rotateDraft.value },
  });
}
</script>

<template>
  <section class="view" aria-labelledby="backup-recovery-heading">
    <header class="view__header">
      <h2 id="backup-recovery-heading">Backup &amp; recovery</h2>
    </header>

    <div class="view__grid">
      <section class="view__section" aria-labelledby="backup-export-heading">
        <header class="view__section-header">
          <h3 id="backup-export-heading">Export sealed bundle</h3>
          <span class="badge badge--safe">encrypted values</span>
        </header>

        <label class="view__field">
          <span>Recipient descriptor</span>
          <textarea
            v-model.trim="exportDraft.recipientDescriptor"
            rows="3"
            spellcheck="false"
            autocomplete="off"
            placeholder="lkdev2_..."
          />
        </label>

        <fieldset class="view__fieldset">
          <legend>Environments</legend>
          <label>
            <input v-model="exportDraft.scope" type="radio" value="active-profile" />
            <span>Active environment</span>
          </label>
          <label>
            <input v-model="exportDraft.scope" type="radio" value="all-profiles" />
            <span>All environments</span>
          </label>
        </fieldset>

        <label class="view__field view__field--inline">
          <input v-model="exportDraft.includeAudit" type="checkbox" />
          <span>Include audit rows</span>
        </label>

        <p>
          Shared variables and current versions only by default. Preview the recipient and selection
          before exporting.
        </p>
        <label class="view__field view__field--inline"
          ><input v-model="exportDraft.includePersonal" type="checkbox" /><span
            >Include my overrides and this machine</span
          ></label
        >
        <label class="view__field view__field--inline"
          ><input v-model="exportDraft.includeHistory" type="checkbox" /><span
            >Include previous versions</span
          ></label
        >
        <label class="view__field">
          <span>Output path</span>
          <input v-model.trim="exportDraft.outputPath" type="text" autocomplete="off" />
        </label>

        <button
          type="button"
          class="view__action"
          :disabled="!canExport || props.busy"
          @click="exportAction(true)"
        >
          Preview scope
        </button>
        <p v-if="previewMatches" role="status" class="view__preview">{{ props.previewMessage }}</p>
        <button
          type="button"
          class="view__action"
          :disabled="!canExport || !previewMatches || props.busy"
          @click="exportAction(false)"
        >
          Export
        </button>
      </section>

      <section class="view__section" aria-labelledby="backup-import-heading">
        <header class="view__section-header">
          <h3 id="backup-import-heading">Import bundle</h3>
          <span class="badge badge--warning">conflict review</span>
        </header>

        <p>
          Imported commands require explicit local approval before running. Sealed bundles do not
          authenticate their issuer.
        </p>
        <label class="view__field">
          <span>Bundle path</span>
          <input v-model.trim="importDraft.bundlePath" type="text" autocomplete="off" />
        </label>

        <label class="view__field view__field--inline">
          <input v-model="importDraft.includeAudit" type="checkbox" />
          <span>Import audit evidence</span>
        </label>

        <fieldset class="view__fieldset">
          <legend>Conflict mode</legend>
          <label>
            <input v-model="importDraft.conflictMode" type="radio" value="review" />
            <span>Review only, no changes</span>
          </label>
          <label>
            <input v-model="importDraft.conflictMode" type="radio" value="accept-incoming" />
            <span>Import and replace conflicting values</span>
          </label>
          <label>
            <input v-model="importDraft.conflictMode" type="radio" value="accept-local" />
            <span>Import new values and keep local conflicts</span>
          </label>
        </fieldset>

        <button
          type="button"
          class="view__action"
          :disabled="!canImport || props.busy"
          @click="importAction"
        >
          {{ importDraft.conflictMode === 'review' ? 'Review bundle' : 'Apply import' }}
        </button>
      </section>

      <section class="view__section" aria-labelledby="backup-verify-heading">
        <header class="view__section-header">
          <h3 id="backup-verify-heading">Verify bundle</h3>
          <span class="badge badge--safe">non-destructive</span>
        </header>

        <label class="view__field">
          <span>Bundle path</span>
          <input v-model.trim="verifyDraft.bundlePath" type="text" autocomplete="off" />
        </label>

        <label class="view__field view__field--inline">
          <input v-model="verifyDraft.requireDecryptable" type="checkbox" />
          <span>Require local recipient</span>
        </label>

        <dl class="view__definitions">
          <div>
            <dt>Structural check</dt>
            <dd>pending</dd>
          </div>
          <div>
            <dt>Decryptable</dt>
            <dd>unknown</dd>
          </div>
        </dl>

        <button type="button" class="view__action" :disabled="!canVerify" @click="verifyAction">
          Verify
        </button>
      </section>

      <section class="view__section" aria-labelledby="recovery-rotate-heading">
        <header class="view__section-header">
          <h3 id="recovery-rotate-heading">Rotate recovery code</h3>
          <span class="badge badge--danger">user verification</span>
        </header>

        <fieldset class="view__fieldset">
          <legend>Verification</legend>
          <label>
            <input v-model="rotateDraft.verification" type="radio" value="platform" />
            <span>Platform prompt</span>
          </label>
          <label>
            <input v-model="rotateDraft.verification" type="radio" value="current-code" />
            <span>Current recovery code</span>
          </label>
        </fieldset>

        <label class="view__field view__field--inline">
          <input v-model="rotateDraft.acknowledgedOneTimeDisplay" type="checkbox" />
          <span>One-time display acknowledged</span>
        </label>

        <label class="view__field view__field--inline">
          <input v-model="rotateDraft.clearAfterDisplay" type="checkbox" />
          <span>Clear screen after display</span>
        </label>

        <button
          type="button"
          class="view__action view__action--danger"
          :disabled="!canRotate"
          @click="rotateAction"
        >
          Rotate
        </button>
      </section>
    </div>
  </section>
</template>

<style scoped>
.view__preview {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.view {
  background: #0f1115;
  color: #e6e8ec;
  padding: 1rem;
  border-radius: 0.5rem;
}

.view__header {
  margin-bottom: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 1rem;
}

.view__section {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  min-width: 0;
  padding: 0.875rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
}

.view__section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
}

.view__section-header h3 {
  margin: 0;
  font-size: 0.875rem;
}

.view__field,
.view__fieldset {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  margin: 0;
  padding: 0;
  border: 0;
  font-size: 0.8125rem;
  color: #9aa3b2;
}

.view__field--inline,
.view__fieldset label {
  flex-direction: row;
  align-items: center;
  color: #e6e8ec;
}

.view__fieldset {
  gap: 0.5rem;
}

.view__fieldset legend {
  padding: 0;
  margin-bottom: 0.375rem;
  color: #9aa3b2;
}

.view__fieldset label {
  display: inline-flex;
  gap: 0.5rem;
  margin-right: 0.75rem;
}

.view__field input[type='text'],
.view__field textarea {
  width: 100%;
  box-sizing: border-box;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  padding: 0.5rem;
  font: inherit;
}

.view__field textarea {
  resize: vertical;
  min-height: 4.75rem;
}

.view__field input[type='checkbox'],
.view__fieldset input[type='radio'] {
  accent-color: #f8d77a;
}

.view__field input:focus-visible,
.view__field textarea:focus-visible,
.view__fieldset input:focus-visible,
.view__action:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__definitions {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem;
  font-size: 0.8125rem;
}

.view__definitions dt {
  color: #9aa3b2;
}

.view__definitions dd {
  margin: 0.125rem 0 0;
  color: #e6e8ec;
}

.view__action {
  align-self: flex-start;
  border: 1px solid rgba(248, 215, 122, 0.32);
  border-radius: 0.375rem;
  background: rgba(248, 215, 122, 0.12);
  color: #f8d77a;
  padding: 0.375rem 0.875rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover:not(:disabled) {
  background: rgba(248, 215, 122, 0.18);
}

.view__action:disabled {
  cursor: not-allowed;
  opacity: 0.45;
}

.view__action--danger {
  border-color: rgba(240, 138, 138, 0.32);
  background: rgba(240, 138, 138, 0.12);
  color: #f4b3b3;
}

.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  letter-spacing: 0.02em;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  white-space: nowrap;
}

.badge--safe {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--warning {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}

.badge--danger {
  background: rgba(240, 138, 138, 0.12);
  border-color: rgba(240, 138, 138, 0.32);
  color: #f4b3b3;
}

@media (max-width: 960px) {
  .view__grid {
    grid-template-columns: 1fr;
  }
}
</style>
