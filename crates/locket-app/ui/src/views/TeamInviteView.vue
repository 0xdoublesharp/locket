<script setup lang="ts">
import { formatTime } from '../utils/formatTime';
// Desktop view for metadata-only team invite history and validated
// invite forms. Secret values and wrapped keys never pass through the
// webview; invite mutations remain available through the CLI.

import { computed, ref, watch } from 'vue';

import AppIcon from '../components/AppIcon.vue';
import CommandHandoff from '../components/CommandHandoff.vue';
import TeamSharingPanel from '../components/TeamSharingPanel.vue';
import {
  defaultAcceptForm,
  defaultIssueForm,
  defaultRevokeForm,
  agentInviteAcceptCliCommand,
  agentInviteCreateCliCommand,
  agentInviteRequestCliCommand,
  filterTeamInviteRows,
  issueDangerousConfirmationMatches,
  issueRequiresDangerousConfirmation,
  teamInviteAcceptCliCommand,
  teamInviteIssueCliCommand,
  TEAM_INVITE_DESKTOP_NOTICE,
  teamInviteRevokeCliCommand,
  teamInviteRowsFromAudit,
  validateAcceptForm,
  validateIssueForm,
  validateRevokeForm,
  type TeamInviteAcceptFormState,
  type TeamInviteIssueFormState,
  type TeamInviteRevokeFormState,
  type TeamInviteRow,
} from '../team/invite';
import type { AuditWireRow } from '../agent/types';

interface Props {
  projectId?: string;
  privacyMode?: boolean;
  confirmDangerous?: (action: string) => Promise<string | false | undefined>;
  /** Audit rows for the active project, used for invite reconstruction. */
  auditRows: ReadonlyArray<AuditWireRow>;
  /** Comma-separated list of dangerous-profile names from agent settings. */
  dangerousProfiles: string;
  /** Whether team_accept enforces fresh user-verification. */
  requireAcceptUserVerification: boolean;
  loading: boolean;
  metadataLoaded: boolean;
  actionGuidance?: string | null;
  errorMessage?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (event: 'refresh'): void;
}>();

const issueForm = ref<TeamInviteIssueFormState>(defaultIssueForm());
const issueDangerousConfirmation = ref<string>('');

const acceptForm = ref<TeamInviteAcceptFormState>(defaultAcceptForm());

const revokeForm = ref<TeamInviteRevokeFormState>(defaultRevokeForm());

const searchQuery = ref<string>('');

watch([() => props.projectId, () => props.privacyMode], () => {
  issueForm.value = { ...defaultIssueForm(), dangerousProfiles: props.dangerousProfiles };
  issueDangerousConfirmation.value = '';
  acceptForm.value = {
    ...defaultAcceptForm(),
    requireUserVerification: props.requireAcceptUserVerification,
  };
  revokeForm.value = defaultRevokeForm();
  searchQuery.value = '';
});

watch(
  () => props.dangerousProfiles,
  (next) => {
    issueForm.value = { ...issueForm.value, dangerousProfiles: next };
  },
  { immediate: true },
);

watch(
  () => props.requireAcceptUserVerification,
  (next) => {
    acceptForm.value = { ...acceptForm.value, requireUserVerification: next };
  },
  { immediate: true },
);

const inviteRows = computed<TeamInviteRow[]>(() => teamInviteRowsFromAudit(props.auditRows));

const filteredRows = computed<TeamInviteRow[]>(() => [
  ...filterTeamInviteRows(inviteRows.value, searchQuery.value),
]);

const issueValidation = computed(() => validateIssueForm(issueForm.value));
const issueRequiresConfirmation = computed<boolean>(() =>
  issueRequiresDangerousConfirmation(issueValidation.value),
);
const issueConfirmationMatches = computed<boolean>(() =>
  issueDangerousConfirmationMatches(issueValidation.value, issueDangerousConfirmation.value),
);
const issueCanSubmit = computed<boolean>(() => {
  if (!props.metadataLoaded || !issueValidation.value.valid) {
    return false;
  }
  if (issueRequiresConfirmation.value && !issueConfirmationMatches.value) {
    return false;
  }
  return true;
});

const acceptValidation = computed(() => validateAcceptForm(acceptForm.value));
const acceptCanSubmit = computed<boolean>(
  () => props.metadataLoaded && acceptValidation.value.valid,
);

const revokeValidation = computed(() => validateRevokeForm(revokeForm.value));
const revokeCanSubmit = computed<boolean>(
  () => props.metadataLoaded && revokeValidation.value.valid,
);

const issueCliCommand = computed<string | null>(() =>
  issueCanSubmit.value ? teamInviteIssueCliCommand(issueForm.value) : null,
);
const acceptCliCommand = computed<string | null>(() =>
  acceptCanSubmit.value ? teamInviteAcceptCliCommand(acceptForm.value.inviteText) : null,
);
const revokeCliCommand = computed<string | null>(() =>
  revokeCanSubmit.value ? teamInviteRevokeCliCommand(revokeForm.value.inviteId) : null,
);
const agentRequestCliCommand = computed<string | null>(() =>
  props.metadataLoaded && issueForm.value.deviceDescriptor.trim().length > 0
    ? agentInviteRequestCliCommand(issueForm.value.deviceDescriptor)
    : null,
);
const agentIssueCliCommand = computed<string | null>(() =>
  issueCanSubmit.value ? agentInviteCreateCliCommand(issueForm.value) : null,
);
const agentAcceptCliCommand = computed<string | null>(() =>
  acceptCanSubmit.value ? agentInviteAcceptCliCommand(acceptForm.value.inviteText) : null,
);

function refresh(): void {
  emit('refresh');
}

function statusBadge(status: TeamInviteRow['status']): string {
  switch (status) {
    case 'pending':
      return 'badge--info';
    case 'accepted':
      return 'badge--ok';
    case 'revoked':
      return 'badge--danger';
    case 'expired':
      return 'badge--warning';
    default:
      return 'badge--neutral';
  }
}
</script>

<template>
  <section class="view" aria-labelledby="team-invite-heading">
    <header class="companion-toolbar view__header">
      <h2 id="team-invite-heading">Team sharing</h2>
      <div class="companion-toolbar__controls">
        <span v-if="lastRefreshedAt" class="companion-toolbar__meta">
          Updated
          <time :datetime="lastRefreshedAt" :title="lastRefreshedAt">{{
            formatTime(lastRefreshedAt)
          }}</time>
        </span>
        <button
          type="button"
          class="companion-button icon-label"
          :disabled="loading"
          @click="refresh"
        >
          <AppIcon name="refresh" />
          Refresh
        </button>
      </div>
    </header>

    <TeamSharingPanel
      :project-id="projectId"
      :privacy-mode="privacyMode"
      :confirm-dangerous="confirmDangerous"
    />
    <details v-if="!privacyMode" class="view__disclosure">
      <summary>
        <AppIcon name="chevron-down" class="view__chevron" />
        <span>Invite history and advanced commands</span>
      </summary>
      <div class="view__disclosure-body">
        <p class="view__notice">
          Invites require local pending invite state. Use signed team updates above for a fresh
          machine.
        </p>
        <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>

        <p class="view__notice" role="note">
          {{ TEAM_INVITE_DESKTOP_NOTICE }}
        </p>

        <section aria-labelledby="team-invite-list-heading" class="view__panel">
          <div class="view__panel-head">
            <h3 id="team-invite-list-heading" class="view__panel-heading">
              Pending and recent invites
            </h3>
            <label class="companion-toolbar__search">
              <span class="visually-hidden">Search invites</span>
              <AppIcon name="search" :size="14" />
              <input
                v-model="searchQuery"
                class="companion-input"
                type="search"
                autocomplete="off"
                spellcheck="false"
                placeholder="Search by id, recipient, role, status, profile"
              />
            </label>
          </div>
          <p v-if="actionGuidance" class="view__empty" role="status">{{ actionGuidance }}</p>
          <p v-else-if="loading" class="view__loading" role="status">Loading invite history…</p>
          <p v-else-if="metadataLoaded && filteredRows.length === 0" class="view__empty">
            No matching invites in audit history.
          </p>
          <div
            v-else-if="metadataLoaded"
            class="companion-table-scroll"
            role="region"
            aria-labelledby="team-invite-list-heading"
            tabindex="0"
          >
            <table class="view__table" aria-describedby="team-invite-list-heading">
              <thead>
                <tr>
                  <th scope="col">Invite id</th>
                  <th scope="col">Direction</th>
                  <th scope="col">Status</th>
                  <th scope="col">Recipient / Issuer</th>
                  <th scope="col">Role</th>
                  <th scope="col">Profiles</th>
                  <th scope="col">Created</th>
                  <th scope="col">Expires</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in filteredRows" :key="row.id">
                  <td>
                    <code>{{ row.id }}</code>
                  </td>
                  <td>{{ row.direction }}</td>
                  <td>
                    <span class="badge" :class="statusBadge(row.status)">{{ row.status }}</span>
                  </td>
                  <td>
                    <span v-if="row.direction === 'issued'">{{ row.recipientLabel ?? '—' }}</span>
                    <span v-else>{{ row.issuerLabel ?? '—' }}</span>
                  </td>
                  <td>{{ row.role ?? '—' }}</td>
                  <td>
                    <span v-if="row.profiles.length > 0">{{ row.profiles.join(', ') }}</span>
                    <span v-else class="view__muted">—</span>
                  </td>
                  <td>
                    <time :datetime="row.createdAt" :title="row.createdAt">{{
                      formatTime(row.createdAt)
                    }}</time>
                  </td>
                  <td>
                    <time v-if="row.expiresAt" :datetime="row.expiresAt" :title="row.expiresAt">{{
                      formatTime(row.expiresAt, 'timestamp')
                    }}</time>
                    <span v-else class="view__muted">—</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section aria-labelledby="team-invite-issue-heading" class="view__panel">
          <h3 id="team-invite-issue-heading" class="view__panel-heading">Issue invite</h3>
          <form @submit.prevent>
            <label class="view__field">
              <span>Recipient label</span>
              <input
                v-model="issueForm.recipientLabel"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-recipient"
              />
              <span v-if="issueValidation.errors.recipientLabel" class="view__error">
                {{ issueValidation.errors.recipientLabel }}
              </span>
            </label>
            <label class="view__field">
              <span>Recipient device descriptor</span>
              <textarea
                v-model="issueForm.deviceDescriptor"
                rows="2"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-descriptor"
              />
              <span v-if="issueValidation.errors.deviceDescriptor" class="view__error">
                {{ issueValidation.errors.deviceDescriptor }}
              </span>
            </label>
            <div class="view__row">
              <label class="view__field">
                <span>Role</span>
                <select v-model="issueForm.role">
                  <option value="developer">developer</option>
                  <option value="maintainer">maintainer</option>
                  <option value="owner">owner</option>
                  <option value="read-only">read-only</option>
                </select>
              </label>
              <label class="view__field">
                <span>Expiry (ISO 8601)</span>
                <input
                  v-model="issueForm.expiresAt"
                  type="datetime-local"
                  autocomplete="off"
                  spellcheck="false"
                />
                <span v-if="issueValidation.errors.expiresAt" class="view__error">
                  {{ issueValidation.errors.expiresAt }}
                </span>
              </label>
            </div>
            <label class="view__field">
              <span>Profiles (comma-separated)</span>
              <input
                v-model="issueForm.profiles"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-profiles"
              />
              <span v-if="issueValidation.errors.profiles" class="view__error">
                {{ issueValidation.errors.profiles }}
              </span>
            </label>
            <p v-if="issueRequiresConfirmation" class="view__warn" role="status">
              This invite includes the dangerous profile(s):
              <strong>{{ issueValidation.dangerousMatches.join(', ') }}</strong
              >. Type each dangerous profile name to confirm.
            </p>
            <label v-if="issueRequiresConfirmation" class="view__field">
              <span>Type dangerous profile name(s)</span>
              <input
                v-model="issueDangerousConfirmation"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-dangerous-confirmation"
              />
            </label>
            <div class="view__form-actions">
              <CommandHandoff
                v-if="issueCliCommand"
                :command="issueCliCommand"
                label="Issue invite command"
                data-testid="team-invite-issue-cli-command"
              />
              <CommandHandoff
                v-if="agentRequestCliCommand"
                :command="agentRequestCliCommand"
                label="Agent request command"
                data-testid="agent-invite-request-cli-command"
              />
              <CommandHandoff
                v-if="agentIssueCliCommand"
                :command="agentIssueCliCommand"
                label="Agent invite command"
                data-testid="agent-invite-create-cli-command"
              />
              <span v-else class="view__muted">Complete the fields to show the CLI command.</span>
            </div>
          </form>
        </section>

        <section aria-labelledby="team-invite-accept-heading" class="view__panel">
          <h3 id="team-invite-accept-heading" class="view__panel-heading">Accept invite</h3>
          <form @submit.prevent>
            <label class="view__field">
              <span>Paste invite text</span>
              <textarea
                v-model="acceptForm.inviteText"
                rows="6"
                spellcheck="false"
                autocomplete="off"
                data-testid="team-invite-accept-text"
              />
              <span v-if="acceptValidation.errors.inviteText" class="view__error">
                {{ acceptValidation.errors.inviteText }}
              </span>
            </label>
            <label class="view__field">
              <span>Issuer device fingerprint (64 hex)</span>
              <input
                v-model="acceptForm.fingerprintConfirmation"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-accept-fingerprint"
              />
              <span v-if="acceptValidation.errors.fingerprintConfirmation" class="view__error">
                {{ acceptValidation.errors.fingerprintConfirmation }}
              </span>
            </label>
            <label v-if="acceptForm.requireUserVerification" class="view__check">
              <input v-model="acceptForm.userVerified" type="checkbox" />
              I have completed local user verification (platform prompt / hardware key / passphrase
              fallback).
              <span v-if="acceptValidation.errors.userVerified" class="view__error">
                {{ acceptValidation.errors.userVerified }}
              </span>
            </label>
            <div class="view__form-actions">
              <CommandHandoff
                v-if="acceptCliCommand"
                :command="acceptCliCommand"
                label="Accept pasted invite command"
                data-testid="team-invite-accept-cli-command"
              />
              <CommandHandoff
                v-if="agentAcceptCliCommand"
                :command="agentAcceptCliCommand"
                label="Accept pasted agent invite command"
                data-testid="agent-invite-accept-cli-command"
              />
              <span v-else class="view__muted">Complete the checks to show the CLI command.</span>
            </div>
          </form>
        </section>

        <section aria-labelledby="team-invite-revoke-heading" class="view__panel">
          <h3 id="team-invite-revoke-heading" class="view__panel-heading">Revoke invite</h3>
          <p class="view__muted">
            Owners and the issuing maintainer may revoke an outstanding invite.
          </p>
          <form @submit.prevent>
            <label class="view__field">
              <span>Invite id</span>
              <input
                v-model="revokeForm.inviteId"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-revoke-id"
              />
              <span v-if="revokeValidation.errors.inviteId" class="view__error">
                {{ revokeValidation.errors.inviteId }}
              </span>
            </label>
            <label class="view__field">
              <span>Type the invite id again to confirm</span>
              <input
                v-model="revokeForm.confirmation"
                type="text"
                autocomplete="off"
                spellcheck="false"
                data-testid="team-invite-revoke-confirm"
              />
              <span v-if="revokeValidation.errors.confirmation" class="view__error">
                {{ revokeValidation.errors.confirmation }}
              </span>
            </label>
            <div class="view__form-actions">
              <CommandHandoff
                v-if="revokeCliCommand"
                :command="revokeCliCommand"
                label="Revoke invite command"
                data-testid="team-invite-revoke-cli-command"
              />
              <span v-else class="view__muted"
                >Complete the confirmation to show the CLI command.</span
              >
            </div>
          </form>
        </section>
      </div>
    </details>
  </section>
</template>

<style scoped>
.view {
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}
.view__header h2 {
  margin: 0;
  font-size: 1rem;
}
.view__disclosure {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
}
.view__disclosure > summary {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.7rem 1rem;
  border-radius: var(--radius-md);
  font-size: 0.875rem;
  font-weight: 600;
  cursor: pointer;
  list-style: none;
}
.view__disclosure > summary::-webkit-details-marker {
  display: none;
}
.view__disclosure > summary:hover {
  background: var(--bg-subtle);
}
.view__disclosure[open] > summary {
  border-bottom: 1px solid var(--border-subtle);
  border-radius: var(--radius-md) var(--radius-md) 0 0;
}
.view__chevron {
  flex: none;
  color: var(--text-muted);
  transform: rotate(-90deg);
  transition: transform 120ms ease;
}
.view__disclosure[open] .view__chevron {
  transform: none;
}
.view__disclosure-body {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 1rem;
}
.view__panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem 0.75rem;
}
.view__panel {
  background: var(--bg-surface);
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
  padding: 0.875rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.view__panel-heading {
  margin: 0;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
}
.view__field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.85rem;
}
.view__field input,
.view__field select,
.view__field textarea {
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  padding: 0.4rem 0.6rem;
  font: inherit;
  font-size: 0.85rem;
}
.view__row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
}
.view__check {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
  font-size: 0.85rem;
}
.view__warn {
  margin: 0;
  padding: 0.5rem 0.625rem;
  background: var(--accent-soft);
  border: 1px solid var(--accent);
  color: var(--accent);
  border-radius: 0.375rem;
  font-size: 0.8rem;
}
.view__notice {
  margin: 0;
  padding: 0.5rem 0.625rem;
  background: var(--info-soft);
  border: 1px solid var(--border-strong);
  color: var(--info);
  border-radius: 0.375rem;
  font-size: 0.78rem;
}
.view__notice code {
  background: var(--bg-subtle);
  padding: 0 0.25rem;
  border-radius: 0.25rem;
}
.view__form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}
.view__button {
  min-height: 2rem;
  border: 1px solid var(--border-strong);
  border-radius: 0.375rem;
  background: var(--bg-subtle);
  color: var(--text-primary);
  cursor: pointer;
  font: inherit;
  font-size: 0.8125rem;
  padding: 0.25rem 0.625rem;
}
.view__button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.view__button--primary {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: transparent;
}
.view__button--danger {
  background: var(--danger);
  color: var(--accent-fg);
  border-color: transparent;
}
.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary);
}
.view__error {
  margin: 0;
  color: var(--danger);
  font-size: 0.8rem;
}
.view__muted {
  color: var(--text-secondary);
}
.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
.view__table th,
.view__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: top;
}
.view__table th {
  font-weight: 600;
  color: var(--text-secondary);
  font-size: 0.75rem;
  letter-spacing: 0.04em;
}
.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  border: 1px solid var(--border-subtle);
  background: var(--bg-subtle);
  color: var(--text-primary);
}
.badge--info {
  background: var(--info-soft);
  border-color: var(--border-strong);
  color: var(--info);
}
.badge--ok {
  background: var(--success-soft);
  border-color: var(--border-strong);
  color: var(--success);
}
.badge--warning {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}
.badge--danger {
  background: var(--danger-soft);
  border-color: var(--danger);
  color: var(--danger);
}
.badge--neutral {
  color: var(--text-secondary);
}
</style>
