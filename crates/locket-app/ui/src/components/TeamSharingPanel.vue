<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import AppIcon from './AppIcon.vue';
import CommandHandoff from './CommandHandoff.vue';
import { formatTime } from '../utils/formatTime';
import {
  actionError,
  desktopTeamSyncStatus,
  desktopTeamSyncNow,
  desktopTeamSyncConfigure,
  desktopTeamSyncRenameProfile,
  desktopTeamSyncPreserveOverride,
} from '../agent/client';
import { joinCommand, syncMessage, type TeamSyncStatus } from '../team/sync';
const props = defineProps<{
  projectId?: string;
  privacyMode?: boolean;
  confirmDangerous?: (action: string) => Promise<string | false | undefined>;
}>();
const status = ref<TeamSyncStatus | null>(null);
const busy = ref(false);
const error = ref('');
const folder = ref('');
const ownerPin = ref('');
const allowDangerous = ref(false);
const localNames = ref<Record<string, string>>({});
const join = computed(() => joinCommand(folder.value, ownerPin.value));
const message = computed(() =>
  status.value ? syncMessage(status.value) : 'Check this project’s last verified team update.',
);
const hasWaiting = computed(() => (status.value?.waiting ?? 0) > 0);
const folderSegments = computed(() => status.value?.folder?.split('/') ?? []);
const verifiedIso = computed(() =>
  status.value?.last_verified_at
    ? new Date(status.value.last_verified_at / 1_000_000).toISOString()
    : null,
);
const verifiedAt = computed(() =>
  verifiedIso.value ? formatTime(verifiedIso.value) : 'No verified update received',
);
const verifiedExact = computed(() =>
  verifiedIso.value ? formatTime(verifiedIso.value, 'datetime') : null,
);
const tone = computed(() => {
  const state = status.value?.state;
  if (!state) return 'info';
  if (['fork', 'rollback', 'stopped', 'delivery-error', 'removed'].includes(state)) return 'danger';
  if (
    state === 'locked' ||
    state === 'unanchored' ||
    status.value?.conflicts ||
    Object.keys(status.value?.pending_profiles ?? {}).length
  )
    return 'warn';
  return 'info';
});
let generation = 0;
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  timer = setInterval(() => {
    void perform('status');
  }, 30_000);
});
onUnmounted(() => {
  generation++;
  if (timer) clearInterval(timer);
});
async function perform(kind: 'status' | 'now' | 'configure') {
  const project = props.projectId;
  if (!project || busy.value) return;
  const token = generation;
  busy.value = true;
  error.value = '';
  try {
    const approved =
      kind === 'status' || !props.confirmDangerous
        ? false
        : await props.confirmDangerous(
            kind === 'now' ? 'Sync team updates' : 'Configure team sync',
          );
    if (approved === undefined || token !== generation || project !== props.projectId) return;
    const request = {
      project_id: project,
      ...(approved && { confirm_dangerous_profile: approved }),
    };
    const result =
      kind === 'now'
        ? await desktopTeamSyncNow(request)
        : kind === 'configure'
          ? await desktopTeamSyncConfigure({
              ...request,
              folder: folder.value,
              allow_dangerous: allowDangerous.value,
            })
          : await desktopTeamSyncStatus(request);
    if (token !== generation || project !== props.projectId) return;
    if (result.ok) status.value = result.value;
    else error.value = actionError(result.error);
  } finally {
    if (token === generation) busy.value = false;
  }
}
async function reconcile(incoming: string, localId: string, kind: 'profile' | 'value') {
  const project = props.projectId;
  if (!project || busy.value) return;
  const token = generation;
  busy.value = true;
  error.value = '';
  try {
    const approved = props.confirmDangerous
      ? await props.confirmDangerous('Reconcile team changes')
      : false;
    if (approved === undefined || token !== generation || project !== props.projectId) return;
    const confirmation = approved ? { confirm_dangerous_profile: approved } : {};
    const result =
      kind === 'profile'
        ? await desktopTeamSyncRenameProfile({
            project_id: project,
            ...confirmation,
            incoming_profile_id: incoming,
            local_profile_id: localId,
            new_name: localNames.value[incoming]?.trim() ?? '',
          })
        : await desktopTeamSyncPreserveOverride({
            project_id: project,
            ...confirmation,
            incoming_profile_id: incoming,
            local_secret_id: localId,
          });
    if (token !== generation || project !== props.projectId) return;
    if (result.ok) status.value = result.value;
    else error.value = actionError(result.error);
  } finally {
    if (token === generation) busy.value = false;
  }
}

watch(
  () => props.projectId,
  () => {
    generation++;
    busy.value = false;
    status.value = null;
    error.value = '';
    folder.value = '';
    ownerPin.value = '';
    allowDangerous.value = false;
    localNames.value = {};
    void perform('status');
  },
  { immediate: true },
);
</script>
<template>
  <section class="sharing" aria-labelledby="signed-sharing-heading">
    <header class="sharing__head">
      <div class="sharing__intro">
        <h3 id="signed-sharing-heading">Signed team updates</h3>
        <p class="sharing__lede">
          One owner publishes shared values. Each device receives an encrypted package; personal
          overrides stay local.
        </p>
      </div>
      <div class="sharing__actions">
        <button
          type="button"
          class="companion-button icon-label"
          :class="{ 'companion-button--primary': !hasWaiting }"
          :disabled="busy || !projectId"
          @click="perform('status')"
        >
          <AppIcon name="refresh" />
          Check status
        </button>
        <button
          type="button"
          class="companion-button icon-label"
          :class="{ 'companion-button--primary': hasWaiting }"
          :disabled="busy || !projectId"
          @click="perform('now')"
        >
          <AppIcon name="check" />
          Apply verified updates
        </button>
      </div>
    </header>
    <p :class="['sharing__banner', `sharing__banner--${tone}`]" role="status">
      <AppIcon :name="tone === 'info' ? 'info' : 'alert'" />
      <span>{{ message }}</span>
    </p>
    <template v-if="status">
      <dl class="sharing__facts">
        <div class="sharing__fact--verified">
          <dt>Last verified</dt>
          <dd>
            <time
              v-if="verifiedIso"
              class="sharing__verified"
              :datetime="verifiedIso"
              :title="verifiedIso"
            >
              <span class="sharing__verified-relative">{{ verifiedAt }}</span>
              <span class="sharing__verified-exact">{{ verifiedExact }}</span>
            </time>
            <span v-else class="sharing__muted">{{ verifiedAt }}</span>
          </dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>
            <span class="companion-pill">#{{ status.epoch }}</span>
          </dd>
        </div>
        <div v-if="status.waiting_known || hasWaiting">
          <dt>Waiting updates</dt>
          <dd>
            <span
              :class="['companion-pill', status.waiting ? 'companion-pill--warn' : '']"
              :title="`${status.waiting} update files waiting for verification.`"
              >{{ status.waiting }} {{ status.waiting === 1 ? 'file' : 'files' }}</span
            >
          </dd>
        </div>
        <div v-if="!privacyMode && status.folder" class="sharing__fact--wide">
          <dt>Delivery folder</dt>
          <dd>
            <code>
              <template v-for="(segment, index) in folderSegments" :key="index"
                >{{ segment }}<template v-if="index < folderSegments.length - 1">/<wbr /></template>
              </template>
            </code>
          </dd>
        </div>
        <div v-if="!privacyMode && status.owner_fingerprint" class="sharing__fact--wide">
          <dt>Owner fingerprint</dt>
          <dd>
            <code>{{ status.owner_fingerprint }}</code>
          </dd>
        </div>
      </dl>
      <p v-if="status.last_error" class="sharing__alert" role="alert">
        {{ privacyMode ? 'Delivery needs attention.' : status.last_error }}
      </p>
      <p v-if="status.conflicts" class="sharing__hint">
        Resolve each value with <code>locket team sync resolve SECRET_ID keep-local</code> or
        <code>take-team</code>. Find the IDs with <code>locket team sync status</code>.
      </p>
      <div v-if="!privacyMode && status.pending_details?.length" class="pending">
        <article v-for="profile in status.pending_details" :key="profile.profile_id">
          <strong>{{ profile.profile_name }}</strong>
          <template v-if="profile.reason === 'consent-required'">
            <p>
              Values are held because this profile is dangerous on this machine or in the signed
              update.
            </p>
            <p>
              To accept automatic delivery, open “Set up this device”, choose the shared folder, and
              explicitly allow dangerous profiles. This consent applies to the folder’s shared
              profiles on this machine.
            </p>
          </template>
          <template v-else-if="profile.colliding_profile">
            <p>
              A different local profile is already named {{ profile.colliding_profile.name }}. Give
              that local profile a new name to keep its values and make room for the team profile.
            </p>
            <p>
              Policies, default_profile and lk:// references using the old name will refer to the
              incoming team profile after retry. Review those references before using it. Directory
              grants remain on the renamed local profile’s ID.
            </p>
            <label class="sharing__field"
              >New name for your local profile
              <input
                v-model="localNames[profile.profile_id]"
                class="companion-input"
                autocomplete="off"
              />
            </label>
            <button
              type="button"
              class="companion-button companion-button--primary"
              :disabled="busy || !localNames[profile.profile_id]?.trim()"
              @click="reconcile(profile.profile_id, profile.colliding_profile.id, 'profile')"
            >
              Rename local profile and retry
            </button>
          </template>
          <template v-else-if="profile.colliding_secrets.length">
            <p>
              These existing values have different IDs from the incoming team values. Keep each as a
              personal override before receiving the shared version.
            </p>
            <div
              v-for="secret in profile.colliding_secrets"
              :key="secret.id"
              class="pending__collision"
            >
              <code>{{ secret.name }}</code>
              <button
                type="button"
                class="companion-button"
                :disabled="busy"
                @click="reconcile(profile.profile_id, secret.id, 'value')"
              >
                Keep as personal override and retry
              </button>
            </div>
          </template>
          <p v-else>
            The local collision has been resolved. Apply verified updates to retry delivery using
            your saved consent.
          </p>
        </article>
      </div>
      <p
        v-if="
          !privacyMode &&
          Object.keys(status.pending_profiles ?? {}).length &&
          !status.pending_details?.length
        "
        class="sharing__hint"
      >
        Run <code>locket team sync pending</code> for the authenticated collision details and
        resolution commands.
      </p>
    </template>
    <p v-if="error" class="sharing__alert" role="alert">
      {{
        privacyMode ? 'Team update check failed. Turn off privacy mode to read the details.' : error
      }}
    </p>
    <details v-if="!privacyMode" class="sharing__disclosure">
      <summary>
        <AppIcon name="chevron-down" class="sharing__chevron" />
        <span>Set up this device</span>
      </summary>
      <div class="sharing__disclosure-body">
        <ol class="sharing__steps">
          <li>
            Clone the project, then prepare this device:
            <CommandHandoff command="locket team join --request" label="Prepare receiving device" />
          </li>
          <li>
            Give the descriptor to the owner. Compare your full device fingerprint through a
            separate trusted channel. The owner adds your device and publishes to the shared folder.
          </li>
          <li>
            Get the owner’s full fingerprint through that trusted channel. A fingerprint supplied
            only inside the folder is insufficient.
          </li>
        </ol>
        <div class="sharing__form">
          <label class="sharing__field"
            >Shared folder
            <input
              v-model="folder"
              class="companion-input"
              autocomplete="off"
              placeholder="/path/to/shared-folder"
          /></label>
          <label class="sharing__field"
            >Independently verified owner fingerprint
            <input
              v-model="ownerPin"
              class="companion-input sharing__mono"
              autocomplete="off"
              spellcheck="false"
              maxlength="64"
          /></label>
        </div>
        <CommandHandoff v-if="join" :command="join" label="Join verified team" />
        <p>Already joined? Choose this folder for automatic updates while unlocked.</p>
        <label class="sharing__check"
          ><input v-model="allowDangerous" type="checkbox" /> Allow automatic delivery to dangerous
          profiles on this machine</label
        >
        <div class="sharing__actions sharing__actions--start">
          <button
            type="button"
            class="companion-button companion-button--primary"
            :disabled="busy || !projectId || !folder.trim()"
            @click="perform('configure')"
          >
            Save folder and consent
          </button>
        </div>
        <p class="sharing__muted">
          After saving, choose “Apply verified updates” to retry held values.
        </p>
        <p class="sharing__muted">
          Owners can publish immediately with <code>locket team publish</code>. The unlocked owner’s
          agent also publishes changed shared values automatically. Removing a teammate cannot erase
          values already received; rotate credentials at their providers.
        </p>
      </div>
    </details>
  </section>
</template>
<style scoped>
.sharing {
  container: sharing / inline-size;
  display: grid;
  gap: 0.75rem;
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  color: var(--text-primary);
  font-size: 0.875rem;
}
.sharing h3 {
  margin: 0;
  font-size: 1rem;
}
.sharing p {
  margin: 0;
  line-height: 1.5;
}
.sharing__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem 1rem;
}
.sharing__intro {
  flex: 1 1 22rem;
  min-width: 0;
}
.sharing .sharing__lede {
  margin-top: 0.25rem;
  color: var(--text-secondary);
}
.sharing__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.sharing__actions--start {
  justify-content: flex-start;
}
.sharing__banner {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.55rem 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.sharing__banner .app-icon {
  flex: none;
  margin-top: 0.15rem;
}
.sharing__banner--info .app-icon {
  color: var(--info);
}
.sharing__banner--warn {
  border-color: transparent;
  background: var(--warn-soft);
  color: var(--warn);
}
.sharing__banner--danger {
  border-color: var(--danger);
  background: var(--danger-soft);
  color: var(--danger);
}
.sharing__facts {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: start;
  gap: 0.65rem 0.5rem;
  margin: 0;
  padding: 0.75rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
}
.sharing__facts > div {
  min-width: 0;
}
.sharing__fact--wide {
  grid-column: 1 / -1;
}
.sharing__verified {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}
.sharing__verified-relative {
  font-weight: 500;
}
.sharing__verified-exact {
  color: var(--text-muted);
  font-size: 0.75rem;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.sharing__facts dt {
  color: var(--text-muted);
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.sharing__facts dd {
  margin: 0.25rem 0 0;
}
.sharing__facts code {
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}
.sharing__alert {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--danger);
  border-radius: var(--radius-sm);
  background: var(--danger-soft);
  color: var(--danger);
}
.sharing__hint,
.sharing__muted {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.sharing code {
  overflow-wrap: anywhere;
}
.pending {
  display: grid;
  gap: 0.5rem;
}
.pending article {
  display: grid;
  gap: 0.5rem;
  padding: 0.75rem;
  border: 1px solid var(--border-subtle);
  border-left: 3px solid var(--warn);
  border-radius: var(--radius-sm);
}
.pending article p {
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.pending article > .companion-button {
  justify-self: start;
}
.pending__collision {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.sharing__disclosure {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
}
.sharing__disclosure summary {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 0.75rem;
  border-radius: var(--radius-sm);
  font-weight: 600;
  cursor: pointer;
  list-style: none;
}
.sharing__disclosure summary::-webkit-details-marker {
  display: none;
}
.sharing__disclosure summary:hover {
  background: var(--bg-subtle);
}
.sharing__chevron {
  flex: none;
  color: var(--text-muted);
  transform: rotate(-90deg);
  transition: transform 120ms ease;
}
.sharing__disclosure[open] .sharing__chevron {
  transform: none;
}
.sharing__disclosure[open] summary {
  border-bottom: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm) var(--radius-sm) 0 0;
}
.sharing__disclosure-body {
  display: grid;
  gap: 0.75rem;
  padding: 0.75rem;
}
.sharing__steps {
  display: grid;
  gap: 0.6rem;
  margin: 0;
  padding-left: 1.25rem;
  color: var(--text-secondary);
}
.sharing__form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 16rem), 1fr));
  gap: 0.75rem;
}
.sharing__field {
  display: grid;
  gap: 0.3rem;
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.sharing__mono {
  font-family: var(--font-mono);
}
.sharing__check {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  font-size: 0.8125rem;
}
.sharing__check input {
  margin: 0.15rem 0 0;
  accent-color: var(--accent);
}
@container sharing (max-width: 30rem) {
  .sharing__head > .sharing__actions {
    display: grid;
    width: 100%;
    grid-template-columns: minmax(0, 1fr);
  }

  .sharing__head > .sharing__actions .companion-button {
    width: 100%;
  }

  .sharing__facts {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.65rem 0.75rem;
  }

  .sharing__fact--verified {
    grid-column: 1 / -1;
  }

  .sharing__verified {
    flex-direction: row;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.15rem 0.5rem;
  }

  .sharing__actions--start,
  .sharing__actions--start .companion-button {
    width: 100%;
  }
}
</style>
