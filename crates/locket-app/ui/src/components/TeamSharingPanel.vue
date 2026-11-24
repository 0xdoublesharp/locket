<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import CommandHandoff from './CommandHandoff.vue';
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
  confirmDangerous?: (action: string) => Promise<boolean | undefined>;
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
const verifiedAt = computed(() =>
  status.value?.last_verified_at
    ? new Date(status.value.last_verified_at / 1_000_000).toLocaleString()
    : 'No verified update received',
);
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
    const request = { project_id: project, ...(approved && { confirm_dangerous: true }) };
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
    const confirmation = approved ? { confirm_dangerous: true } : {};
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
    <h3 id="signed-sharing-heading">Signed team updates</h3>
    <p>
      One owner publishes shared values. Each device receives an encrypted package; personal
      overrides stay local.
    </p>
    <p role="status">{{ message }}</p>
    <template v-if="status">
      <p>Last verified: {{ verifiedAt }} · Revision {{ status.epoch }}</p>
      <p v-if="!privacyMode && status.owner_fingerprint">
        Owner fingerprint: <code>{{ status.owner_fingerprint }}</code>
      </p>
      <p v-if="!privacyMode && status.folder">Delivery folder: {{ status.folder }}</p>
      <p v-if="status.last_error" role="alert">
        {{ privacyMode ? 'Delivery needs attention.' : status.last_error }}
      </p>
      <p v-if="status.waiting_known">{{ status.waiting }} update files waiting for verification.</p>
      <p v-if="status.conflicts">
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
            <label
              >New name for your local profile
              <input v-model="localNames[profile.profile_id]" autocomplete="off" />
            </label>
            <button
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
            <div v-for="secret in profile.colliding_secrets" :key="secret.id" class="actions">
              <span>{{ secret.name }}</span>
              <button :disabled="busy" @click="reconcile(profile.profile_id, secret.id, 'value')">
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
      >
        Run <code>locket team sync pending</code> for the authenticated collision details and
        resolution commands.
      </p>
    </template>
    <p v-if="error" role="alert">
      {{
        privacyMode ? 'Team update check failed. Turn off privacy mode to read the details.' : error
      }}
    </p>
    <div class="actions">
      <button :disabled="busy || !projectId" @click="perform('status')">Check status</button>
      <button :disabled="busy || !projectId" @click="perform('now')">Apply verified updates</button>
    </div>
    <details v-if="!privacyMode">
      <summary>Set up this device</summary>
      <ol>
        <li>
          Clone the project, then prepare this device:
          <CommandHandoff command="locket team join --request" label="Prepare receiving device" />
        </li>
        <li>
          Give the descriptor to the owner. Compare your full device fingerprint through a separate
          trusted channel. The owner adds your device and publishes to the shared folder.
        </li>
        <li>
          Get the owner’s full fingerprint through that trusted channel. A fingerprint supplied only
          inside the folder is insufficient.
        </li>
      </ol>
      <label
        >Shared folder
        <input v-model="folder" autocomplete="off" placeholder="/path/to/shared-folder"
      /></label>
      <label
        >Independently verified owner fingerprint
        <input v-model="ownerPin" autocomplete="off" spellcheck="false" maxlength="64"
      /></label>
      <CommandHandoff v-if="join" :command="join" label="Join verified team" />
      <p>Already joined? Choose this folder for automatic updates while unlocked.</p>
      <label
        ><input v-model="allowDangerous" type="checkbox" /> Allow automatic delivery to dangerous
        profiles on this machine</label
      >
      <button :disabled="busy || !projectId || !folder.trim()" @click="perform('configure')">
        Save folder and consent
      </button>
      <p>After saving, choose “Apply verified updates” to retry held values.</p>
      <p>
        Owners can publish immediately with <code>locket team publish</code>. The unlocked owner’s
        agent also publishes changed shared values automatically. Removing a teammate cannot erase
        values already received; rotate credentials at their providers.
      </p>
    </details>
  </section>
</template>
<style scoped>
.sharing {
  display: grid;
  gap: 0.65rem;
  padding: 1rem;
  border: 1px solid var(--border-subtle);
  border-radius: 0.5rem;
}
h3,
p {
  margin: 0;
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
label {
  display: grid;
  gap: 0.3rem;
  margin: 0.8rem 0;
}
input,
button {
  font: inherit;
  padding: 0.45rem;
}
code {
  overflow-wrap: anywhere;
}
li {
  margin: 0.6rem 0;
}
</style>
