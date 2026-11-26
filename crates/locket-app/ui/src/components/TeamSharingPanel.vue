<script setup lang="ts">
import { computed, reactive, ref, watch, onMounted, onUnmounted } from 'vue';
import AppIcon from './AppIcon.vue';
import CommandHandoff from './CommandHandoff.vue';
import { formatTime } from '../utils/formatTime';
import {
  actionError,
  desktopTeamSyncStatus,
  desktopTeamSyncNow,
  desktopTeamSyncConfigure,
  desktopTeamSyncTestRemote,
  desktopTeamSyncRenameProfile,
  desktopTeamSyncPreserveOverride,
} from '../agent/client';
import type { TeamSyncTransportInput } from '../agent/types';
import {
  joinCommand,
  syncMessage,
  validDeliveryUrl,
  type TeamSyncStatus,
  type TeamSyncTransportKind,
  type TeamSyncWebDavAuthKind,
} from '../team/sync';

const props = defineProps<{
  projectId?: string;
  privacyMode?: boolean;
  confirmDangerous?: (action: string, force?: boolean) => Promise<string | false | undefined>;
}>();
const status = ref<TeamSyncStatus | null>(null);
const busy = ref(false);
const error = ref('');
const backends = [
  { kind: 'folder', label: 'Shared folder' },
  { kind: 's3', label: 'S3 / R2 / MinIO' },
  { kind: 'webdav', label: 'WebDAV' },
] as const;
const backend = ref<TeamSyncTransportKind>('folder');
const folder = ref('');
const bucket = ref('');
const region = ref('us-east-1');
const prefix = ref('');
const endpoint = ref('');
const pathStyle = ref(false);
const s3CredentialMode = ref<'vault' | 'env'>('vault');
const accessKeyId = ref('');
const secretAccessKey = ref('');
const sessionToken = ref('');
const showSecretAccessKey = ref(false);
const webdavUrl = ref('');
const webdavAuth = ref<TeamSyncWebDavAuthKind>('none');
const webdavCredentialMode = ref<'vault' | 'env'>('vault');
const webdavUsername = ref('');
const webdavSecret = ref('');
const ownerPin = ref('');
const allowDangerous = ref(false);
const localNames = ref<Record<string, string>>({});
const connection = ref<{ ok: boolean; message: string } | null>(null);
const editedBackends = reactive(new Set<TeamSyncTransportKind>());

const activeBackend = computed(() => status.value?.transport_kind ?? 'folder');
const remoteBackend = computed(() => activeBackend.value !== 'folder');
const join = computed(() => {
  if (backend.value !== 'folder' && activeBackend.value !== backend.value) return null;
  return joinCommand(folder.value, ownerPin.value, backend.value);
});

const validEndpoint = computed(
  () => !endpoint.value || validDeliveryUrl(endpoint.value.trim(), true),
);
const validWebdavUrl = computed(() => validDeliveryUrl(webdavUrl.value.trim()));
const canSave = computed(() => {
  switch (backend.value) {
    case 's3':
      return Boolean(
        bucket.value.trim() &&
        region.value.trim() &&
        validEndpoint.value &&
        (s3CredentialMode.value === 'env' || (accessKeyId.value.trim() && secretAccessKey.value)),
      );
    case 'webdav':
      return (
        validWebdavUrl.value &&
        (webdavAuth.value === 'none' ||
          webdavCredentialMode.value === 'env' ||
          (Boolean(webdavSecret.value) &&
            (webdavAuth.value === 'bearer' || Boolean(webdavUsername.value.trim()))))
      );
    default:
      return Boolean(folder.value.trim());
  }
});

function clearS3Credentials() {
  accessKeyId.value = '';
  secretAccessKey.value = '';
  sessionToken.value = '';
  showSecretAccessKey.value = false;
}

function clearWebdavCredentials() {
  webdavUsername.value = '';
  webdavSecret.value = '';
}

function clearCredentials() {
  clearS3Credentials();
  clearWebdavCredentials();
}

watch(s3CredentialMode, clearS3Credentials, { flush: 'sync' });
watch([webdavAuth, webdavCredentialMode], clearWebdavCredentials, { flush: 'sync' });
watch(
  backend,
  () => {
    clearCredentials();
    connection.value = null;
    error.value = '';
  },
  { flush: 'sync' },
);
watch(
  () => props.privacyMode,
  (privateMode) => {
    if (privateMode) clearCredentials();
  },
  { flush: 'sync' },
);

function markEdited(kind: TeamSyncTransportKind) {
  editedBackends.add(kind);
  connection.value = null;
}

watch(folder, () => markEdited('folder'), { flush: 'sync' });
watch(
  [
    bucket,
    region,
    prefix,
    endpoint,
    pathStyle,
    s3CredentialMode,
    accessKeyId,
    secretAccessKey,
    sessionToken,
  ],
  () => markEdited('s3'),
  { flush: 'sync' },
);
watch(
  [webdavUrl, webdavAuth, webdavCredentialMode, webdavUsername, webdavSecret],
  () => markEdited('webdav'),
  { flush: 'sync' },
);

// Track draft changes independently of the draft values so clearing credentials
// after a save never requires a second copy of the transport payload.
const savedTarget = computed(() =>
  activeBackend.value === 'folder' ? status.value?.folder : status.value?.remote_target,
);
const canTestSaved = computed(() =>
  Boolean(
    savedTarget.value &&
    activeBackend.value === backend.value &&
    !editedBackends.has(backend.value),
  ),
);

function transportInput(): TeamSyncTransportInput {
  switch (backend.value) {
    case 'folder':
      return { kind: 'folder', path: folder.value.trim() };
    case 's3':
      return {
        kind: 's3',
        bucket: bucket.value.trim(),
        region: region.value.trim(),
        ...(prefix.value.trim() && { prefix: prefix.value.trim() }),
        ...(endpoint.value.trim() && { endpoint: endpoint.value.trim() }),
        path_style: pathStyle.value,
        credential_mode: s3CredentialMode.value,
        ...(s3CredentialMode.value === 'vault' && {
          access_key_id: accessKeyId.value.trim(),
          secret_access_key: secretAccessKey.value,
          ...(sessionToken.value && { session_token: sessionToken.value }),
        }),
      };
    case 'webdav':
      return {
        kind: 'webdav',
        url: webdavUrl.value.trim(),
        auth_kind: webdavAuth.value,
        credential_mode: webdavAuth.value === 'none' ? 'none' : webdavCredentialMode.value,
        ...(webdavAuth.value !== 'none' &&
          webdavCredentialMode.value === 'vault' && {
            ...(webdavAuth.value === 'basic' && { username: webdavUsername.value.trim() }),
            secret: webdavSecret.value,
          }),
      };
  }
}

function redactCredentials(message: string, transport?: TeamSyncTransportInput): string {
  const credentials =
    transport?.kind === 's3'
      ? [transport.access_key_id, transport.secret_access_key, transport.session_token]
      : transport?.kind === 'webdav'
        ? [transport.username, transport.secret]
        : [];
  for (const value of credentials
    .filter((value): value is string => Boolean(value))
    .sort((a, b) => b.length - a.length)) {
    message = message.replaceAll(value, '[redacted]');
  }
  return message;
}

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
  clearCredentials();
  if (timer) clearInterval(timer);
});
async function perform(kind: 'status' | 'now' | 'configure' | 'test') {
  const project = props.projectId;
  if (!project || busy.value) return;
  const editing = kind === 'configure' || kind === 'test';
  const testSaved = kind === 'test' && canTestSaved.value;
  if (editing && (props.privacyMode || (!testSaved && !canSave.value))) return;

  const token = generation;
  const selectedBackend = backend.value;
  const consent = allowDangerous.value;
  const transport = editing && !testSaved ? transportInput() : undefined;
  if (kind === 'configure') clearCredentials();
  busy.value = true;
  error.value = '';
  if (editing) connection.value = null;
  try {
    const approved =
      kind === 'status' || !props.confirmDangerous
        ? false
        : kind === 'configure' && consent
          ? await props.confirmDangerous('Configure team sync', true)
          : await props.confirmDangerous(
              kind === 'now'
                ? 'Sync team updates'
                : kind === 'test'
                  ? 'Test team sync connection'
                  : 'Configure team sync',
            );
    if (
      approved === undefined ||
      token !== generation ||
      project !== props.projectId ||
      (kind === 'configure' && consent && !approved) ||
      (editing && (props.privacyMode || selectedBackend !== backend.value))
    )
      return;
    const request = {
      project_id: project,
      ...(approved && { confirm_dangerous_profile: approved }),
    };
    if (kind === 'test') {
      const result = await desktopTeamSyncTestRemote({
        ...request,
        ...(transport && { transport }),
      });
      if (token !== generation || project !== props.projectId || selectedBackend !== backend.value)
        return;
      if (result.ok && result.value.ok) {
        const count = result.value.package_count;
        connection.value = {
          ok: true,
          message: `Connected · ${count} encrypted ${count === 1 ? 'package' : 'packages'} found`,
        };
      } else {
        const detail = result.ok ? result.value.message : actionError(result.error);
        connection.value = { ok: false, message: redactCredentials(detail, transport) };
      }
      return;
    }
    const result =
      kind === 'now'
        ? await desktopTeamSyncNow(request)
        : kind === 'configure' && transport
          ? await desktopTeamSyncConfigure({
              ...request,
              ...(transport.kind === 'folder' ? { folder: transport.path } : { transport }),
              allow_dangerous: consent,
            })
          : await desktopTeamSyncStatus(request);
    if (token !== generation || project !== props.projectId) return;
    if (result.ok) {
      if (kind === 'status' && !status.value)
        backend.value = result.value.transport_kind ?? 'folder';
      if (kind === 'configure') editedBackends.delete(selectedBackend);
      const lastError = result.value.last_error;
      status.value = lastError
        ? { ...result.value, last_error: redactCredentials(lastError, transport) }
        : result.value;
    } else {
      error.value = redactCredentials(actionError(result.error), transport);
    }
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
    connection.value = null;
    backend.value = 'folder';
    folder.value = '';
    bucket.value = '';
    region.value = 'us-east-1';
    prefix.value = '';
    endpoint.value = '';
    pathStyle.value = false;
    s3CredentialMode.value = 'vault';
    webdavUrl.value = '';
    webdavAuth.value = 'none';
    webdavCredentialMode.value = 'vault';
    clearCredentials();
    editedBackends.clear();
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
        <div v-if="!privacyMode && remoteBackend" class="sharing__fact--wide">
          <dt>Delivery backend</dt>
          <dd class="sharing__destination">
            <span class="companion-pill">{{ activeBackend === 's3' ? 'S3' : 'WebDAV' }}</span>
            <code v-if="status.remote_target">{{ status.remote_target }}</code>
          </dd>
          <dd v-if="activeBackend === 's3'" class="sharing__destination">
            <span v-if="status.remote_endpoint" class="companion-pill sharing__metadata">
              Endpoint {{ status.remote_endpoint }}
            </span>
            <span v-if="status.remote_region" class="companion-pill sharing__metadata">
              Region {{ status.remote_region }}
            </span>
            <span v-if="status.credential_mode === 'vault'" class="companion-pill"
              >Vault encrypted</span
            >
            <span v-else-if="status.credential_mode === 'env'" class="companion-pill"
              >Env vars</span
            >
          </dd>
        </div>
        <div v-else-if="!privacyMode && status.folder" class="sharing__fact--wide">
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
              To accept automatic delivery, open “Set up this device”, choose the delivery backend,
              and explicitly allow dangerous profiles. This consent applies to shared profiles on
              this machine.
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
    <p
      v-if="privacyMode && connection"
      :class="['sharing__banner', `sharing__banner--${connection.ok ? 'ok' : 'danger'}`]"
      :role="connection.ok ? 'status' : 'alert'"
    >
      {{ connection.ok ? 'Connection test passed.' : 'Connection test failed.' }}
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
            separate trusted channel. The owner adds your device and publishes to the team’s
            storage.
          </li>
          <li>
            Get the owner’s full fingerprint through that trusted channel. A fingerprint supplied
            only through the delivery backend is insufficient.
          </li>
        </ol>
        <fieldset class="sharing__setup" :disabled="busy">
          <div class="sharing__backends" role="group" aria-label="Delivery backend">
            <button
              v-for="choice in backends"
              :key="choice.kind"
              type="button"
              class="companion-button"
              :aria-pressed="backend === choice.kind"
              @click="backend = choice.kind"
            >
              {{ choice.label }}
            </button>
          </div>
          <div :key="backend" class="sharing__form">
            <label v-if="backend === 'folder'" class="sharing__field">
              Shared folder
              <input
                v-model="folder"
                class="companion-input"
                autocomplete="off"
                placeholder="/path/to/shared-folder"
                required
              />
            </label>
            <template v-else-if="backend === 's3'">
              <label class="sharing__field">
                Bucket
                <input
                  v-model="bucket"
                  class="companion-input"
                  autocomplete="off"
                  spellcheck="false"
                  required
                />
              </label>
              <label class="sharing__field">
                Region
                <input
                  v-model="region"
                  class="companion-input"
                  autocomplete="off"
                  spellcheck="false"
                  placeholder="us-east-1 or auto for R2"
                  required
                />
              </label>
              <label class="sharing__field">
                Key prefix (optional)
                <input
                  v-model="prefix"
                  class="companion-input"
                  autocomplete="off"
                  spellcheck="false"
                  placeholder="locket/my-project"
                />
              </label>
              <label class="sharing__field">
                Custom endpoint URL (optional)
                <input
                  v-model.trim="endpoint"
                  type="url"
                  class="companion-input"
                  autocomplete="off"
                  spellcheck="false"
                  placeholder="https://<account>.r2.cloudflarestorage.com"
                  :aria-invalid="!validEndpoint || undefined"
                />
              </label>
              <label class="sharing__check">
                <input v-model="pathStyle" type="checkbox" /> Path-style URLs
              </label>
              <label class="sharing__field">
                Credential mode
                <select v-model="s3CredentialMode" class="companion-input">
                  <option value="vault">Encrypt in local vault</option>
                  <option value="env">Read from environment variables</option>
                </select>
              </label>
              <template v-if="s3CredentialMode === 'vault'">
                <label class="sharing__field">
                  Access Key ID
                  <input
                    v-model="accessKeyId"
                    class="companion-input"
                    autocomplete="off"
                    spellcheck="false"
                    required
                  />
                </label>
                <div class="sharing__secret-row">
                  <label class="sharing__field">
                    Secret Access Key
                    <input
                      v-model="secretAccessKey"
                      :type="showSecretAccessKey ? 'text' : 'password'"
                      class="companion-input"
                      autocomplete="off"
                      autocapitalize="off"
                      spellcheck="false"
                      required
                    />
                  </label>
                  <button
                    type="button"
                    class="companion-button icon-label"
                    :aria-label="
                      showSecretAccessKey ? 'Hide secret access key' : 'Show secret access key'
                    "
                    @click="showSecretAccessKey = !showSecretAccessKey"
                  >
                    {{ showSecretAccessKey ? 'Hide' : 'Show' }}
                  </button>
                </div>
                <label class="sharing__field">
                  Session Token (optional)
                  <input
                    v-model="sessionToken"
                    type="password"
                    class="companion-input"
                    autocomplete="off"
                  />
                </label>
              </template>
            </template>
            <template v-else>
              <label class="sharing__field">
                HTTPS URL
                <input
                  v-model.trim="webdavUrl"
                  type="url"
                  class="companion-input"
                  autocomplete="off"
                  spellcheck="false"
                  placeholder="https://dav.example.com/locket-team"
                  :aria-invalid="(Boolean(webdavUrl) && !validWebdavUrl) || undefined"
                  required
                />
              </label>
              <label class="sharing__field">
                Auth type
                <select v-model="webdavAuth" class="companion-input">
                  <option value="none">None</option>
                  <option value="basic">Basic</option>
                  <option value="bearer">Bearer</option>
                </select>
              </label>
              <template v-if="webdavAuth !== 'none'">
                <label class="sharing__field">
                  Credential mode
                  <select v-model="webdavCredentialMode" class="companion-input">
                    <option value="vault">Encrypt in local vault</option>
                    <option value="env">Read from environment variables</option>
                  </select>
                </label>
                <template v-if="webdavCredentialMode === 'vault'">
                  <label v-if="webdavAuth === 'basic'" class="sharing__field">
                    Username
                    <input
                      v-model="webdavUsername"
                      class="companion-input"
                      autocomplete="off"
                      spellcheck="false"
                      required
                    />
                  </label>
                  <label class="sharing__field">
                    {{ webdavAuth === 'basic' ? 'Password' : 'Bearer token' }}
                    <input
                      v-model="webdavSecret"
                      type="password"
                      class="companion-input"
                      autocomplete="off"
                      required
                    />
                  </label>
                </template>
              </template>
            </template>
          </div>
          <p v-if="backend === 's3'" class="sharing__muted">
            Packages are encrypted per device and signed before upload. Bucket admins only see
            opaque ciphertext.
          </p>
          <p v-if="backend === 's3' && !validEndpoint" class="sharing__hint">
            Use HTTPS for the endpoint, or HTTP for a loopback address. Leave out credentials,
            queries, and fragments.
          </p>
          <p v-if="backend === 'webdav' && webdavUrl && !validWebdavUrl" class="sharing__hint">
            Enter an HTTPS URL without credentials, a query, or a fragment.
          </p>
          <p v-if="backend !== 'folder' && activeBackend !== backend" class="sharing__muted">
            Save the delivery backend before joining the team.
          </p>
          <label class="sharing__field"
            >Independently verified owner fingerprint
            <input
              v-model="ownerPin"
              class="companion-input sharing__mono"
              autocomplete="off"
              spellcheck="false"
              maxlength="64"
          /></label>
          <CommandHandoff v-if="join" :command="join" label="Join verified team" />
          <p>Already joined? Save the delivery backend for automatic updates while unlocked.</p>
          <label class="sharing__check"
            ><input v-model="allowDangerous" type="checkbox" /> Allow automatic delivery to
            dangerous profiles on this machine</label
          >
          <div class="sharing__actions sharing__actions--start">
            <button
              type="button"
              class="companion-button"
              :disabled="busy || !projectId || (!canSave && !canTestSaved)"
              @click="perform('test')"
            >
              Test connection
            </button>
            <button
              type="button"
              class="companion-button companion-button--primary"
              :disabled="busy || !projectId || !canSave"
              @click="perform('configure')"
            >
              Save delivery backend &amp; consent
            </button>
          </div>
        </fieldset>
        <p
          v-if="connection"
          :class="['sharing__banner', `sharing__banner--${connection.ok ? 'ok' : 'danger'}`]"
          :role="connection.ok ? 'status' : 'alert'"
        >
          <AppIcon :name="connection.ok ? 'check' : 'alert'" />
          <span>{{
            connection.ok ? connection.message : `Connection test failed. ${connection.message}`
          }}</span>
        </p>
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
.sharing__banner--ok {
  background: var(--success-soft);
  color: var(--success);
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
.sharing__destination {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 0.35rem 0.5rem;
}
.sharing__metadata {
  max-width: 100%;
  white-space: normal;
  overflow-wrap: anywhere;
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
.sharing__setup {
  display: grid;
  gap: 0.75rem;
  min-width: 0;
  margin: 0;
  padding: 0;
  border: 0;
}
.sharing__backends {
  display: flex;
  flex-wrap: wrap;
  justify-self: start;
  gap: 0.25rem;
  padding: 0.25rem;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  background: var(--bg-app);
}
.sharing__backends > .companion-button {
  border-color: transparent;
  background: transparent;
  color: var(--text-secondary);
}
.sharing__backends > .companion-button:hover {
  background: var(--bg-subtle);
}
.sharing__backends > .companion-button[aria-pressed='true'] {
  border-color: var(--border-subtle);
  background: var(--bg-surface);
  color: var(--text-primary);
}
.sharing__form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 16rem), 1fr));
  gap: 0.75rem;
}
.sharing__field {
  display: grid;
  gap: 0.3rem;
  min-width: 0;
  color: var(--text-secondary);
  font-size: 0.8125rem;
}
.sharing__setup > .sharing__field {
  max-width: 36rem;
}
.sharing__secret-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: end;
  gap: 0.5rem;
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
.sharing__form > .sharing__check {
  align-self: end;
  min-height: 2.25rem;
  align-items: center;
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
