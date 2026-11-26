/** Metadata-only presentation of authenticated team delivery. */
export type TeamSyncTransportKind = 'folder' | 's3' | 'webdav';
export type TeamSyncCredentialMode = 'none' | 'vault' | 'env';
export type TeamSyncWebDavAuthKind = 'none' | 'basic' | 'bearer';

export interface PendingCollision {
  id: string;
  name: string;
}
export interface PendingProfileDetails {
  profile_id: string;
  profile_name: string;
  reason: string;
  colliding_profile: PendingCollision | null;
  colliding_secrets: PendingCollision[];
}
export interface TeamSyncStatus {
  epoch: number;
  state: string;
  conflicts: number;
  conflict_ids?: string[];
  pending_profiles?: Record<string, string>;
  pending_details?: PendingProfileDetails[];
  waiting: number;
  waiting_known?: boolean;
  last_error?: string | null;
  last_verified_at?: number | null;
  owner_fingerprint?: string | null;
  folder?: string | null;
  transport_kind?: TeamSyncTransportKind | null;
  remote_target?: string | null;
  remote_endpoint?: string | null;
  remote_region?: string | null;
  credential_mode?: TeamSyncCredentialMode | null;
  published: number;
  applied: number;
}
export function syncMessage(
  status: Pick<
    TeamSyncStatus,
    'state' | 'conflicts' | 'waiting' | 'pending_profiles' | 'transport_kind'
  >,
): string {
  if (['fork', 'rollback', 'stopped'].includes(status.state))
    return 'Stopped: conflicting update history. Contact the owner and verify the history before continuing.';
  if (status.state === 'delivery-error')
    return 'Delivery needs attention. Check the details below, then try again.';
  if (status.state === 'removed') return 'Your device was removed. Automatic updates have stopped.';
  if (status.state === 'locked') return 'Unlock to check and apply waiting team updates.';
  const profiles = Object.keys(status.pending_profiles ?? {}).length;
  if (profiles || status.conflicts) {
    const choices = [
      profiles
        ? `${profiles} ${profiles === 1 ? 'profile needs' : 'profiles need'} local consent or collision resolution`
        : '',
      status.conflicts
        ? `${status.conflicts} ${status.conflicts === 1 ? 'value needs' : 'values need'} your choice`
        : '',
    ]
      .filter(Boolean)
      .join('; ');
    return `${choices}. Other verified membership and key changes still apply.`;
  }
  if (status.state === 'unanchored')
    return 'Join using an independently verified owner fingerprint to establish trust.';
  if (status.transport_kind === 's3' || status.transport_kind === 'webdav')
    return 'Showing the last verified update. Remote storage cannot prove that this is the owner’s newest state.';
  return 'Showing the last verified update. Folder delivery cannot prove that this is the owner’s newest state.';
}
const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;
export function joinCommand(
  folder: string,
  ownerPin: string,
  transport: TeamSyncTransportKind = 'folder',
): string | null {
  if (!/^[a-fA-F0-9]{64}$/.test(ownerPin)) return null;
  if (transport === 'folder' && !folder.trim()) return null;
  const target = transport === 'folder' ? `--folder ${quote(folder.trim())}` : '--remote';
  return `locket team join ${target} --owner ${quote(ownerPin.toLowerCase())}`;
}

export function validDeliveryUrl(value: string, allowLoopbackHttp = false): boolean {
  if (value.length > 4096 || /[?#\\\s]/.test(value) || !/^https?:\/\/[^/@]+(?:\/|$)/.test(value))
    return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  return (
    !url.username &&
    !url.password &&
    (url.protocol === 'https:' || (allowLoopbackHttp && url.protocol === 'http:' && loopback))
  );
}
