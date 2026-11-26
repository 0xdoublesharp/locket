import type { VersionSourceWire, SecretWireRow } from './types';
import type { PersistedSecretSource, SecretRowMeta } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

function sourceLabel(source: SecretWireRow['source']): SecretRowMeta['source'] {
  return source === 'team-managed' ? 'team' : source;
}

export function secretSourceWire(source: PersistedSecretSource): VersionSourceWire {
  return source === 'team' ? 'team-managed' : source;
}

export function secretRow(row: SecretWireRow): SecretRowMeta {
  return {
    id: row.id,
    name: row.name,
    source: sourceLabel(row.source),
    required: row.required,
    optional: row.optional ?? false,
    ownerLabel: row.owner,
    tags: row.tags,
    createdAt: nanosToIso(row.created_at),
    rotatedAt:
      typeof row.last_rotated_at === 'number' ? nanosToIso(row.last_rotated_at) : undefined,
    currentVersion: row.current_version,
    hasDeprecatedGrace: false,
    ...(row.linked_target_secret_id != null && {
      linkedTargetSecretId: row.linked_target_secret_id,
    }),
    ...(row.linked_target_name != null && { linkedTargetName: row.linked_target_name }),
    ...(row.link_count !== undefined && { linkCount: row.link_count }),
  };
}
