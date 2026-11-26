import type {
  CommandPolicyRow,
  SecretDeprecationWarning,
  SecretDeprecationWarningStatus,
  SecretDeprecationWarningSurface,
  SecretRowMeta,
  VersionHistoryRow,
} from '../types/views';

const PINNED_LK_REFERENCE_PATTERN =
  /\blk:\/\/[a-z][a-z0-9_-]*\/([A-Z][A-Z0-9_]*)@v([1-9][0-9]*)\b/gu;
const PINNED_POLICY_SECRET_PATTERN = /^([A-Z][A-Z0-9_]*)@v([1-9][0-9]*)$/u;

interface PinnedReference {
  name: string;
  version: number;
  surface: SecretDeprecationWarningSurface;
}

interface WarningKey {
  rowName: string;
  version: number;
  status: SecretDeprecationWarningStatus;
  surface: SecretDeprecationWarningSurface;
  graceUntil?: string;
}

export function secretRowsWithDeprecationWarnings(
  rows: readonly SecretRowMeta[],
  versions: readonly VersionHistoryRow[],
  policies: readonly CommandPolicyRow[],
  nowUnixNanos: number,
): SecretRowMeta[] {
  const deprecatedVersions = new Map<string, VersionHistoryRow>();
  for (const version of versions) {
    if (version.secretName === undefined || version.state !== 'deprecated') {
      continue;
    }
    deprecatedVersions.set(versionKey(version.secretName, version.version), version);
  }

  const warningCounts = new Map<string, { key: WarningKey; count: number }>();
  for (const reference of policyPinnedReferences(policies)) {
    const version = deprecatedVersions.get(versionKey(reference.name, reference.version));
    if (version === undefined || version.secretName === undefined) {
      continue;
    }
    const status = referenceStatus(version, nowUnixNanos);
    const key = warningKey({
      rowName: version.secretName,
      version: reference.version,
      status,
      surface: reference.surface,
      graceUntil: version.graceUntil,
    });
    const current = warningCounts.get(key);
    if (current === undefined) {
      warningCounts.set(key, {
        key: {
          rowName: version.secretName,
          version: reference.version,
          status,
          surface: reference.surface,
          graceUntil: version.graceUntil,
        },
        count: 1,
      });
    } else {
      current.count += 1;
    }
  }

  const warningsBySecret = new Map<string, SecretDeprecationWarning[]>();
  for (const { key, count } of warningCounts.values()) {
    const warnings = warningsBySecret.get(key.rowName) ?? [];
    warnings.push({
      version: key.version,
      status: key.status,
      surface: key.surface,
      graceUntil: key.graceUntil,
      referenceCount: count,
    });
    warningsBySecret.set(key.rowName, warnings);
  }

  return rows.map((row) => {
    if (row.source === 'shared-link') return row;
    const warnings = warningsBySecret.get(row.name) ?? [];
    if (warnings.length === 0) {
      return { ...row, deprecatedReferenceWarnings: [] };
    }
    return {
      ...row,
      hasDeprecatedGrace: true,
      deprecatedReferenceWarnings: warnings.sort(compareWarnings),
    };
  });
}

function policyPinnedReferences(policies: readonly CommandPolicyRow[]): PinnedReference[] {
  const references: PinnedReference[] = [];
  for (const policy of policies) {
    references.push(...pinnedReferencesInText(policy.commandPreview, 'command-preview'));
    for (const secretName of [
      ...policy.requiredSecrets,
      ...policy.optionalSecrets,
      ...policy.allowedSecrets,
    ]) {
      references.push(...pinnedReferencesInPolicySecret(secretName));
    }
  }
  return references;
}

function pinnedReferencesInText(
  text: string,
  surface: SecretDeprecationWarningSurface,
): PinnedReference[] {
  return [...text.matchAll(PINNED_LK_REFERENCE_PATTERN)].flatMap((match) => {
    const name = match[1];
    const version = Number(match[2]);
    if (name === undefined || !Number.isSafeInteger(version)) {
      return [];
    }
    return [{ name, version, surface }];
  });
}

function pinnedReferencesInPolicySecret(secretName: string): PinnedReference[] {
  const lkReferences = pinnedReferencesInText(secretName, 'policy');
  if (lkReferences.length > 0) {
    return lkReferences;
  }
  const match = PINNED_POLICY_SECRET_PATTERN.exec(secretName);
  if (match === null || match[1] === undefined) {
    return [];
  }
  const version = Number(match[2]);
  if (!Number.isSafeInteger(version)) {
    return [];
  }
  return [{ name: match[1], version, surface: 'policy' }];
}

function referenceStatus(
  version: VersionHistoryRow,
  nowUnixNanos: number,
): SecretDeprecationWarningStatus {
  if (!version.pinnedReferenceEligible || version.graceUntil === undefined) {
    return 'expired-grace';
  }
  const graceUntil = Date.parse(version.graceUntil) * 1_000_000;
  if (Number.isNaN(graceUntil) || graceUntil <= nowUnixNanos) {
    return 'expired-grace';
  }
  return 'active-grace';
}

function versionKey(name: string, version: number): string {
  return `${name}\u0000${version.toString()}`;
}

function warningKey(key: WarningKey): string {
  return [key.rowName, key.version.toString(), key.status, key.surface, key.graceUntil ?? ''].join(
    '\u0000',
  );
}

function compareWarnings(left: SecretDeprecationWarning, right: SecretDeprecationWarning): number {
  if (left.status !== right.status) {
    return left.status === 'expired-grace' ? -1 : 1;
  }
  if (left.version !== right.version) {
    return left.version - right.version;
  }
  return left.surface.localeCompare(right.surface);
}
