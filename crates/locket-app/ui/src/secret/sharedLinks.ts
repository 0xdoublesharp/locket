import type { SharedUsageRow } from '../agent/types';

export function unlinkAllConfirmation(
  usages: SharedUsageRow[],
  secretName: string,
): string | undefined {
  const dangerous = new Set(
    usages.filter((usage) => usage.profile_dangerous).map((usage) => usage.profile_name),
  );
  return dangerous.size > 1 ? secretName : [...dangerous][0];
}
