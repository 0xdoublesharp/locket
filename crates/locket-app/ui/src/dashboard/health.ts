export interface HealthLabel {
  label: string;
  tone: 'ok' | 'warn' | 'neutral';
}
export function auditHealth(ok: boolean | null | undefined): HealthLabel {
  if (ok === true) return { label: 'Verified', tone: 'ok' };
  if (ok === false) return { label: 'Verification failed', tone: 'warn' };
  return { label: 'Not verified', tone: 'neutral' };
}
export function scanHealth(
  checkedAt: string | undefined,
  locked: boolean,
  error: string | null | undefined,
  count: number,
): HealthLabel {
  if (error) return { label: 'Scan failed', tone: 'warn' };
  if (!checkedAt) return { label: 'Not checked', tone: 'neutral' };
  if (locked) return { label: 'Limited scan', tone: 'warn' };
  return {
    label: count === 0 ? 'No findings' : `${count} findings`,
    tone: count === 0 ? 'ok' : 'warn',
  };
}
export function auditRowVerified(
  chain: { hmac_ok: boolean | null; first_break_sequence: number | null },
  sequence: number,
): boolean | null {
  if (chain.hmac_ok === true) return true;
  if (chain.hmac_ok === null) return null;
  return chain.first_break_sequence !== null && sequence < chain.first_break_sequence;
}
export function configuredDurationSeconds(value: string | null): number {
  const match = /^([1-9]\d*)([smhdw])$/.exec(value ?? '');
  if (!match) return 0;
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  return Number(match[1]) * units[match[2]!]!;
}

export function unlockTtl(configured: number): number {
  return Number.isInteger(configured) && configured > 0 && configured <= 28800 ? configured : 900;
}

export function projectStatusMatches(
  status: { project_id: string | null; profile_name: string | null } | null,
  project: { project_id: string; profile_name: string } | null,
  connected = true,
): boolean {
  return (
    connected &&
    status !== null &&
    project !== null &&
    status.project_id === project.project_id &&
    status.profile_name === project.profile_name
  );
}
