const day = 24 * 60 * 60 * 1000;
const shortDate = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const fullDate = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
});

const localDateTime = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'medium',
});

const shortDateTime = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
});
const fullDateTime = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
});

const utcDate = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
  timeZone: 'UTC',
});
const utcTime = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
  timeZone: 'UTC',
});
const utcShortDate = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  timeZone: 'UTC',
});

export function formatTime(
  iso: string,
  precision: 'compact' | 'datetime' | 'timestamp' | 'utc' | 'utc-date' = 'compact',
): string {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return 'Unknown date';

  if (precision === 'timestamp') return localDateTime.format(date);
  if (precision === 'datetime') {
    return (date.getFullYear() === new Date().getFullYear() ? shortDateTime : fullDateTime).format(
      date,
    );
  }
  if (precision === 'utc') return `${utcDate.format(date)} · ${utcTime.format(date)} UTC`;
  if (precision === 'utc-date') {
    return (date.getUTCFullYear() === new Date().getUTCFullYear() ? utcShortDate : utcDate).format(
      date,
    );
  }

  const now = Date.now();
  const elapsed = now - date.getTime();
  if (elapsed >= -5000 && elapsed < 60000) return 'just now';
  if (elapsed >= 60000 && elapsed < 3600000) return `${Math.floor(elapsed / 60000)}m ago`;
  if (elapsed >= 3600000 && elapsed < day) return `${Math.floor(elapsed / 3600000)}h ago`;
  if (elapsed >= day && elapsed < 7 * day) return `${Math.floor(elapsed / day)}d ago`;

  return (date.getFullYear() === new Date(now).getFullYear() ? shortDate : fullDate).format(date);
}

export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const remainingSeconds = total % 60;
  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours} hr`);
  if (minutes > 0) parts.push(`${minutes} min`);
  if (remainingSeconds > 0 || parts.length === 0) parts.push(`${remainingSeconds} sec`);
  return parts.join(' ');
}
