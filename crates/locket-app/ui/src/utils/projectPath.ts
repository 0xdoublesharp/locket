export function shortenProjectPath(path: string): string {
  const homeRelative = path.replace(/^\/Users\/[^/]+(?=\/)/, '~');
  const parts = homeRelative.split('/');
  if (parts.length < 3) return homeRelative;
  return `${parts[0]}/…/${parts.at(-1)}`;
}
