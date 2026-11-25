function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) return value;
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

export function mcpClientSnippets(command: string, args: string[]) {
  const launch = [command, ...args].map(shellQuote).join(' ');
  return {
    json: JSON.stringify({ mcpServers: { locket: { command, args } } }, null, 2),
    claude: `claude mcp add locket -- ${launch}`,
    codex: `codex mcp add locket -- ${launch}`,
  };
}

export function dotenvMigrationPrompt(options?: {
  vaultName?: string;
  isShared?: boolean;
}): string {
  const context = options?.isShared
    ? 'The active vault is Global Vault (@shared).'
    : options?.vaultName?.trim()
      ? `The active vault label is ${JSON.stringify(options.vaultName.trim())}.`
      : '';

  return [
    'Help me migrate .env files into Locket.',
    context,
    'NEVER read raw .env file contents directly. Do not open, source, print, or parse them yourself. Let Locket read the files internally. Use only file paths, key names, and counts in your tools and replies.',
    '1. In the workspace I approve, run `locket env scan --json` (or MCP `locket_scan_env_files`) to inventory .env* files by key name and identify `shared_candidates`.',
    '2. Show me a proposed plan by file, key, vault, and environment. Put confirmed personal or reusable keys in Global Vault (@shared) and repo-specific keys in their project vaults. Treat shared_candidates as suggestions. A repeated key name does not prove the values are the same. Exclude a key from a project only if I confirm that project should use the Global Vault entry.',
    '3. Preview each planned import with `locket import <file> --dry-run --json` using the same destination and filters as the planned write (or preview with MCP `locket_import_env`). Show only metadata and wait for my approval before writing.',
    '4. After approval, use `locket import <file> --project @shared --only <keys> --keep --json` for shared keys and `locket import <file> --exclude <keys> --keep --json` from the project root for the rest (or use MCP `locket_import_env` with equivalent options). Quote paths and use comma-separated key names. If there are no shared keys, skip the shared import and omit --exclude. Do not overwrite existing values.',
    '5. Verify by key name and import counts. Report skipped keys or conflicts using metadata only. Keep the original .env files through verification and leave them in place unless I separately authorize deletion.',
    'If the metadata-only scan or preview options are unavailable, stop and tell me what is missing.',
  ]
    .filter(Boolean)
    .join('\n\n');
}
