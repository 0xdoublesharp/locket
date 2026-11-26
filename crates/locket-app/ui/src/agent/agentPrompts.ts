import { shellQuote } from '../utils/shellQuote';

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
    '1. In the workspace I approve, run `locket env scan --remaining --json` (or MCP `locket_scan_env_files`) to inventory remaining .env* files by key name and migration status.',
    '2. Run `locket shared list` before planning any @shared links. If Global Vault is uninitialized, plan a local import with `locket import <file> --keep`. Show me the plan by file, key, vault, and environment. Use `--link-shared` in the preview if the plan includes linking exact matches in Global Vault.',
    '3. Once each project is set up with `locket init`, preview each import with `locket import <file> --dry-run --json` (or MCP `locket_import_env`) using the planned destination and filters. Run `locket policy detect` and give me the ready-to-run `locket policy add` commands to review and run myself. Show only metadata and wait for my approval before importing.',
    '4. If several repos need unlocking, give me one command to run in my terminal, such as `locket unlock --project <project1> --project <project2> --ttl 3600`. After approval, import with the previewed options and `--keep`. Do not overwrite existing values. Verify the app with an approved `locket run <policy>` or scoped `locket exec` command, and report skipped keys or conflicts by name.',
    '5. Archive only with my separate authorization. Preview with `locket import <file> --archive <DIR> --archive-if-matching [--verify-policy <POLICY>] --dry-run --json`. Review `archive_consumer_warnings` with me and address any remaining .env consumers before removing `--dry-run`.',
    'If the metadata-only scan or preview options are unavailable, stop and tell me what is missing.',
  ]
    .filter(Boolean)
    .join('\n\n');
}
